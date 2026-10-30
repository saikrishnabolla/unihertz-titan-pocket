/* Bounded metadata diagnostics without libc, shell or policy modification. */
#include <asm/unistd.h>
#include <linux/fcntl.h>
#include <linux/stat.h>
#include <asm/stat.h>
#include <asm/statfs.h>

typedef unsigned long usize;
#ifdef GOOGLE_DIAG_TEST
static int test_fsync_fail_at,test_fsync_count,test_kernel_loss;
#endif
void *memset(void *dest,int value,usize n) {
    unsigned char *d=dest; for(usize i=0;i<n;++i) d[i]=(unsigned char)value; return dest;
}
void *memcpy(void *dest,const void *source,usize n) {
    unsigned char *d=dest; const unsigned char *s=source;
    for(usize i=0;i<n;++i) d[i]=s[i]; return dest;
}
static long call(long n, long a, long b, long c, long d) {
#ifdef GOOGLE_DIAG_TEST
    if(n==__NR_fsync && ++test_fsync_count==test_fsync_fail_at) return -5;
#endif
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory", "cc");
    return x0;
}
static usize length(const char *s) { usize n=0; while(s[n]) ++n; return n; }
static int equal(const char *a,const char *b) { while(*a && *a==*b) { ++a; ++b; } return *a==*b; }
static long pid_mountinfo(char *out,usize capacity,long pid) {
    if(pid<1 || pid>2147483647) return -22;
    char digits[10]; usize count=0; usize value=(usize)pid;
    do { digits[count++]='0'+value%10; value/=10; } while(value);
    if(capacity<5+count+10+1) return -36;
    memcpy(out,"proc/",5); usize at=5;
    while(count) out[at++]=digits[--count];
    memcpy(out+at,"/mountinfo",11);
    return 0;
}
static long openat(long fd,const char *p,long flags,long mode) {
    return call(__NR_openat,fd,(long)p,flags|O_CLOEXEC|O_NOFOLLOW,mode);
}
static void closefd(long fd) { call(__NR_close,fd,0,0,0); }
static int write_error;
static long writeall(long fd,const char *p,usize n) {
    while(n) { long r=call(__NR_write,fd,(long)p,n,0); if(r==-4) continue;
        if(r<=0) { write_error=1; return r?r:-5; } p+=r; n-=r; }
    return 0;
}
static void number(long fd,usize n) {
    char b[32]; usize i=sizeof(b); do { b[--i]='0'+n%10; n/=10; } while(n);
    writeall(fd,b+i,sizeof(b)-i);
}
static long fail(const char *stage,long error,long code) {
    writeall(2,stage,length(stage)); writeall(2," errno=",7); number(2,error<0?-error:error);
    writeall(2,"\n",1); return code;
}
/* Walk every component beneath an already-open trusted root; never resolve links. */
static long beneath(long root,const char *path,long final_flags) {
    long fd=openat(root,".",O_RDONLY|O_DIRECTORY,0); if(fd<0) return fd;
    const char *p=path;
    while(*p) {
        char part[128]; usize n=0;
        while(*p && *p!='/') { if(n==127) { closefd(fd); return -36; } part[n++]=*p++; }
        part[n]=0;
        if(!n || (n==1 && part[0]=='.') || (n==2 && part[0]=='.' && part[1]=='.')) {
            closefd(fd); return -22;
        }
        int more=*p=='/'; if(more) ++p;
        if(more && !*p) { closefd(fd); return -22; }
        long next=openat(fd,part,more?O_RDONLY|O_DIRECTORY:final_flags,0);
        closefd(fd); if(next<0) return next; fd=next;
    }
    return fd;
}
static long open_private_dir(long parent,const char *name) {
    long fd=openat(parent,name,O_RDONLY|O_DIRECTORY,0); if(fd<0) return fd;
    struct stat st;
    long r=call(__NR_fstat,fd,(long)&st,0,0);
#ifdef GOOGLE_DIAG_TEST
    long owner=call(__NR_getuid,0,0,0,0);
    long group=call(__NR_getgid,0,0,0,0);
#else
    long owner=0;
    long group=0;
#endif
    if(r<0 || st.st_uid!=owner || st.st_gid!=group || (st.st_mode&07777)!=0700) { closefd(fd); return r<0?r:-13; }
    return fd;
}
static long create_private_dir(long parent,const char *name) {
    long r=call(__NR_mkdirat,parent,(long)name,0700,0);
    if(r<0) return r;
    return open_private_dir(parent,name);
}
static long create(long dir,const char *name) {
    return openat(dir,name,O_WRONLY|O_CREAT|O_EXCL|O_NONBLOCK,0600);
}
struct mount_facts { usize rootdev,metadev,inode,type,flags; };
static long metadata_mounted(long root,long meta) {
    struct mount_facts facts;
#if defined(GOOGLE_DIAG_TEST) && !defined(GOOGLE_DIAG_REAL_MOUNT)
    long fd=beneath(root,"test-metadata-facts",O_RDONLY|O_NONBLOCK);
    if(fd<0) return fd;
    struct stat input;
    long check=call(__NR_fstat,fd,(long)&input,0,0);
    if(check<0 || (input.st_mode&S_IFMT)!=S_IFREG || input.st_size!=sizeof(facts)) {
        closefd(fd); return -22;
    }
    long count=call(__NR_read,fd,(long)&facts,sizeof(facts),0); closefd(fd);
    if(count!=sizeof(facts)) return -22;
    (void)meta;
#else
    struct stat rs,ms; struct statfs fs;
    long error=call(__NR_fstat,root,(long)&rs,0,0); if(error<0) return error;
    error=call(__NR_fstat,meta,(long)&ms,0,0); if(error<0) return error;
    error=call(__NR_fstatfs,meta,(long)&fs,0,0); if(error<0) return error;
    facts=(struct mount_facts){rs.st_dev,ms.st_dev,ms.st_ino,fs.f_type,fs.f_flags};
#endif
    /* A writable EXT4 filesystem root on a distinct device, mounted at /metadata. */
    if(facts.rootdev==facts.metadev || facts.inode!=2 || facts.type!=0xef53 || (facts.flags&1)) return -19;
    return 0;
}
static long safe_core_pattern(long root) {
    long fd=beneath(root,"proc/sys/kernel/core_pattern",O_RDONLY|O_NONBLOCK);
    if(fd<0) return fd;
    struct stat st;
    long error=call(__NR_fstat,fd,(long)&st,0,0);
    if(error<0 || (st.st_mode&S_IFMT)!=S_IFREG) { closefd(fd); return error<0?error:-22; }
    char pattern[32];
    long count=call(__NR_read,fd,(long)pattern,sizeof(pattern),0);
    closefd(fd);
    if(count<0) return count;
    if((count==4 || (count==5 && pattern[4]=='\n')) &&
       pattern[0]=='c' && pattern[1]=='o' && pattern[2]=='r' && pattern[3]=='e') return 0;
    return -13;
}
static long statusfd;
static int status_error;
static void record(const char *name,long error,usize bytes,int capped) {
    writeall(statusfd,name,length(name)); writeall(statusfd," errno=",7);
    number(statusfd,error<0?-error:error); writeall(statusfd," bytes=",7); number(statusfd,bytes);
    writeall(statusfd,capped?" capped=1\n":" capped=0\n",10);
    if(call(__NR_fsync,statusfd,0,0,0)<0 || write_error) status_error=1;
}
static int capture(long root,long out,const char *input,const char *name,usize limit) {
    long src=beneath(root,input,O_RDONLY|O_NONBLOCK); usize total=0; long error=0;
    if(src<0) { record(name,src,0,0); return 1; }
    struct stat st;
    error=call(__NR_fstat,src,(long)&st,0,0);
    if(error<0 || (st.st_mode&S_IFMT)!=S_IFREG) {
        closefd(src); record(name,error<0?error:-22,0,0); return 1;
    }
    long dst=create(out,name); if(dst<0) { closefd(src); record(name,dst,0,0); return 1; }
    char buf[4096]; int capped=0;
    while(total<limit) {
        usize want=limit-total; if(want>sizeof(buf)) want=sizeof(buf);
        long r=call(__NR_read,src,(long)buf,want,0);
        if(r==-4) continue; if(r<0) { error=r; break; } if(!r) break;
        error=writeall(dst,buf,r); if(error<0) break; total+=r;
    }
    if(!error && total==limit) {
        long r=call(__NR_read,src,(long)buf,1,0);
        if(r>0) capped=1; else if(r<0) error=r;
    }
    long sync=call(__NR_fsync,dst,0,0,0); if(!error && sync<0) error=sync;
    closefd(src); closefd(dst); record(name,error,total,capped);
    return error!=0 || capped;
}
static long kernel_stream(long root,long output) {
    long dev=openat(root,"dev",O_PATH|O_DIRECTORY,0);
    if(dev<0) return fail("kernel-dev-dir",dev,90);
    long source=openat(dev,"kmsg",O_RDONLY|O_NONBLOCK,0);
    closefd(dev);
    if(source<0) return fail("kernel-open",source,90);
    struct stat st;
    long error=call(__NR_fstat,source,(long)&st,0,0);
    if(error<0) return fail("kernel-stat",error,91);
#if defined(GOOGLE_DIAG_TEST) && !defined(GOOGLE_DIAG_REAL_KERNEL)
    if((st.st_mode&S_IFMT)!=S_IFREG && (st.st_mode&S_IFMT)!=S_IFIFO) return fail("kernel-test-input",-22,91);
#else
    if((st.st_mode&S_IFMT)!=S_IFCHR || st.st_rdev!=0x10b) return fail("kernel-device",-19,91);
#endif
    char buffer[8192]; usize total=0,synced=0;
    const usize limit=2097152;
    while(total<limit) {
        long count=call(__NR_read,source,(long)buffer,sizeof(buffer),0);
#ifdef GOOGLE_DIAG_TEST
        if(count>0 && test_kernel_loss) {
            test_kernel_loss=0;
            if(call(__NR_lseek,source,0,0,0)<0) return 95;
            count=-32;
        }
#endif
        if(count==-4) continue;
        if(count==-11) {
            if(total!=synced) {
                error=call(__NR_fsync,output,0,0,0);
                if(error<0) return fail("kernel-sync",error,93);
                synced=total;
            }
            struct { long seconds,nanoseconds; } delay={0,100000000};
            call(__NR_nanosleep,(long)&delay,0,0,0);
            continue;
        }
        const char *bytes=buffer;
        if(count==-32) {
            bytes="TITAN_KERNEL_LOG: records overwritten before read\n";
            count=length(bytes);
        } else if(count<0) return fail("kernel-read",count,92);
        if(!count) {
#ifdef GOOGLE_DIAG_TEST
            break;
#else
            return fail("kernel-eof",-5,92);
#endif
        }
        usize amount=count;
        if(amount>limit-total) amount=limit-total;
        error=writeall(output,bytes,amount);
        if(error<0) return fail("kernel-write",error,93);
        total+=amount;
        if(total-synced>=65536) {
            error=call(__NR_fsync,output,0,0,0);
            if(error<0) return fail("kernel-sync",error,93);
            synced=total;
        }
    }
    return call(__NR_fsync,output,0,0,0)<0?93:0;
}
static long run(long argc,char **argv) {
#ifdef GOOGLE_DIAG_TEST
    int limiting=argc==3 && equal(argv[2],"--limit-probe");
    int kernel_logging=argc==3 && (equal(argv[2],"--kernel") || equal(argv[2],"--kernel-loss-probe") ||
                       equal(argv[2],"--kernel-sync-probe") || equal(argv[2],"--kernel-directory-sync-probe"));
    test_kernel_loss=argc==3 && equal(argv[2],"--kernel-loss-probe");
    if(argc==3 && equal(argv[2],"--kernel-directory-sync-probe")) test_fsync_fail_at=1;
    if(argc==3 && equal(argv[2],"--kernel-sync-probe")) test_fsync_fail_at=4;
    int logging=argc==3 && (equal(argv[2],"--logcat") || limiting || kernel_logging);
#else
    int kernel_logging=argc==2 && equal(argv[1],"--kernel");
    int logging=argc==2 && (equal(argv[1],"--logcat") || kernel_logging);
    if(argc!=1 && !logging) return 64;
#endif
#ifdef GOOGLE_DIAG_LOGCAT_ONLY
    if(!logging || kernel_logging) return 64;
#endif
#ifdef GOOGLE_DIAG_KERNEL_ONLY
    if(!kernel_logging) return 64;
#endif
    struct { usize soft,hard; } no_core={0,0};
    long core_error=call(__NR_prlimit64,0,4,(long)&no_core,0);
    if(core_error<0) return fail("disable-core-limit",core_error,86);
    core_error=call(__NR_prctl,4,0,0,0);
    if(core_error<0) return fail("disable-dumpable",core_error,86);
    /* Default SIGALRM and an empty signal mask keep the deadline active across exec. */
    struct { usize handler,flags,restorer,mask; } action={0,0,0,0};
    usize mask=0;
    struct { long interval_sec,interval_usec,value_sec,value_usec; } timer={0,0,logging?120:1,0};
#ifdef GOOGLE_DIAG_TEST
    timer.value_sec=logging?1:5; /* Fixture fsync assertions tolerate shared-host I/O load. */
#endif
    if(call(__NR_rt_sigaction,14,(long)&action,0,8)<0 ||
       call(__NR_rt_sigprocmask,2,(long)&mask,0,8)<0 ||
       call(__NR_setitimer,0,(long)&timer,0,0)<0) return 70;
    action.handler=1; /* SIG_IGN survives exec; overflow returns EFBIG without a core signal. */
    if(call(__NR_rt_sigaction,25,(long)&action,0,8)<0) return 70;
#ifdef GOOGLE_DIAG_TEST
    if(argc!=2 && argc!=3) return 64;
    if(equal(argv[1],"--format-probe")) {
        char path[32];
        if(pid_mountinfo(path,sizeof(path),1) || !equal(path,"proc/1/mountinfo") ||
           pid_mountinfo(path,sizeof(path),10) || !equal(path,"proc/10/mountinfo") ||
           pid_mountinfo(path,sizeof(path),2147483647) || !equal(path,"proc/2147483647/mountinfo") ||
           pid_mountinfo(path,sizeof(path),0)!=-22 || pid_mountinfo(path,sizeof(path),-1)!=-22 ||
           pid_mountinfo(path,sizeof(path),2147483648L)!=-22 || pid_mountinfo(path,25,2147483647)!=-36)
            return 89;
        return 0;
    }
    if(equal(argv[1],"--deadline-probe")) {
        timer.value_sec=1;
        if(call(__NR_setitimer,0,(long)&timer,0,0)<0) return 70;
        for(;;) call(__NR_ppoll,0,0,0,0);
    }
    if(argc==3 && !logging) return 64;
    const char *rootpath=argv[1];
#else
    const char *rootpath="/";
#endif
    long root=openat(AT_FDCWD,rootpath,O_RDONLY|O_DIRECTORY,0); if(root<0) return fail("root",root,71);
    long meta=beneath(root,"metadata",O_RDONLY|O_DIRECTORY); if(meta<0) return fail("metadata",meta,72);
    long mounted=metadata_mounted(root,meta);
    if(mounted<0) return fail("metadata-mount",mounted,87);
    if(logging && !kernel_logging) {
        long safe=safe_core_pattern(root);
        if(safe<0) return fail("core-pattern",safe,88);
    }
    long parent=open_private_dir(meta,"titan-pocket-diag"); if(parent<0) return fail("private-dir",parent,73);
#ifdef GOOGLE_DIAG_KEY_PROBE_TRIAL
    const char *kernel_run="kernel-v3";
#else
    const char *kernel_run="kernel-v1";
#endif
    long out=create_private_dir(parent,kernel_logging?kernel_run:logging?"logcat-v1":"snapshot-v1"); if(out<0) return fail("exclusive-run",out,74);
    if(logging) {
        long log=create(out,kernel_logging?"kernel.log":"android.log"); if(log<0) return fail("log-file",log,79);
        struct { usize soft,hard; } size={2097152,2097152};
        if(call(__NR_prlimit64,0,1,(long)&size,0)<0) return 80;
        if(call(__NR_dup3,log,1,0,0)<0 || call(__NR_dup3,log,2,0,0)<0) return 81;
        long dirs[]={out,parent,meta};
        for(usize i=0;i<3;++i) {
            long synced=call(__NR_fsync,dirs[i],0,0,0);
            if(synced<0) return fail("directory-sync",synced,94);
        }
        if(kernel_logging) return kernel_stream(root,log);
#ifdef GOOGLE_DIAG_TEST
        if(limiting) { char buf[4096]={0}; for(int i=0;i<513;++i) {
            long r=writeall(1,buf,sizeof(buf)); if(r<0) return r==-27?0:84;
        } return 84; }
#endif
        char *args[]={"/system/bin/logcat","-b","main","-b","system","-b","crash",
            "-v","threadtime","*:W","init:I","vold:V","fs_mgr:V","fscrypt:V","apexd:I","zygote:I",0};
        char *env[]={0};
#ifdef GOOGLE_DIAG_TEST
        long exe=beneath(root,"system/bin/logcat",O_RDONLY);
        if(exe<0) return fail("exec-logcat",exe,83);
        register long x8 __asm__("x8")=__NR_execveat;
        register long x0 __asm__("x0")=exe;
        register long x1 __asm__("x1")=(long)"";
        register long x2 __asm__("x2")=(long)args;
        register long x3 __asm__("x3")=(long)env;
        register long x4 __asm__("x4")=AT_EMPTY_PATH;
        __asm__ volatile("svc 0" : "+r"(x0) : "r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4) : "memory","cc");
        long error=x0;
#else
        long safe=safe_core_pattern(root);
        if(safe<0) return fail("core-pattern",safe,88);
        long error=call(__NR_execve,(long)args[0],(long)args,(long)env,0);
#endif
        return fail("exec-logcat",error,83);
    }
    statusfd=create(out,"status.txt"); if(statusfd<0) return fail("status",statusfd,75);
    int failed=0;
    failed|=capture(root,out,"sys/fs/selinux/enforce","enforce.txt",16);
    char mount_path[32];
    long formatted=pid_mountinfo(mount_path,sizeof(mount_path),call(__NR_getpid,0,0,0,0));
    if(formatted<0) { record("self-mountinfo.txt",formatted,0,0); failed=1; }
    else failed|=capture(root,out,mount_path,"self-mountinfo.txt",262144);
    failed|=capture(root,out,"sys/fs/selinux/policy","policy.bin",4194304);
    if(status_error) return fail("status-fsync",-5,85);
    long marker=create(out,"complete"); if(marker<0) return 76;
    if(writeall(marker,failed?"partial\n":"ok\n",failed?8:3)<0 ||
       call(__NR_fsync,marker,0,0,0)<0) return 77;
    closefd(marker);
    if(call(__NR_fsync,out,0,0,0)<0 || call(__NR_fsync,parent,0,0,0)<0) return 78;
    return failed?2:0;
}
#ifndef GOOGLE_DIAG_LIBRARY
__attribute__((noreturn)) void entry(long *stack) {
    long result=run(stack[0],(char **)(stack+1)); call(__NR_exit_group,result,0,0,0);
    __builtin_unreachable();
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl entry\n");
#endif
