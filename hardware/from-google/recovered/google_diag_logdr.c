#define GOOGLE_DIAG_LIBRARY
#include "google_diag_snapshot.c"

static long now_seconds(void) {
    struct { long seconds,nanoseconds; } value;
    if(call(__NR_clock_gettime,1,(long)&value,0,0)<0) return -1;
    return value.seconds;
}
static void pause_reader(void) {
    struct { long seconds,nanoseconds; } delay={0,100000000};
    call(__NR_nanosleep,(long)&delay,0,0,0);
}
static unsigned int little16(const unsigned char *p) { return p[0]|((unsigned int)p[1]<<8); }
static long logdr_stream(long output,long status,const char *path,long deadline) {
    struct { unsigned short family; char path[108]; } address={1,{0}};
    usize pathlen=length(path);
    if(pathlen>=sizeof(address.path)) return fail("socket-path",-36,90);
    memcpy(address.path,path,pathlen+1);
    long socket=-1,connected=0,last_error=0;
    while(now_seconds()<deadline) {
        socket=call(__NR_socket,1,5|O_CLOEXEC|O_NONBLOCK,0,0);
        if(socket<0) return fail("socket-create",socket,90);
        long result=call(__NR_connect,socket,(long)&address,2+pathlen+1,0);
        if(result==0) { connected=1; break; }
        closefd(socket); socket=-1; last_error=result;
        if(result!=-2 && result!=-111 && result!=-11 && result!=-4) return fail("socket-connect",result,90);
        pause_reader();
    }
    if(!connected) return fail("socket-deadline",last_error,90);
    const char *request="stream lids=0,3,4";
    long sent;
    do { sent=call(__NR_write,socket,(long)request,length(request),0); }
    while(sent==-4);
    if(sent!=(long)length(request)) { closefd(socket); return fail("socket-request",sent,91); }
    if(writeall(status,"connected\n",10)<0 || call(__NR_fsync,status,0,0,0)<0) return 93;
    unsigned char buffer[65536]; usize total=0,synced=0,packets=0,skipped=0;
    const usize limit=2096128;
    while(now_seconds()<deadline) {
        long count=call(__NR_read,socket,(long)buffer,sizeof(buffer),0);
        if(count==-4) continue;
        if(count==-11) {
            if(total!=synced) {
                if(call(__NR_fsync,output,0,0,0)<0) return fail("log-sync",-5,93);
                synced=total;
            }
            pause_reader(); continue;
        }
        if(count<=0) { closefd(socket); return fail("socket-read",count?count:-5,92); }
        if(count<20) return fail("record-short",-22,92);
        unsigned int payload=little16(buffer),header=little16(buffer+2);
        if(header<20 || header>64 || header+payload!=(unsigned long)count)
            return fail("record-length",-22,92);
        if(!payload) return fail("record-empty",-22,92);
        unsigned int log_id=header>=24?buffer[20]:0;
        if(log_id!=4 && buffer[header]<5) { ++skipped; continue; }
        if(total+4+(usize)count>limit) {
            writeall(status,"capped\n",7); break;
        }
        unsigned int size=(unsigned int)count;
        if(writeall(output,(char *)&size,4)<0 || writeall(output,(char *)buffer,count)<0)
            return fail("log-write",-5,93);
        total+=4+count; ++packets;
        if(total-synced>=65536) {
            if(call(__NR_fsync,output,0,0,0)<0) return fail("log-sync",-5,93);
            synced=total;
        }
    }
    closefd(socket);
    if(call(__NR_fsync,output,0,0,0)<0) return fail("log-sync",-5,93);
    writeall(status,"packets=",8); number(status,packets);
    writeall(status," bytes=",7); number(status,total);
    writeall(status," skipped=",9); number(status,skipped); writeall(status,"\n",1);
    if(write_error || call(__NR_fsync,status,0,0,0)<0) return 93;
    return 0;
}
static long logdr_run(long argc,char **argv) {
#ifdef GOOGLE_DIAG_TEST
    if(argc!=3 || !equal(argv[2],"--logdr")) return 64;
    const char *rootpath=argv[1]; long duration=2;
#else
    if(argc!=2 || !equal(argv[1],"--logdr")) return 64;
    const char *rootpath="/"; long duration=110;
#endif
    long started=now_seconds(); if(started<0) return 70;
    struct { usize soft,hard; } no_core={0,0},size={2097152,2097152};
    if(call(__NR_prlimit64,0,4,(long)&no_core,0)<0 || call(__NR_prctl,4,0,0,0)<0) return 70;
    struct { usize handler,flags,restorer,mask; } action={0,0,0,0}; usize mask=0;
    struct { long interval_sec,interval_usec,value_sec,value_usec; } timer={0,0,duration+5,0};
    if(call(__NR_rt_sigaction,14,(long)&action,0,8)<0 ||
       call(__NR_rt_sigprocmask,2,(long)&mask,0,8)<0 ||
       call(__NR_setitimer,0,(long)&timer,0,0)<0 ||
       call(__NR_prlimit64,0,1,(long)&size,0)<0) return 70;
    long root=openat(AT_FDCWD,rootpath,O_RDONLY|O_DIRECTORY,0);
    if(root<0) return fail("root",root,71);
    long meta=beneath(root,"metadata",O_RDONLY|O_DIRECTORY);
    if(meta<0) return fail("metadata",meta,72);
    long mounted=metadata_mounted(root,meta);
    if(mounted<0) return fail("metadata-mount",mounted,87);
    long parent=open_private_dir(meta,"titan-pocket-diag");
    if(parent<0) return fail("private-dir",parent,73);
    long out=create_private_dir(parent,"logdr-v1");
    if(out<0) return fail("exclusive-run",out,74);
    long output=create(out,"android.bin"),status=create(out,"status.txt");
    if(output<0 || status<0) return fail("log-file",-5,79);
    if(call(__NR_dup3,status,2,0,0)<0) return 81;
    long dirs[]={out,parent,meta};
    for(usize i=0;i<3;++i) if(call(__NR_fsync,dirs[i],0,0,0)<0) return 94;
    char socketpath[108]; usize prefix=length(rootpath);
    if(prefix+17>=sizeof(socketpath)) return fail("socket-root",-36,90);
    memcpy(socketpath,rootpath,prefix);
    if(prefix && socketpath[prefix-1]=='/') --prefix;
    memcpy(socketpath+prefix,"/dev/socket/logdr",18);
    long result=logdr_stream(output,status,socketpath,started+duration);
    call(__NR_fsync,status,0,0,0);
    return result;
}
__attribute__((noreturn)) void entry(long *stack) {
    long result=logdr_run(stack[0],(char **)(stack+1)); call(__NR_exit_group,result,0,0,0);
    __builtin_unreachable();
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl entry\n");
