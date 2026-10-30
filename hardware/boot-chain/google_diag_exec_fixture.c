/* Successful-exec fixture only; never an Android image payload. */
#include <asm/unistd.h>
typedef unsigned long word;
static long sys(long n,long a,long b,long c,long d) {
    register long x8 __asm__("x8")=n;
    register long x0 __asm__("x0")=a;
    register long x1 __asm__("x1")=b;
    register long x2 __asm__("x2")=c;
    register long x3 __asm__("x3")=d;
    __asm__ volatile("svc 0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3):"memory","cc");
    return x0;
}
__attribute__((noreturn)) void entry(void) {
    long code=0;
    struct {word soft,hard;} core,size;
    struct {long a,b,sec,usec;} timer;
    struct {word handler,flags,restorer,mask;} signal;
    if(sys(__NR_prlimit64,0,4,0,(long)&core)<0 || core.soft || core.hard) code=1;
    if(sys(__NR_prlimit64,0,1,0,(long)&size)<0 || size.soft!=2097152 || size.hard!=2097152) code=2;
    if(sys(__NR_getitimer,0,(long)&timer,0,0)<0 || timer.sec<0 || timer.sec>120 || (!timer.sec&&!timer.usec)) code=3;
    if(sys(__NR_rt_sigaction,25,0,(long)&signal,8)<0 || signal.handler!=1) code=4;
    for(long fd=3;fd<128;++fd) if(sys(__NR_fcntl,fd,1,0,0)!=-9) code=5;
    if(code) {sys(__NR_exit_group,code,0,0,0); __builtin_unreachable();}
    sys(__NR_write,1,(long)"stdout-ok\n",10,0);
    sys(__NR_write,2,(long)"stderr-ok\n",10,0);
#if FIXTURE_MODE == 1
    /* A one-second alarm set in the launcher must survive exec. */
    for(;;) sys(__NR_ppoll,0,0,0,0);
#elif FIXTURE_MODE == 2
    char data[4096]; for(word i=0;i<sizeof(data);++i) data[i]='x';
    for(int i=0;i<514;++i) {
        long r=sys(__NR_write,1,(long)data,sizeof(data),0);
        if(r==-27) {sys(__NR_exit_group,0,0,0,0); __builtin_unreachable();}
        if(r<0) break;
    }
    code=6;
#endif
    sys(__NR_exit_group,code,0,0,0); __builtin_unreachable();
}
__asm__(".global _start\n_start:\nbl entry\n");
