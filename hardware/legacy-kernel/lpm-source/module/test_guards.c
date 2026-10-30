#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;
#define READ_ONCE(p) (p)
#define pr_notice(...) ((void)0)
#define pr_crit(...) ((void)0)
#define THIS_MODULE ((void *)1)
static unsigned hook_status,checks;
static unsigned long fake_base,callback_get,callback_delete;
static int cpus_locked,pinned,patch_calls,mode,pin_failure,lookup_wrong;
static const char *release="4.14.186-g40b2a1864-dirty";
struct uts { const char *release; };
static struct uts *init_utsname(void){static struct uts u;u.release=release;return &u;}
static void cpus_read_lock(void){assert(!cpus_locked);cpus_locked=1;}
static void cpus_read_unlock(void){assert(cpus_locked);cpus_locked=0;}
static int try_module_get(void *p){assert(p==THIS_MODULE&&cpus_locked);if(pin_failure)return 0;pinned++;return 1;}
static unsigned long kallsyms_lookup_name(const char *s){
    if(!strcmp(s,"_stext"))return fake_base+0x800+(lookup_wrong?0x800:0);
    if(!strcmp(s,"trie_get_next_key"))return fake_base+0x16068c;
    if(!strcmp(s,"trie_delete_elem"))return fake_base+0x160a70;
    if(!strcmp(s,"aarch64_insn_patch_text"))return fake_base+0xef2c;
    return 0;
}
static int mock_patch(void *targets[],u32 words[],int count){
    assert(cpus_locked&&pinned==1&&count==2);patch_calls++;
    if(patch_calls==1){
        if(mode==1)return -EIO;
        *(u32 *)targets[0]=words[0];
        if(mode==2||mode==3)return -EIO;
        if(mode==4){*(u32 *)targets[0]=0xdeadbeef;return -EIO;}
        *(u32 *)targets[1]=words[1];
        if(mode==5)return -EIO;
        if(mode==6){((u32 *)targets[0])[1]=0xd503201f;return 0;}
    }else{
        if(mode==3)return -EIO;
        *(u32 *)targets[0]=words[0];*(u32 *)targets[1]=words[1];
    }
    return 0;
}
#define trie_get_next_key callback_get
#define trie_delete_elem callback_delete
#include "hook-test-body.h"
#define CHECK(p) do{checks++;if(!(p)){fprintf(stderr,"FAIL line%d: %s\n",__LINE__,#p);exit(1);}}while(0)
static void reset(void){
    cpus_locked=pinned=patch_calls=mode=pin_failure=lookup_wrong=hook_status=0;
    release="4.14.186-g40b2a1864-dirty";
    u32 *a=(u32 *)(fake_base+0x16068c),*b=(u32 *)(fake_base+0x160a70);
    a[0]=0x12804160;a[1]=0xd65f03c0;b[0]=0x128004a0;b[1]=0xd65f03c0;
    callback_get=fake_base+0x200000;callback_delete=fake_base+0x201000;
}
int main(void){
    void *memory=calloc(1,0x210000);assert(memory);fake_base=(unsigned long)memory;
    u32 branch;
    for(long delta=-134217728;delta<=134217724;delta+=134217724){
        CHECK(branch_word(0x10000000,0x10000000+delta,&branch)==0);
        int32_t imm=(int32_t)(branch<<6)>>6;CHECK((int64_t)imm*4==delta);
    }
    CHECK(branch_word(0x10000000,0x10000000+134217724UL,&branch)==0);
    CHECK(branch==0x15ffffffU);
    CHECK(branch_word(0x10000000,0x10000000,&branch)==0);
    CHECK(branch==0x14000000U);
    CHECK(branch_word(0x10000000,0x10000000-134217732UL,&branch)==-ERANGE);
    CHECK(branch_word(0x10000000,0x10000000+134217728UL,&branch)==-ERANGE);
    CHECK(branch_word(0x10000001,0x10000000,&branch)==-ERANGE);
    CHECK(branch_word(0x10000000,0x10000001,&branch)==-ERANGE);
    reset();CHECK(init_module()==0);CHECK(patch_calls==1&&pinned==1&&!cpus_locked&&hook_status==7);
    for(unsigned which=0;which<4;which++){
        reset();u32 *p=(u32 *)(fake_base+(which<2?0x16068c:0x160a70));p[which%2]^=1;
        CHECK(init_module()==-EINVAL);CHECK(!patch_calls&&!pinned&&!cpus_locked);
    }
    reset();lookup_wrong=1;CHECK(init_module()==-ENODEV);CHECK(!patch_calls&&!pinned);
    reset();release="wrong";CHECK(init_module()==-ENODEV);CHECK(!patch_calls&&!pinned);
    reset();callback_delete=fake_base+0x160a70+134217728UL;CHECK(init_module()==-ERANGE);CHECK(!patch_calls&&!pinned);
    reset();pin_failure=1;CHECK(init_module()==-EBUSY);CHECK(!patch_calls&&!pinned&&!cpus_locked);
    for(unsigned failure=1;failure<=6;failure++){
        reset();mode=failure;CHECK(init_module()==0);CHECK(pinned==1&&!cpus_locked);
        if(failure==1||failure==2||failure==5)CHECK((hook_status&8)&&!(hook_status&6)&&patch_calls==2);
        if(failure==3)CHECK((hook_status&32)&&(hook_status&2)&&patch_calls==2);
        if(failure==4||failure==6)CHECK((hook_status&64)&&patch_calls==1);
    }
    free(memory);printf("PASS hook guard/state checks=%u\n",checks);return 0;
}
