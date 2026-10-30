#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint32_t raw_spinlock_t;
struct rcu_head { void *next; void *func; };
struct bpf_map {
    unsigned char prefix[24];
    u32 map_type,key_size,value_size,max_entries,map_flags,pages,id;
    int numa_node;
    unsigned char suffix[72];
};
_Static_assert(sizeof(struct bpf_map)==128,"Pinned CONFIG_SECURITY arm64 bpf_map size");
struct bpf_lpm_trie_key { u32 prefixlen; u8 data[]; };
#define __rcu
#define BIT(n) (1U << (n))
#define min(a,b) ((a)<(b)?(a):(b))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define GFP_ATOMIC 0x20
#define __GFP_NOWARN 0x200
static unsigned allocs, frees, fail_alloc;
static unsigned locked;
static int rcu_held;
static void *retired[5000];
static unsigned retired_count;
static void *kmalloc(size_t n, unsigned flags) {
    assert(flags == (GFP_ATOMIC|__GFP_NOWARN));
    if(fail_alloc) return NULL;
    allocs++;
    return malloc(n);
}
#define kmalloc_array(n,s,f) ((n)>SIZE_MAX/(s)?NULL:kmalloc((n)*(s),(f)))
static void kfree(void *p) { if(p) frees++; free(p); }
#define kmalloc_node(n,f,node) kmalloc((n),(f))
#define unlikely(x) (x)
#define BPF_EXIST 2
#define raw_spin_lock_irqsave(p,f) do{assert(!locked);locked=1;(f)=0;(void)(p);}while(0)
#define raw_spin_unlock_irqrestore(p,f) do{assert(locked);locked=0;(void)(p);(void)(f);}while(0)
#define lockdep_is_held(p) ((void)(p),locked)
#define rcu_dereference_protected(p,c) (assert(c),(p))
#define rcu_access_pointer(p) (p)
#define rcu_assign_pointer(p,v) do{assert(locked);(p)=(v);}while(0)
#define RCU_INIT_POINTER(p,v) ((p)=(v))
static void retire(void *p){assert(locked);assert(retired_count<5000);retired[retired_count++]=p;}
#define kfree_rcu(p,member) retire(p)
static void grace_period(void){assert(!locked&&!rcu_held);for(unsigned i=0;i<retired_count;i++)kfree(retired[i]);retired_count=0;}
#define fls shim_fls
static int shim_fls(unsigned x) { return x ? 32-__builtin_clz(x) : 0; }

#define rcu_dereference(p) (assert(rcu_held), (p))
#ifndef ITERATOR_HEADER
#define ITERATOR_HEADER "upstream-iterator.h"
#endif
#include ITERATOR_HEADER

struct key { u32 prefixlen; u8 data[256]; };
static unsigned checks, cases;
#define CHECK(x) do { checks++; if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);exit(1);} } while(0)
static unsigned bit(const u8 *d,unsigned n) { return (d[n/8]>>(7-n%8))&1; }
static void canonical(struct key *k, unsigned bytes) {
    for(unsigned i=k->prefixlen;i<bytes*8;i++) k->data[i/8]&=~(1U<<(7-i%8));
}
static struct lpm_trie_node *node(const struct key *k,unsigned bytes,int intermediate) {
    struct lpm_trie_node *n=calloc(1,sizeof(*n)+bytes);CHECK(n);allocs++;
    n->prefixlen=k->prefixlen;n->flags=intermediate?LPM_TREE_NODE_FLAG_IM:0;
    memcpy(n->data,k->data,bytes);return n;
}
/* Independent compressed-prefix builder; not copied from kernel insertion. */
static struct lpm_trie_node *insert(struct lpm_trie_node *n,const struct key *k,unsigned bytes) {
    if(!n)return node(k,bytes,0);
    unsigned common=0,limit=n->prefixlen<k->prefixlen?n->prefixlen:k->prefixlen;
    while(common<limit && bit(n->data,common)==bit(k->data,common)) common++;
    if(common<n->prefixlen){
        struct key p=*k;p.prefixlen=common;canonical(&p,bytes);
        struct lpm_trie_node *parent=node(&p,bytes,k->prefixlen!=common);
        parent->child[bit(n->data,common)]=n;
        if(k->prefixlen!=common)parent->child[bit(k->data,common)]=node(k,bytes,0);
        return parent;
    }
    if(k->prefixlen==n->prefixlen){n->flags=0;return n;}
    unsigned b=bit(k->data,n->prefixlen);n->child[b]=insert(n->child[b],k,bytes);return n;
}
static void destroy(struct lpm_trie_node *n){if(!n)return;destroy(n->child[0]);destroy(n->child[1]);kfree(n);}
static unsigned order(struct lpm_trie_node *n,struct key *out,unsigned bytes,unsigned at){
    if(!n)return at;
    CHECK(!(n->flags&LPM_TREE_NODE_FLAG_IM)||(n->child[0]&&n->child[1]));
    for(unsigned i=0;i<2;i++){if(n->child[i])CHECK(n->child[i]->prefixlen>n->prefixlen);at=order(n->child[i],out,bytes,at);}
    if(!(n->flags&LPM_TREE_NODE_FLAG_IM)){out[at].prefixlen=n->prefixlen;memcpy(out[at].data,n->data,bytes);at++;}return at;
}
static int next(struct lpm_trie *t,const struct key *in,struct key *out){
    unsigned before=allocs-frees;rcu_held=1;
    int r=trie_get_next_key(&t->map,(void *)in,out);
    rcu_held=0;CHECK(allocs-frees==before);return r;
}
static int same(const struct key *a,const struct key *b,unsigned bytes){return a->prefixlen==b->prefixlen&&!memcmp(a->data,b->data,bytes);}
static void validate(struct lpm_trie *t){
    struct key expected[3000]={0},got={0},current={0};unsigned n=order(t->root,expected,t->data_size,0);
    int r=next(t,NULL,&got);CHECK(r==(n?0:-ENOENT));if(n)CHECK(same(&got,&expected[0],t->data_size));
    for(unsigned i=0;i<n;i++){
        r=next(t,&expected[i],&got);CHECK(r==(i+1<n?0:-ENOENT));
        if(i+1<n)CHECK(same(&got,&expected[i+1],t->data_size));
    }
    /* A missing or invalid-prefix key restarts at the first real node. */
    current.prefixlen=t->max_prefixlen+1;r=next(t,&current,&got);CHECK(r==(n?0:-ENOENT));if(n)CHECK(same(&got,&expected[0],t->data_size));
    for(unsigned pass=0;pass<16;pass++){
        memset(&current,0,sizeof(current));current.prefixlen=t->max_prefixlen;
        memset(current.data,pass*17,t->data_size);
        unsigned found=n;for(unsigned i=0;i<n;i++)if(same(&current,&expected[i],t->data_size))found=i;
        unsigned want=found<n?found+1:0;r=next(t,&current,&got);CHECK(r==(n&&want<n?0:-ENOENT));
        if(n&&want<n){if(!same(&got,&expected[want],t->data_size))fprintf(stderr,"missing test bytes=%zu pass=%u n=%u found=%u got=%u/%02x want=%u/%02x query=%u/%02x\n",t->data_size,pass,n,found,got.prefixlen,got.data[0],expected[want].prefixlen,expected[want].data[0],current.prefixlen,current.data[0]);CHECK(same(&got,&expected[want],t->data_size));}
    }
    cases++;
}
static struct key key(unsigned prefix,unsigned first){struct key k={.prefixlen=prefix};k.data[0]=first;return k;}
static uint32_t seed=0x47160414;
static uint32_t random32(void){seed^=seed<<13;seed^=seed>>17;seed^=seed<<5;return seed;}
#ifdef HAS_MUTATIONS
static void update(struct lpm_trie *t,struct key *key){
    u8 value=0x71;
    CHECK(trie_update_elem(&t->map,key,&value,0)==0);CHECK(!locked);grace_period();
}
static void mutation_cases(void){
    {
        struct lpm_trie t={.max_prefixlen=8,.data_size=1};t.map.max_entries=100;t.map.value_size=1;
        struct key root_key=key(0,0),left=key(1,0),right=key(1,128),out;
        update(&t,&root_key);update(&t,&left);update(&t,&right);validate(&t);
        CHECK(trie_delete_elem(&t.map,&root_key)==0);CHECK(t.root->flags&LPM_TREE_NODE_FLAG_IM);CHECK(t.n_entries==2);grace_period();
        CHECK(trie_delete_elem(&t.map,&left)==0);CHECK(retired_count==2);CHECK(t.root->prefixlen==1&&t.root->data[0]==128);
        /* Deferred nodes remain readable until our mocked grace period. */
        CHECK(((struct lpm_trie_node *)retired[0])->prefixlen==0);grace_period();
        CHECK(trie_delete_elem(&t.map,&left)==-ENOENT);CHECK(t.n_entries==1);
        CHECK(next(&t,&left,&out)==0&&same(&out,&right,1));
        CHECK(trie_delete_elem(&t.map,&right)==0);grace_period();CHECK(!t.root&&t.n_entries==0);
    }
    unsigned sizes[]={1,4,16,24,256};
    for(unsigned s=0;s<5;s++)for(unsigned trial=0;trial<25;trial++){
        struct lpm_trie t={.max_prefixlen=sizes[s]*8,.data_size=sizes[s]};
        t.map.max_entries=2000;t.map.value_size=1;
        for(unsigned j=0;j<40;j++){
            struct key k={.prefixlen=random32()%(t.max_prefixlen+1)};
            for(unsigned b=0;b<t.data_size;b++)k.data[b]=random32();canonical(&k,t.data_size);update(&t,&k);
        }
        struct key zero=key(0,0);update(&t,&zero);validate(&t);
        struct key missing=key(t.max_prefixlen+1,0);
        CHECK(trie_delete_elem(&t.map,&missing)==-EINVAL);
        struct key snapshot[3000]={0};unsigned count=order(t.root,snapshot,t.data_size,0);CHECK(count==t.n_entries);
        for(unsigned j=0;j<16;j++){
            missing=key(t.max_prefixlen,j*17);memset(missing.data,j*17,t.data_size);
            unsigned found=count;for(unsigned i=0;i<count;i++)if(same(&missing,&snapshot[i],t.data_size))found=i;
            if(found==count){CHECK(trie_delete_elem(&t.map,&missing)==-ENOENT);CHECK(t.n_entries==count);}
        }
        unsigned at=count/2;struct key deleted=snapshot[at];
        CHECK(trie_delete_elem(&t.map,&deleted)==0);CHECK(t.n_entries==count-1);grace_period();
        CHECK(trie_delete_elem(&t.map,&deleted)==-ENOENT);grace_period();validate(&t);
        struct key expected[3000]={0},out={0};unsigned n=order(t.root,expected,t.data_size,0);
        CHECK(next(&t,&deleted,&out)==(n?0:-ENOENT));if(n)CHECK(same(&out,&expected[0],t.data_size));
        unsigned removed=0;
        while(next(&t,NULL,&out)==0){CHECK(removed++<count);CHECK(trie_delete_elem(&t.map,&out)==0);CHECK(!locked);grace_period();}
        CHECK(removed==count-1);CHECK(t.root==NULL);CHECK(t.n_entries==0);validate(&t);
        CHECK(trie_delete_elem(&t.map,&zero)==-ENOENT);grace_period();
    }
    struct lpm_trie t={.max_prefixlen=2048,.data_size=256};struct lpm_trie_node **slot=&t.root;
    for(unsigned p=0;p<=2048;p++){struct key k=key(p,0);*slot=node(&k,256,0);slot=&(*slot)->child[0];}
    struct key last=key(2048,0),out;
    CHECK(next(&t,&last,&out)==0);CHECK(out.prefixlen==2047);CHECK(next(&t,NULL,&out)==0);CHECK(out.prefixlen==2048);struct key root_key=key(0,0);CHECK(next(&t,&root_key,&out)==-ENOENT);destroy(t.root);
    memset(&t,0,sizeof(t));t.max_prefixlen=192;t.data_size=24;t.map.max_entries=1000;t.map.value_size=1;
    for(unsigned p=0;p<=192;p++){struct key k=key(p,0);update(&t,&k);}validate(&t);
    unsigned removed=0;while(next(&t,NULL,&out)==0){CHECK(trie_delete_elem(&t.map,&out)==0);removed++;grace_period();}
    CHECK(removed==193&&t.n_entries==0&&t.root==NULL);
}
#endif
int main(int argc,char **argv){
    struct lpm_trie t={.max_prefixlen=8,.data_size=1};
    if(argc>1&&!strcmp(argv[1],"right-only")){
        struct key a=key(0,0),b=key(1,128);t.root=insert(NULL,&a,1);t.root=insert(t.root,&b,1);validate(&t);destroy(t.root);
    }else if(argc>1&&!strcmp(argv[1],"deep-stack")){
        for(unsigned p=0;p<=8;p++){struct key k=key(p,0);t.root=insert(t.root,&k,1);}validate(&t);destroy(t.root);
    }else{
        validate(&t);
        for(unsigned bytes_index=0;bytes_index<4;bytes_index++){
            unsigned sizes[]={1,4,16,24};unsigned bytes=sizes[bytes_index];
            for(unsigned trial=0;trial<100;trial++){
                memset(&t,0,sizeof(t));t.data_size=bytes;t.max_prefixlen=8*bytes;
                for(unsigned j=0;j<80;j++){
                    struct key k={.prefixlen=random32()%(t.max_prefixlen+1)};
                    for(unsigned b=0;b<bytes;b++)k.data[b]=random32();canonical(&k,bytes);t.root=insert(t.root,&k,bytes);
                }validate(&t);
                /* Allocation errors remain errors, with no fabricated result. */
                struct key k=key(0,0),out;fail_alloc=1;int r=next(&t,&k,&out);fail_alloc=0;
                CHECK(r==-ENOMEM);destroy(t.root);
            }
        }
    }
#ifdef HAS_MUTATIONS
    if(argc==1)mutation_cases();
#endif
    CHECK(allocs==frees);printf("PASS cases=%u checks=%u allocs=%u frees=%u\n",cases,checks,allocs,frees);return 0;
}
