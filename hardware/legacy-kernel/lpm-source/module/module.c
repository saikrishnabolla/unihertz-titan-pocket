/* Offline-only candidate. No deployment is performed by this source. */
#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/cpu.h>
#include <linux/kallsyms.h>
#include <linux/uts.h>
#include <linux/utsname.h>
#include <asm/insn.h>

#include "backport-functions.h"

_Static_assert(sizeof(struct bpf_map) == 128, "stock bpf_map ABI");
_Static_assert(offsetof(struct lpm_trie, root) == 128, "stock trie root");
_Static_assert(offsetof(struct lpm_trie, n_entries) == 136, "stock trie count");
_Static_assert(offsetof(struct lpm_trie, max_prefixlen) == 144, "stock trie max prefix");
_Static_assert(offsetof(struct lpm_trie, data_size) == 152, "stock trie data size");
_Static_assert(offsetof(struct lpm_trie, lock) == 160, "stock trie lock");
_Static_assert(sizeof(raw_spinlock_t) == 4, "stock raw lock ABI");
_Static_assert(offsetof(struct lpm_trie_node, child) == 16, "stock node children");
_Static_assert(offsetof(struct lpm_trie_node, prefixlen) == 32, "stock node prefix");
_Static_assert(offsetof(struct lpm_trie_node, flags) == 36, "stock node flags");
_Static_assert(offsetof(struct lpm_trie_node, data) == 40, "stock node data");
_Static_assert(offsetof(struct bpf_map_ops, map_get_next_key) == 24, "stock iterator slot");
_Static_assert(offsetof(struct bpf_map_ops, map_delete_elem) == 64, "stock delete slot");

/* 1=attempted,2=iterator live,4=delete live,8=both originals restored,
 * 16=patch error,32=rollback error,64=unexpected readback. */
static unsigned int hook_status;
module_param_named(hook_status, hook_status, uint, 0444);
MODULE_PARM_DESC(hook_status, "Permanent resident hook state; no automatic unload");

static int branch_word(unsigned long from, unsigned long to, u32 *word)
{
    s64 delta = (s64)((u64)to - (u64)from);
    if ((from | to) & 3 || delta < -134217728LL || delta > 134217724LL)
        return -ERANGE;
    *word = 0x14000000U | ((u32)(delta >> 2) & 0x03ffffffU);
    return 0;
}
static bool words_equal(void *target, u32 first)
{
    u32 *p = target;
    return READ_ONCE(p[0]) == first && READ_ONCE(p[1]) == 0xd65f03c0U;
}
static unsigned live_bits(void **targets, u32 *branches)
{
    unsigned state = 0;
    if (words_equal(targets[0], branches[0])) state |= 2;
    if (words_equal(targets[1], branches[1])) state |= 4;
    return state;
}

int init_module(void)
{
    typedef int (*patch_fn)(void *[], u32 [], int);
    unsigned long base, getnext, del, patch_address;
    patch_fn patch;
    void *targets[2];
    u32 branches[2], originals[2] = {0x12804160U, 0x128004a0U};
    int result, rollback;
    bool known;

    if (strcmp(init_utsname()->release, "4.14.186-g40b2a1864-dirty"))
        return -ENODEV;
    base = kallsyms_lookup_name("_stext");
    if (base < 0x800UL) return -ENODEV;
    base -= 0x800UL;
    getnext = kallsyms_lookup_name("trie_get_next_key");
    del = kallsyms_lookup_name("trie_delete_elem");
    patch_address = kallsyms_lookup_name("aarch64_insn_patch_text");
    if (!base || getnext != base + 0x16068cUL || del != base + 0x160a70UL ||
        patch_address != base + 0xef2cUL)
        return -ENODEV;
    patch = (patch_fn)patch_address;
    targets[0] = (void *)getnext;
    targets[1] = (void *)del;
    if (branch_word(getnext, (unsigned long)trie_get_next_key, &branches[0]) ||
        branch_word(del, (unsigned long)trie_delete_elem, &branches[1]))
        return -ERANGE;
    cpus_read_lock();
    if (!words_equal(targets[0], originals[0]) || !words_equal(targets[1], originals[1])) {
        cpus_read_unlock();
        return -EINVAL;
    }
    /* Pin before text can reference this module. No exit routine exists. */
    if (!try_module_get(THIS_MODULE)) {
        cpus_read_unlock();
        return -EBUSY;
    }
    hook_status = 1;
    result = patch(targets, branches, 2);
    hook_status |= live_bits(targets, branches);
    if (result) hook_status |= 16;
    if (!result && (hook_status & 6) == 6) {
        cpus_read_unlock();
        pr_notice("titan_lpm: both hooks installed; module permanently resident\n");
        return 0;
    }
    /* The kernel API is not transactional. Only undo our own known words. */
    known = (words_equal(targets[0], originals[0]) || words_equal(targets[0], branches[0])) &&
            (words_equal(targets[1], originals[1]) || words_equal(targets[1], branches[1]));
    if (known) {
        rollback = patch(targets, originals, 2);
        if (rollback) hook_status |= 32;
        hook_status &= ~6U;
        hook_status |= live_bits(targets, branches);
        if (words_equal(targets[0], originals[0]) && words_equal(targets[1], originals[1]))
            hook_status |= 8;
        else
            hook_status |= 64;
    } else {
        hook_status |= 64;
    }
    cpus_read_unlock();
    pr_crit("titan_lpm: hook attempt failed, status=%u; resident for safety; inspect before any further action\n", hook_status);
    /* Never free resident callbacks after any attempted write. */
    return 0;
}

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Titan legacy LPM iteration and deletion; offline experimental candidate");
MODULE_INFO(vermagic, "4.14.186-g40b2a1864-dirty SMP preempt mod_unload modversions aarch64");
MODULE_INFO(name, "titan_lpm");
MODULE_INFO(depends, "");
struct module __this_module __attribute__((section(".gnu.linkonce.this_module"))) = {
    .name = "titan_lpm",
    .init = init_module,
};
asm(".pushsection .plt,\"ax\",%nobits\n.balign 4\n.popsection\n"
    ".pushsection .init.plt,\"ax\",%nobits\n.balign 4\n.popsection\n");
#include "versions.h"
