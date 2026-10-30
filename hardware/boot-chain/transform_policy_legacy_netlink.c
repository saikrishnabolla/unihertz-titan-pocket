#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sepol/kernel_to_conf.h>
#include <sepol/policydb.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/polcaps.h>

_Static_assert(POLICYDB_CAP_NETLINK_XPERM == 9, "Unexpected capability numbering");

struct image {
    void *data;
    size_t size;
};

struct counts {
    size_t ioctl;
    size_t allowed;
    size_t auditallow;
    size_t dontaudit;
};

struct removed {
    avtab_ptr_t *link;
    avtab_ptr_t node;
};

static int compare_nodes(const void *a, const void *b)
{
    const struct avtab_node *x = *(avtab_ptr_t const *)a;
    const struct avtab_node *y = *(avtab_ptr_t const *)b;
#define COMPARE(field) do { if (x->field != y->field) return x->field < y->field ? -1 : 1; } while (0)
    COMPARE(key.source_type);
    COMPARE(key.target_type);
    COMPARE(key.target_class);
    COMPARE(key.specified);
    if (x->key.specified & AVTAB_XPERMS) {
        COMPARE(datum.xperms->specified);
        COMPARE(datum.xperms->driver);
        for (size_t i = 0; i < 8; ++i) COMPARE(datum.xperms->perms[i]);
    } else {
        COMPARE(datum.data);
    }
#undef COMPARE
    return 0;
}

static int canonicalize_avtab(avtab_t *table)
{
    avtab_ptr_t *nodes = calloc(table->nel ? table->nel : 1, sizeof(*nodes));
    if (!nodes) return -1;
    /* libsepol reverses equal-key xperm nodes on read; only their order changes here. */
    for (uint32_t i = 0; i < table->nslot; ++i) {
        size_t count = 0;
        for (avtab_ptr_t n = table->htable[i]; n; n = n->next) nodes[count++] = n;
        if (!count) continue;
        qsort(nodes, count, sizeof(*nodes), compare_nodes);
        table->htable[i] = nodes[0];
        for (size_t j = 1; j < count; ++j) nodes[j - 1]->next = nodes[j];
        nodes[count - 1]->next = NULL;
    }
    free(nodes);
    return 0;
}

static int read_memory(struct image image, sepol_policydb_t **db)
{
    sepol_policy_file_t *file = NULL;
    int rc = -1;
    if (sepol_policydb_create(db) || sepol_policy_file_create(&file))
        goto out;
    sepol_policy_file_set_mem(file, image.data, image.size);
    /* Unlike from_image(), read() leaves failure cleanup to this caller. */
    if (sepol_policydb_read(*db, file)) {
        fputs("Cannot read policy\n", stderr);
        goto out;
    }
    if (file->pf.len) {
        fputs("Trailing policy bytes are not supported\n", stderr);
        goto out;
    }
    if ((*db)->p.policy_type != POLICY_KERN || (*db)->p.policyvers != 30 ||
        (*db)->p.target_platform != SEPOL_TARGET_SELINUX) {
        fputs("Requires a SELinux kernel policy version 30\n", stderr);
        goto out;
    }
    if (canonicalize_avtab(&(*db)->p.te_avtab)) goto out;
    rc = 0;
out:
    sepol_policy_file_free(file);
    return rc;
}

static int read_input(const char *path, sepol_policydb_t **db)
{
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    FILE *input = NULL;
    struct stat st;
    struct image image = {0};
    int rc = -1;
    if (fd < 0) {
        perror("open input");
        return -1;
    }
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size <= 0 || st.st_size > 64 * 1024 * 1024) {
        fputs("Input must be a nonempty regular policy file of at most 64 MiB\n", stderr);
        goto out;
    }
    input = fdopen(fd, "rb");
    if (!input) goto out;
    image.size = (size_t)st.st_size;
    image.data = malloc(image.size);
    if (!image.data || fread(image.data, 1, image.size, input) != image.size ||
        fgetc(input) != EOF || ferror(input)) {
        fputs("Cannot read complete input\n", stderr);
        goto out;
    }
    rc = read_memory(image, db);
out:
    free(image.data);
    if (input) fclose(input);
    else close(fd);
    return rc;
}

static int inspect_xperms(const policydb_t *p, struct counts *counts)
{
    const avtab_t *tables[] = {&p->te_avtab, &p->te_cond_avtab};
    for (size_t t = 0; t < 2; ++t) {
        for (uint32_t i = 0; i < tables[t]->nslot; ++i) {
            for (avtab_ptr_t n = tables[t]->htable[i]; n; n = n->next) {
                if (!(n->key.specified & AVTAB_XPERMS))
                    continue;
                const avtab_extended_perms_t *x = n->datum.xperms;
                if (!x || (x->specified != AVTAB_XPERMS_IOCTLFUNCTION &&
                           x->specified != AVTAB_XPERMS_IOCTLDRIVER &&
                           x->specified != AVTAB_XPERMS_NLMSG)) {
                    fputs("Unknown xperm kind\n", stderr);
                    return -1;
                }
                if (x->specified != AVTAB_XPERMS_NLMSG) {
                    ++counts->ioctl;
                    continue;
                }
                if (t) {
                    fputs("Conditional NLMSG is not supported\n", stderr);
                    return -1;
                }
                switch (n->key.specified & ~AVTAB_ENABLED) {
                case AVTAB_XPERMS_ALLOWED: ++counts->allowed; break;
                case AVTAB_XPERMS_AUDITALLOW: ++counts->auditallow; break;
                case AVTAB_XPERMS_DONTAUDIT: ++counts->dontaudit; break;
                default:
                    fputs("Unsupported NLMSG rule flags\n", stderr);
                    return -1;
                }
            }
        }
    }
    return 0;
}

static int serialize(sepol_policydb_t *db, struct image *image)
{
    if (sepol_policydb_to_image(NULL, db, &image->data, &image->size)) {
        fputs("Cannot serialize policy\n", stderr);
        return -1;
    }
    return 0;
}

static int equal_images(struct image a, struct image b)
{
    return a.size == b.size && memcmp(a.data, b.data, a.size) == 0;
}

static int publish_new(const char *path, struct image image)
{
    char *temporary = NULL;
    FILE *out = NULL;
    int fd = -1, rc = -1;
    struct stat st;
    if (!path[0]) {
        fputs("Output path must not be empty\n", stderr);
        return -1;
    }
    if (!lstat(path, &st)) {
        fputs("Output path already exists; refusing to replace it\n", stderr);
        return -1;
    }
    if (errno != ENOENT) {
        perror("inspect output path");
        return -1;
    }
    if (asprintf(&temporary, "%s.tmp.XXXXXX", path) < 0)
        return -1;
    fd = mkstemp(temporary);
    if (fd < 0 || !(out = fdopen(fd, "wb"))) {
        perror("create temporary output");
        if (fd >= 0) close(fd);
        goto done;
    }
    int failed = fwrite(image.data, 1, image.size, out) != image.size;
    if (fflush(out) || fsync(fileno(out)))
        failed = 1;
    if (fclose(out)) failed = 1;
    out = NULL;
    if (failed) {
        fputs("Cannot write complete temporary output\n", stderr);
        goto done;
    }
    /* Same-directory hard link publishes a complete file without replacing a name. */
    if (link(temporary, path)) {
        perror("publish new output (existing paths are never replaced)");
        goto done;
    }
    rc = 0;
done:
    if (out) fclose(out);
    if (unlink(temporary) && errno != ENOENT)
        perror("remove temporary output");
    free(temporary);
    return rc;
}

static int compare_strings(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static int inventory(sepol_policydb_t *db)
{
    policydb_t *p = &db->p;
    const avtab_t *tables[] = {&p->te_avtab, &p->te_cond_avtab};
    size_t used = 0, size = (size_t)p->te_avtab.nel + p->te_cond_avtab.nel;
    char **lines = calloc(size ? size : 1, sizeof(*lines));
    int rc = -1;
    if (!lines) return -1;
    for (size_t t = 0; t < 2; ++t) {
        for (uint32_t i = 0; i < tables[t]->nslot; ++i) {
            for (avtab_ptr_t n = tables[t]->htable[i]; n; n = n->next) {
                char *line = NULL;
                const avtab_extended_perms_t *x =
                    n->key.specified & AVTAB_XPERMS ? n->datum.xperms : NULL;
                int len = asprintf(&line,
                    "avtab table=%s source=%u:%s target=%u:%s class=%u:%s flags=%04x "
                    "data=%08x kind=%u driver=%u perms=%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x",
                    t ? "conditional" : "unconditional",
                    n->key.source_type, p->p_type_val_to_name[n->key.source_type - 1],
                    n->key.target_type, p->p_type_val_to_name[n->key.target_type - 1],
                    n->key.target_class, p->p_class_val_to_name[n->key.target_class - 1],
                    n->key.specified, n->datum.data, x ? x->specified : 0,
                    x ? x->driver : 0, x ? x->perms[0] : 0, x ? x->perms[1] : 0,
                    x ? x->perms[2] : 0, x ? x->perms[3] : 0, x ? x->perms[4] : 0,
                    x ? x->perms[5] : 0, x ? x->perms[6] : 0, x ? x->perms[7] : 0);
                if (len < 0 || used >= size) {
                    free(line);
                    goto done;
                }
                lines[used++] = line;
            }
        }
    }
    if (used != size) goto done;
    qsort(lines, used, sizeof(*lines), compare_strings);
    printf("policy type=%u version=%u target=%d mls=%d unknown=%u\n",
           p->policy_type, p->policyvers, p->target_platform, p->mls, p->handle_unknown);
    ebitmap_node_t *node;
    unsigned int bit;
    ebitmap_for_each_positive_bit(&p->policycaps, node, bit)
        printf("policycap %u\n", bit);
    for (size_t i = 0; i < used; ++i) puts(lines[i]);
    puts("--- canonical policy.conf ---");
    if (sepol_kernel_policydb_to_conf(stdout, p) || fflush(stdout) || ferror(stdout))
        goto done;
    rc = 0;
done:
    for (size_t i = 0; i < used; ++i) free(lines[i]);
    free(lines);
    return rc;
}

static int transform(sepol_policydb_t *db, const char *output, struct counts before)
{
    struct image original = {0}, changed = {0}, restored = {0}, reread = {0};
    sepol_policydb_t *check = NULL;
    struct counts after = {0};
    size_t total = before.allowed + before.auditallow + before.dontaudit, used = 0;
    struct removed *removed = calloc(total ? total : 1, sizeof(*removed));
    int rc = -1;
    if (!removed || serialize(db, &original)) goto done;
    int old_cap = ebitmap_get_bit(&db->p.policycaps, POLICYDB_CAP_NETLINK_XPERM);
    avtab_t *table = &db->p.te_avtab;
    for (uint32_t i = 0; i < table->nslot; ++i) {
        avtab_ptr_t *link = &table->htable[i];
        while (*link) {
            avtab_ptr_t n = *link;
            if ((n->key.specified & AVTAB_XPERMS) &&
                n->datum.xperms->specified == AVTAB_XPERMS_NLMSG) {
                removed[used++] = (struct removed){link, n};
                *link = n->next;
                --table->nel;
            } else {
                link = &n->next;
            }
        }
    }
    int failed = ebitmap_set_bit(&db->p.policycaps, POLICYDB_CAP_NETLINK_XPERM, 0);
    if (!failed) failed = serialize(db, &changed);
    /* Restore exact chain positions, then prove all other serialized state survived. */
    while (used) {
        struct removed r = removed[--used];
        r.node->next = *r.link;
        *r.link = r.node;
        ++table->nel;
    }
    if (ebitmap_set_bit(&db->p.policycaps, POLICYDB_CAP_NETLINK_XPERM, old_cap) || failed)
        goto done;
    if (serialize(db, &restored) || !equal_images(original, restored)) {
        fputs("Inverse transform changed unrelated serialized policy state\n", stderr);
        goto done;
    }
    if (read_memory(changed, &check) || inspect_xperms(&check->p, &after) ||
        after.allowed || after.auditallow || after.dontaudit || after.ioctl != before.ioctl ||
        ebitmap_get_bit(&check->p.policycaps, POLICYDB_CAP_NETLINK_XPERM) ||
        serialize(check, &reread) || !equal_images(changed, reread)) {
        fputs("Transformed policy failed read-back invariants\n", stderr);
        goto done;
    }
    if (publish_new(output, changed)) goto done;
    printf("{\"removed_allowed\":%zu,\"removed_auditallow\":%zu,"
           "\"removed_dontaudit\":%zu,\"preserved_ioctl\":%zu,"
           "\"cleared_capability\":9,\"capability_was_enabled\":%s,"
           "\"inverse_serialization_equal\":true,\"readback_serialization_equal\":true}\n",
           before.allowed, before.auditallow, before.dontaudit, before.ioctl,
           old_cap ? "true" : "false");
    fputs("Legacy NLMSG permissions are coarser; this is not security-equivalent.\n", stderr);
    rc = 0;
done:
    free(removed);
    free(original.data);
    free(changed.data);
    free(restored.data);
    free(reread.data);
    sepol_policydb_free(check);
    return rc;
}

int main(int argc, char **argv)
{
    int inspect = argc == 3 && strcmp(argv[1], "--inventory") == 0;
    int roundtrip = argc == 4 && strcmp(argv[1], "--roundtrip") == 0;
    if ((!inspect && !roundtrip && argc != 3) ||
        (!inspect && !roundtrip && argv[1][0] == '-')) {
        fprintf(stderr, "Usage: %s INPUT NEW_OUTPUT\n"
                        "       %s --inventory INPUT\n"
                        "       %s --roundtrip INPUT NEW_OUTPUT\n", argv[0], argv[0], argv[0]);
        return 64;
    }
    sepol_policydb_t *db = NULL;
    struct counts counts = {0};
    int rc = 1;
    if (read_input(argv[inspect || roundtrip ? 2 : 1], &db) ||
        inspect_xperms(&db->p, &counts)) goto done;
    if (inspect) {
        rc = inventory(db) ? 1 : 0;
    } else if (roundtrip) {
        struct image image = {0};
        if (!serialize(db, &image)) rc = publish_new(argv[3], image) ? 1 : 0;
        free(image.data);
    } else {
        rc = transform(db, argv[2], counts) ? 1 : 0;
    }
done:
    sepol_policydb_free(db);
    return rc;
}
