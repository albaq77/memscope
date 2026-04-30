#include "collector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

struct bpf_object *g_bpf_obj = NULL;

static int add_alloc_record(struct alloc_table *tbl, struct alloc_record *rec)
{
    if (tbl->count >= tbl->capacity) {
        size_t new_cap = tbl->capacity ? tbl->capacity * 2 : 1024;
        struct alloc_record *new_buf = realloc(tbl->records,
                                                new_cap * sizeof(*new_buf));
        if (!new_buf)
            return -ENOMEM;
        tbl->records = new_buf;
        tbl->capacity = new_cap;
    }
    tbl->records[tbl->count++] = *rec;
    return 0;
}

static struct alloc_record *find_live_alloc(struct alloc_table *tbl, uint64_t addr)
{
    for (size_t i = 0; i < tbl->count; i++) {
        struct alloc_record *r = &tbl->records[i];
        if (r->live && addr >= r->addr && addr < r->addr + r->size)
            return r;
    }
    return NULL;
}

static int handle_event(void *ctx, void *data, size_t size)
{
    struct collector_ctx *cctx = (struct collector_ctx *)ctx;
    struct mem_event *evt = (struct mem_event *)data;

    (void)size;

    if (cctx->target_pid && evt->pid != cctx->target_pid)
        return 0;

    switch (evt->type) {
    case EVENT_MALLOC_ENTRY:
        break;

    case EVENT_MALLOC_RETURN: {
        struct alloc_record rec = {};
        rec.addr = evt->malloc_ret.addr;
        rec.size = evt->malloc_ret.size;
        rec.timestamp_alloc = evt->timestamp;
        rec.pid = evt->pid;
        rec.tid = evt->tid;
        rec.live = 1;
        rec.stack_id = evt->stack_id;
        add_alloc_record(&cctx->table, &rec);
        break;
    }

    case EVENT_FREE: {
        struct alloc_record *rec = find_live_alloc(&cctx->table,
                                                    evt->free_evt.addr);
        if (rec) {
            rec->live = 0;
            rec->timestamp_free = evt->timestamp;
        }
        break;
    }

    case EVENT_MMAP:
    case EVENT_MUNMAP:
    case EVENT_STACK_SAMPLE:
        break;

    default:
        fprintf(stderr, "unknown event type: %u\n", evt->type);
    }

    return 0;
}

static const char *find_libc_path(void)
{
    const char *paths[] = {
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib64/libc.so.6",
        "/lib/aarch64-linux-gnu/libc.so.6",
        "/usr/lib/aarch64-linux-gnu/libc.so.6",
        "libc.so.6",
        NULL
    };

    for (int i = 0; paths[i]; i++) {
        if (access(paths[i], R_OK) == 0)
            return paths[i];
    }
    return "libc.so.6";
}

static long find_func_offset(const char *binary_path, const char *func_name)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "objdump -T %s 2>/dev/null | grep ' %s$' | awk '{print $1}'", binary_path, func_name);
    FILE *fp = popen(cmd, "r");
    if (!fp)
        return -1;

    char buf[64];
    long offset = -1;
    if (fgets(buf, sizeof(buf), fp)) {
        offset = strtoul(buf, NULL, 16);
    }
    pclose(fp);
    return offset;
}

static int attach_uprobes(struct collector_ctx *ctx, struct bpf_object *obj)
{
    const char *libc_path = find_libc_path();

    struct {
        const char *prog_name;
        const char *func_name;
        int retprobe;
    } probes[] = {
        { "uprobe_malloc_entry",   "malloc",  0 },
        { "uprobe_malloc_return",  "malloc",  1 },
        { "uprobe_free",           "free",    0 },
        { "uprobe_mmap_entry",     "mmap",    0 },
        { "uprobe_munmap_entry",   "munmap",  0 },
    };

    ctx->link_count = 0;

    for (size_t i = 0; i < sizeof(probes)/sizeof(probes[0]) && ctx->link_count < MAX_ATTACH_POINTS; i++) {
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, probes[i].prog_name);
        if (!prog) {
            fprintf(stderr, "BPF program '%s' not found, skipping\n", probes[i].prog_name);
            continue;
        }

        long offset = find_func_offset(libc_path, probes[i].func_name);
        if (offset < 0) {
            fprintf(stderr, "cannot find offset for %s in %s, skipping\n",
                    probes[i].func_name, libc_path);
            continue;
        }

        struct bpf_link *link = bpf_program__attach_uprobe(prog, probes[i].retprobe,
                                                             -1, libc_path, offset);
        if (libbpf_get_error(link)) {
            fprintf(stderr, "failed to attach %s to %s+%lx: %s\n",
                    probes[i].prog_name, libc_path, offset, strerror(errno));
            continue;
        }

        ctx->links[ctx->link_count++] = link;
        fprintf(stderr, "attached %s -> %s:%s+0x%lx\n",
                probes[i].prog_name, libc_path, probes[i].func_name, offset);
    }

    return ctx->link_count > 0 ? 0 : -1;
}

struct collector_ctx *collector_init(const char *bpf_obj_path,
                                     uint32_t target_pid,
                                     const char *binary_path)
{
    struct collector_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->target_pid = target_pid;
    if (binary_path)
        strncpy(ctx->binary_path, binary_path, sizeof(ctx->binary_path) - 1);

    struct bpf_object *obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "failed to open BPF object: %s\n", bpf_obj_path);
        free(ctx);
        return NULL;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "failed to load BPF object\n");
        bpf_object__close(obj);
        free(ctx);
        return NULL;
    }

    g_bpf_obj = obj;

    struct bpf_map *events_map = bpf_object__find_map_by_name(obj, "events");
    if (!events_map) {
        fprintf(stderr, "failed to find events map\n");
        bpf_object__close(obj);
        free(ctx);
        return NULL;
    }
    ctx->ringbuf_fd = bpf_map__fd(events_map);

    struct bpf_map *stack_map = bpf_object__find_map_by_name(obj, "stack_traces");
    if (stack_map)
        ctx->stack_map_fd = bpf_map__fd(stack_map);

    struct bpf_map *active_map = bpf_object__find_map_by_name(obj, "active_allocs");
    if (active_map)
        ctx->active_map_fd = bpf_map__fd(active_map);

    struct bpf_map *completed_map = bpf_object__find_map_by_name(obj, "completed_allocs");
    if (completed_map)
        ctx->completed_map_fd = bpf_map__fd(completed_map);

    ctx->ringbuf = ring_buffer__new(ctx->ringbuf_fd, handle_event, ctx, NULL);
    if (!ctx->ringbuf) {
        fprintf(stderr, "failed to create ring buffer\n");
        bpf_object__close(obj);
        free(ctx);
        return NULL;
    }

    ctx->running = 0;
    ctx->link_count = 0;
    return ctx;
}

void collector_destroy(struct collector_ctx *ctx)
{
    if (!ctx)
        return;

    for (int i = 0; i < ctx->link_count; i++) {
        bpf_link__destroy(ctx->links[i]);
    }

    if (ctx->ringbuf)
        ring_buffer__free(ctx->ringbuf);

    if (g_bpf_obj) {
        bpf_object__close(g_bpf_obj);
        g_bpf_obj = NULL;
    }

    free(ctx->table.records);
    free(ctx);
}

int collector_start(struct collector_ctx *ctx)
{
    if (!ctx)
        return -EINVAL;

    if (attach_uprobes(ctx, g_bpf_obj) != 0) {
        fprintf(stderr, "failed to attach uprobes\n");
        return -1;
    }

    ctx->running = 1;
    return 0;
}

int collector_stop(struct collector_ctx *ctx)
{
    if (!ctx)
        return -EINVAL;
    ctx->running = 0;
    return 0;
}

int collector_poll(struct collector_ctx *ctx, int timeout_ms)
{
    if (!ctx || !ctx->ringbuf)
        return -EINVAL;
    return ring_buffer__poll(ctx->ringbuf, timeout_ms);
}

void collector_dump_allocs(struct collector_ctx *ctx)
{
    if (!ctx)
        return;

    printf("\n=== Live Allocations ===\n");
    printf("%-18s %-12s %-8s %-8s %-8s %s\n",
           "Address", "Size", "PID", "TID", "Live", "Command");
    printf("-----------------------------------------------------------\n");

    for (size_t i = 0; i < ctx->table.count; i++) {
        struct alloc_record *r = &ctx->table.records[i];
        printf("0x%-16lx %-12lu %-8u %-8u %-8s %s\n",
               r->addr, r->size, r->pid, r->tid,
               r->live ? "yes" : "no", r->comm);
    }
    printf("\nTotal records: %zu, Live: ", ctx->table.count);
    size_t live = 0;
    for (size_t i = 0; i < ctx->table.count; i++)
        live += ctx->table.records[i].live;
    printf("%zu\n", live);
}

struct alloc_record *collector_find_alloc(struct collector_ctx *ctx, uint64_t addr)
{
    if (!ctx)
        return NULL;
    return find_live_alloc(&ctx->table, addr);
}

int collector_resolve_stack(struct collector_ctx *ctx,
                             int64_t stack_id,
                             uint64_t *frames,
                             int max_depth)
{
    if (!ctx || stack_id < 0 || !frames)
        return -EINVAL;

    uint32_t key = (uint32_t)stack_id;
    uint64_t values[MAX_STACK_DEPTH];

    int err = bpf_map_lookup_elem(ctx->stack_map_fd, &key, values);
    if (err) {
        fprintf(stderr, "stack id %lld not found\n", (long long)stack_id);
        return -ENOENT;
    }

    int depth = 0;
    for (int i = 0; i < max_depth && i < MAX_STACK_DEPTH; i++) {
        if (values[i] == 0)
            break;
        frames[depth++] = values[i];
    }
    return depth;
}
