#ifndef COLLECTOR_H
#define COLLECTOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

struct bpf_link;

#define MAX_STACK_DEPTH 64
#define MAX_COMM_LEN 64
#define MAX_EVENTS 16384
#define MAX_SYM_LEN 256
#define MAX_STACK_FRAMES 128
#define MAX_ATTACH_POINTS 16

#define ALLOC_HASH_BITS 16
#define ALLOC_HASH_SIZE (1 << ALLOC_HASH_BITS)
#define ALLOC_HASH_MASK (ALLOC_HASH_SIZE - 1)

enum event_type {
    EVENT_MALLOC_ENTRY  = 1,
    EVENT_MALLOC_RETURN = 2,
    EVENT_FREE          = 3,
    EVENT_MMAP          = 4,
    EVENT_MUNMAP        = 5,
    EVENT_STACK_SAMPLE  = 6,
};

struct mem_event {
    uint32_t type;
    uint32_t pid;
    uint32_t tid;
    uint64_t timestamp;
    int64_t  stack_id;
    union {
        struct { uint64_t size; } malloc_entry;
        struct { uint64_t addr; uint64_t size; } malloc_ret;
        struct { uint64_t addr; } free_evt;
        struct { uint64_t addr; uint64_t size; int32_t prot; int32_t flags; } mmap_evt;
        struct { uint64_t addr; uint64_t size; } munmap_evt;
        struct { uint64_t regs[6]; } stack_sample;
    };
};

struct alloc_record {
    uint64_t addr;
    uint64_t size;
    int64_t  stack_id;
    uint64_t timestamp_alloc;
    uint64_t timestamp_free;
    uint32_t pid;
    uint32_t tid;
    int      live;
    uint64_t *stack_frames;
    int      stack_depth;
    char     comm[MAX_COMM_LEN];
    int      hash_next;
};

struct alloc_table {
    struct alloc_record *records;
    size_t              count;
    size_t              capacity;
    int                *hash_buckets;
    int                *hash_next;
    int                 hash_size;
};

struct collector_ctx {
    int                  ringbuf_fd;
    int                  stack_map_fd;
    int                  active_map_fd;
    int                  completed_map_fd;
    struct alloc_table   table;
    struct ring_buffer  *ringbuf;
    int                  running;
    uint32_t             target_pid;
    char                 binary_path[512];
    struct bpf_link     *links[MAX_ATTACH_POINTS];
    int                  link_count;
};

struct collector_ctx *collector_init(const char *bpf_obj_path,
                                     uint32_t target_pid,
                                     const char *binary_path);
void collector_destroy(struct collector_ctx *ctx);
int  collector_start(struct collector_ctx *ctx);
int  collector_stop(struct collector_ctx *ctx);
int  collector_poll(struct collector_ctx *ctx, int timeout_ms);
void collector_dump_allocs(struct collector_ctx *ctx);
struct alloc_record *collector_find_alloc(struct collector_ctx *ctx, uint64_t addr);
int  collector_resolve_stack(struct collector_ctx *ctx,
                             int64_t stack_id,
                             uint64_t *frames,
                             int max_depth);

#endif
