#ifndef __MEMSCOPE_BPF_H
#define __MEMSCOPE_BPF_H

#define MAX_STACK_DEPTH 64
#define MAX_COMM_LEN 64
#define MAX_EVENTS 16384

#ifndef BPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_HASH 1
#endif

#ifndef BPF_MAP_TYPE_STACK_TRACE
#define BPF_MAP_TYPE_STACK_TRACE 7
#endif

#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif

#ifndef BPF_MAP_TYPE_PERCPU_ARRAY
#define BPF_MAP_TYPE_PERCPU_ARRAY 12
#endif

#ifndef BPF_ANY
#define BPF_ANY 0
#endif

#ifndef BPF_F_USER_STACK
#define BPF_F_USER_STACK     (1ULL << 8)
#endif

#ifndef BPF_F_FAST_STACK_CMP
#define BPF_F_FAST_STACK_CMP (1ULL << 9)
#endif

#ifndef BPF_F_REUSE_STACKID
#define BPF_F_REUSE_STACKID  (1ULL << 10)
#endif

enum event_type {
    EVENT_MALLOC_ENTRY  = 1,
    EVENT_MALLOC_RETURN = 2,
    EVENT_FREE          = 3,
    EVENT_MMAP          = 4,
    EVENT_MUNMAP        = 5,
    EVENT_STACK_SAMPLE  = 6,
};

struct mem_event {
    __u32 type;
    __u32 pid;
    __u32 tid;
    __u64 timestamp;
    __s64 stack_id;
    __u32 stack_depth;
    __u32 _reserved;
    union {
        struct {
            __u64 size;
        } malloc_entry;
        struct {
            __u64 addr;
            __u64 size;
            __u64 pcs[MAX_STACK_DEPTH];
        } malloc_ret;
        struct {
            __u64 addr;
        } free_evt;
        struct {
            __u64 addr;
            __u64 size;
            __s32 prot;
            __s32 flags;
        } mmap_evt;
        struct {
            __u64 addr;
            __u64 size;
        } munmap_evt;
        struct {
            __u64 regs[6];
        } stack_sample;
    };
};

struct alloc_info {
    __u64 size;
    __s64 stack_id;
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
};

struct stack_pcs_value {
    __u32 depth;
    __u32 _pad;
    __u64 pcs[MAX_STACK_DEPTH];
};

struct pending_info {
    __u64 size;
    __s32 stack_id;
    __u32 _pad;
} __attribute__((packed, aligned(8)));

#endif
