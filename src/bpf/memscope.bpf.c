#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "memscope_common.h"

#ifndef BPF_F_USER_STACK
#define BPF_F_USER_STACK (1ULL << 8)
#endif
#ifndef BPF_F_FAST_STACK_CMP
#define BPF_F_FAST_STACK_CMP (1ULL << 9)
#endif
#ifndef BPF_F_REUSE_STACKID
#define BPF_F_REUSE_STACKID (1ULL << 10)
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 26);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, MAX_EVENTS);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_EVENTS);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct alloc_info));
} active_allocs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_EVENTS);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct alloc_info));
} completed_allocs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct pending_info));
} pending_mallocs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct pending_info));
} pending_callocs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct pending_info));
} pending_reallocs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct stack_pcs_value));
} pending_stacks_malloc SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct stack_pcs_value));
} pending_stacks_calloc SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct stack_pcs_value));
} pending_stacks_realloc SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct stack_pcs_value));
} tmp_stack_buf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct mem_event));
} tmp_evt_buf SEC(".maps");

static __always_inline void emit_event(void *ctx, struct mem_event *evt)
{
    bpf_ringbuf_output(&events, evt, sizeof(*evt), 0);
}

static __always_inline __s64 get_stack_id(void *ctx)
{
    return bpf_get_stackid(ctx, &stack_traces,
                           BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);
}

SEC("uprobe/libc.so.6:malloc")
int BPF_KPROBE(uprobe_malloc_entry, __u64 size)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 zero = 0;

    struct pending_info pending = {};
    pending.size = size;

    __s32 sid = bpf_get_stackid(ctx, &stack_traces,
                           BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID);

    if (sid < 0) {
        bpf_printk("entry: stackid FAIL ret=%d", sid);
        sid = bpf_get_stackid(ctx, &stack_traces, 0);
        bpf_printk("entry: retry ret=%d", sid);
    }

    pending.stack_id = sid;
    pending._pad = 0;

    bpf_map_update_elem(&pending_mallocs, &tid, &pending, BPF_ANY);

    struct stack_pcs_value *stack_val = bpf_map_lookup_elem(&tmp_stack_buf, &zero);
    if (!stack_val)
        return 0;

    __builtin_memset(stack_val, 0, sizeof(*stack_val));
    int stack_len = bpf_get_stack(ctx, stack_val->pcs, sizeof(stack_val->pcs),
                                  BPF_F_USER_STACK);
    if (stack_len > 0) {
        stack_val->depth = stack_len / sizeof(__u64);
        bpf_map_update_elem(&pending_stacks_malloc, &tid, stack_val, BPF_ANY);
        bpf_printk("entry: tid=%u sid=%d depth=%u", tid, sid, stack_val->depth);
    } else {
        stack_val->depth = 0;
        bpf_map_update_elem(&pending_stacks_malloc, &tid, stack_val, BPF_ANY);
        bpf_printk("entry: tid=%u sid=%d get_stack=%d", tid, sid, stack_len);
    }

    return 0;
}

SEC("uretprobe/libc.so.6:malloc")
int BPF_KRETPROBE(uprobe_malloc_return, void *ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 addr = (__u64)ret;
    __u32 zero = 0;

    if (!addr)
        return 0;

    struct pending_info *pending = bpf_map_lookup_elem(&pending_mallocs, &tid);
    if (!pending)
        return 0;

    __u64 size_val = pending->size;
    __s32 entry_stack_id = pending->stack_id;
    bpf_map_delete_elem(&pending_mallocs, &tid);

    struct alloc_info info = {};
    info.size = size_val;
    info.stack_id = entry_stack_id;
    info.timestamp = bpf_ktime_get_ns();
    info.pid = pid_tgid >> 32;
    info.tid = tid;

    bpf_map_update_elem(&active_allocs, &addr, &info, BPF_ANY);

    struct mem_event *evt = bpf_map_lookup_elem(&tmp_evt_buf, &zero);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->type = EVENT_MALLOC_RETURN;
    evt->pid = info.pid;
    evt->tid = tid;
    evt->timestamp = info.timestamp;
    evt->stack_id = entry_stack_id;
    evt->malloc_ret.addr = addr;
    evt->malloc_ret.size = size_val;

    struct stack_pcs_value *stack_val = bpf_map_lookup_elem(&pending_stacks_malloc, &tid);
    if (stack_val && stack_val->depth > 0) {
        evt->stack_depth = stack_val->depth;
        if (evt->stack_depth > MAX_STACK_DEPTH)
            evt->stack_depth = MAX_STACK_DEPTH;
        for (__u32 i = 0; i < evt->stack_depth && i < MAX_STACK_DEPTH; i++) {
            evt->malloc_ret.pcs[i] = stack_val->pcs[i];
        }
        bpf_printk("ret: tid=%u sid=%d depth=%u", tid, entry_stack_id, evt->stack_depth);
    } else {
        evt->stack_depth = 0;
        bpf_printk("ret: tid=%u sid=%d NO PCs", tid, entry_stack_id);
    }
    bpf_map_delete_elem(&pending_stacks_malloc, &tid);

    emit_event(ctx, evt);
    return 0;
}

SEC("uprobe/libc.so.6:free")
int BPF_KPROBE(uprobe_free, void *ptr)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 addr = (__u64)ptr;
    __u32 zero = 0;

    if (!addr)
        return 0;

    struct alloc_info *info = bpf_map_lookup_elem(&active_allocs, &addr);
    if (info) {
        bpf_map_update_elem(&completed_allocs, &addr, info, BPF_ANY);
        bpf_map_delete_elem(&active_allocs, &addr);
    }

    struct mem_event *evt = bpf_map_lookup_elem(&tmp_evt_buf, &zero);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->type = EVENT_FREE;
    evt->pid = pid_tgid >> 32;
    evt->tid = (__u32)pid_tgid;
    evt->timestamp = bpf_ktime_get_ns();
    evt->free_evt.addr = addr;
    evt->stack_id = get_stack_id(ctx);

    emit_event(ctx, evt);
    return 0;
}

SEC("uprobe/libc.so.6:calloc")
int BPF_KPROBE(uprobe_calloc_entry, __u64 nmemb, __u64 size)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 zero = 0;

    struct pending_info pending = {};
    pending.size = nmemb * size;

    __s32 sid = bpf_get_stackid(ctx, &stack_traces,
                           BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID);
    if (sid < 0) {
        sid = bpf_get_stackid(ctx, &stack_traces, 0);
    }
    pending.stack_id = sid;
    pending._pad = 0;

    bpf_map_update_elem(&pending_callocs, &tid, &pending, BPF_ANY);

    struct stack_pcs_value *stack_val = bpf_map_lookup_elem(&tmp_stack_buf, &zero);
    if (!stack_val)
        return 0;

    __builtin_memset(stack_val, 0, sizeof(*stack_val));
    int stack_len = bpf_get_stack(ctx, stack_val->pcs, sizeof(stack_val->pcs),
                                  BPF_F_USER_STACK);
    if (stack_len > 0) {
        stack_val->depth = stack_len / sizeof(__u64);
        bpf_map_update_elem(&pending_stacks_calloc, &tid, stack_val, BPF_ANY);
    } else {
        stack_val->depth = 0;
        bpf_map_update_elem(&pending_stacks_calloc, &tid, stack_val, BPF_ANY);
    }

    return 0;
}

SEC("uretprobe/libc.so.6:calloc")
int BPF_KRETPROBE(uprobe_calloc_return, void *ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 addr = (__u64)ret;
    __u32 zero = 0;

    if (!addr)
        return 0;

    struct pending_info *pending = bpf_map_lookup_elem(&pending_callocs, &tid);
    if (!pending)
        return 0;

    __u64 size_val = pending->size;
    __s32 entry_stack_id = pending->stack_id;
    bpf_map_delete_elem(&pending_callocs, &tid);

    struct alloc_info info = {};
    info.size = size_val;
    info.stack_id = entry_stack_id;
    info.timestamp = bpf_ktime_get_ns();
    info.pid = pid_tgid >> 32;
    info.tid = tid;

    bpf_map_update_elem(&active_allocs, &addr, &info, BPF_ANY);

    struct mem_event *evt = bpf_map_lookup_elem(&tmp_evt_buf, &zero);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->type = EVENT_CALLOC_RETURN;
    evt->pid = info.pid;
    evt->tid = tid;
    evt->timestamp = info.timestamp;
    evt->stack_id = entry_stack_id;
    evt->calloc_ret.addr = addr;
    evt->calloc_ret.size = size_val;

    struct stack_pcs_value *stack_val = bpf_map_lookup_elem(&pending_stacks_calloc, &tid);
    if (stack_val && stack_val->depth > 0) {
        evt->stack_depth = stack_val->depth;
        if (evt->stack_depth > MAX_STACK_DEPTH)
            evt->stack_depth = MAX_STACK_DEPTH;
        for (__u32 i = 0; i < evt->stack_depth && i < MAX_STACK_DEPTH; i++) {
            evt->calloc_ret.pcs[i] = stack_val->pcs[i];
        }
    } else {
        evt->stack_depth = 0;
    }
    bpf_map_delete_elem(&pending_stacks_calloc, &tid);

    emit_event(ctx, evt);
    return 0;
}

SEC("uprobe/libc.so.6:realloc")
int BPF_KPROBE(uprobe_realloc_entry, void *ptr, __u64 size)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 zero = 0;

    struct pending_info pending = {};
    pending.size = size;

    __s32 sid = bpf_get_stackid(ctx, &stack_traces,
                           BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID);
    if (sid < 0) {
        sid = bpf_get_stackid(ctx, &stack_traces, 0);
    }
    pending.stack_id = sid;
    pending._pad = 0;

    bpf_map_update_elem(&pending_reallocs, &tid, &pending, BPF_ANY);

    struct stack_pcs_value *stack_val = bpf_map_lookup_elem(&tmp_stack_buf, &zero);
    if (!stack_val)
        return 0;

    __builtin_memset(stack_val, 0, sizeof(*stack_val));
    int stack_len = bpf_get_stack(ctx, stack_val->pcs, sizeof(stack_val->pcs),
                                  BPF_F_USER_STACK);
    if (stack_len > 0) {
        stack_val->depth = stack_len / sizeof(__u64);
        bpf_map_update_elem(&pending_stacks_realloc, &tid, stack_val, BPF_ANY);
    } else {
        stack_val->depth = 0;
        bpf_map_update_elem(&pending_stacks_realloc, &tid, stack_val, BPF_ANY);
    }

    struct mem_event *evt = bpf_map_lookup_elem(&tmp_evt_buf, &zero);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->type = EVENT_REALLOC_ENTRY;
    evt->pid = pid_tgid >> 32;
    evt->tid = tid;
    evt->timestamp = bpf_ktime_get_ns();
    evt->realloc_entry.old_addr = (__u64)ptr;
    evt->realloc_entry.new_size = size;

    emit_event(ctx, evt);
    return 0;
}

SEC("uretprobe/libc.so.6:realloc")
int BPF_KRETPROBE(uprobe_realloc_return, void *ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 addr = (__u64)ret;
    __u32 zero = 0;

    if (!addr)
        return 0;

    struct pending_info *pending = bpf_map_lookup_elem(&pending_reallocs, &tid);
    if (!pending)
        return 0;

    __u64 size_val = pending->size;
    __s32 entry_stack_id = pending->stack_id;
    bpf_map_delete_elem(&pending_reallocs, &tid);

    struct alloc_info info = {};
    info.size = size_val;
    info.stack_id = entry_stack_id;
    info.timestamp = bpf_ktime_get_ns();
    info.pid = pid_tgid >> 32;
    info.tid = tid;

    bpf_map_update_elem(&active_allocs, &addr, &info, BPF_ANY);

    struct mem_event *evt = bpf_map_lookup_elem(&tmp_evt_buf, &zero);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->type = EVENT_REALLOC_RETURN;
    evt->pid = info.pid;
    evt->tid = tid;
    evt->timestamp = info.timestamp;
    evt->stack_id = entry_stack_id;
    evt->realloc_ret.addr = addr;
    evt->realloc_ret.size = size_val;
    evt->realloc_ret.old_addr = 0;

    struct stack_pcs_value *stack_val = bpf_map_lookup_elem(&pending_stacks_realloc, &tid);
    if (stack_val && stack_val->depth > 0) {
        evt->stack_depth = stack_val->depth;
        if (evt->stack_depth > MAX_STACK_DEPTH)
            evt->stack_depth = MAX_STACK_DEPTH;
        for (__u32 i = 0; i < evt->stack_depth && i < MAX_STACK_DEPTH; i++) {
            evt->realloc_ret.pcs[i] = stack_val->pcs[i];
        }
    } else {
        evt->stack_depth = 0;
    }
    bpf_map_delete_elem(&pending_stacks_realloc, &tid);

    emit_event(ctx, evt);
    return 0;
}

SEC("uprobe/libc.so.6:mmap")
int BPF_KPROBE(uprobe_mmap_entry, void *addr, __u64 size, int prot, int flags)
{
    __u32 zero = 0;
    struct mem_event *evt = bpf_map_lookup_elem(&tmp_evt_buf, &zero);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->type = EVENT_MMAP;
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->tid = (__u32)bpf_get_current_pid_tgid();
    evt->timestamp = bpf_ktime_get_ns();
    evt->mmap_evt.addr = (__u64)addr;
    evt->mmap_evt.size = size;
    evt->mmap_evt.prot = prot;
    evt->mmap_evt.flags = flags;

    emit_event(ctx, evt);
    return 0;
}

SEC("uprobe/libc.so.6:munmap")
int BPF_KPROBE(uprobe_munmap_entry, void *addr, __u64 size)
{
    __u32 zero = 0;
    struct mem_event *evt = bpf_map_lookup_elem(&tmp_evt_buf, &zero);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->type = EVENT_MUNMAP;
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->tid = (__u32)bpf_get_current_pid_tgid();
    evt->timestamp = bpf_ktime_get_ns();
    evt->munmap_evt.addr = (__u64)addr;
    evt->munmap_evt.size = size;

    emit_event(ctx, evt);
    return 0;
}

SEC("perf_event")
int on_stack_sample(struct bpf_perf_event_data *ctx)
{
    __u32 zero = 0;
    struct mem_event *evt = bpf_map_lookup_elem(&tmp_evt_buf, &zero);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->type = EVENT_STACK_SAMPLE;
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->tid = (__u32)bpf_get_current_pid_tgid();
    evt->timestamp = bpf_ktime_get_ns();
    evt->stack_id = get_stack_id(ctx);

    emit_event(ctx, evt);
    return 0;
}
