#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "memscope_common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
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
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} pending_mallocs SEC(".maps");

static __always_inline void emit_event(void *ctx, struct mem_event *evt)
{
    bpf_ringbuf_output(&events, evt, sizeof(*evt), 0);
}

static __always_inline __s64 get_stack_id(void *ctx)
{
    return bpf_get_stackid(ctx, &stack_traces, BPF_F_FAST_STACK_CMP);
}

SEC("uprobe/libc.so.6:malloc")
int BPF_KPROBE(uprobe_malloc_entry, __u64 size)
{
    struct mem_event evt = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    evt.type = EVENT_MALLOC_ENTRY;
    evt.pid = pid_tgid >> 32;
    evt.tid = tid;
    evt.timestamp = bpf_ktime_get_ns();
    evt.stack_id = get_stack_id(ctx);
    evt.malloc_entry.size = size;

    bpf_map_update_elem(&pending_mallocs, &tid, &size, BPF_ANY);

    emit_event(ctx, &evt);
    return 0;
}

SEC("uretprobe/libc.so.6:malloc")
int BPF_KRETPROBE(uprobe_malloc_return, void *ret)
{
    struct mem_event evt = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 addr = (__u64)ret;
    __u64 *size_ptr;
    __u64 size_val;

    if (!addr)
        return 0;

    size_ptr = bpf_map_lookup_elem(&pending_mallocs, &tid);
    if (!size_ptr)
        return 0;

    size_val = *size_ptr;
    bpf_map_delete_elem(&pending_mallocs, &tid);

    struct alloc_info info = {};
    info.size = size_val;
    info.stack_id = 0;
    info.timestamp = bpf_ktime_get_ns();
    info.pid = pid_tgid >> 32;
    info.tid = tid;

    bpf_map_update_elem(&active_allocs, &addr, &info, BPF_ANY);

    evt.type = EVENT_MALLOC_RETURN;
    evt.pid = info.pid;
    evt.tid = tid;
    evt.timestamp = info.timestamp;
    evt.stack_id = 0;
    evt.malloc_ret.addr = addr;
    evt.malloc_ret.size = size_val;

    emit_event(ctx, &evt);
    return 0;
}

SEC("uprobe/libc.so.6:free")
int BPF_KPROBE(uprobe_free, void *ptr)
{
    struct mem_event evt = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 addr = (__u64)ptr;

    if (!addr)
        return 0;

    struct alloc_info *info = bpf_map_lookup_elem(&active_allocs, &addr);
    if (info) {
        bpf_map_update_elem(&completed_allocs, &addr, info, BPF_ANY);
        bpf_map_delete_elem(&active_allocs, &addr);
    }

    evt.type = EVENT_FREE;
    evt.pid = pid_tgid >> 32;
    evt.tid = (__u32)pid_tgid;
    evt.timestamp = bpf_ktime_get_ns();
    evt.stack_id = get_stack_id(ctx);
    evt.free_evt.addr = addr;

    emit_event(ctx, &evt);
    return 0;
}

SEC("uprobe/libc.so.6:mmap")
int BPF_KPROBE(uprobe_mmap_entry, void *addr, __u64 size, int prot, int flags)
{
    struct mem_event evt = {};

    evt.type = EVENT_MMAP;
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.tid = (__u32)bpf_get_current_pid_tgid();
    evt.timestamp = bpf_ktime_get_ns();
    evt.stack_id = get_stack_id(ctx);
    evt.mmap_evt.addr = (__u64)addr;
    evt.mmap_evt.size = size;
    evt.mmap_evt.prot = prot;
    evt.mmap_evt.flags = flags;

    emit_event(ctx, &evt);
    return 0;
}

SEC("uprobe/libc.so.6:munmap")
int BPF_KPROBE(uprobe_munmap_entry, void *addr, __u64 size)
{
    struct mem_event evt = {};

    evt.type = EVENT_MUNMAP;
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.tid = (__u32)bpf_get_current_pid_tgid();
    evt.timestamp = bpf_ktime_get_ns();
    evt.stack_id = get_stack_id(ctx);
    evt.munmap_evt.addr = (__u64)addr;
    evt.munmap_evt.size = size;

    emit_event(ctx, &evt);
    return 0;
}

SEC("perf_event")
int on_stack_sample(struct bpf_perf_event_data *ctx)
{
    struct mem_event evt = {};

    evt.type = EVENT_STACK_SAMPLE;
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.tid = (__u32)bpf_get_current_pid_tgid();
    evt.timestamp = bpf_ktime_get_ns();
    evt.stack_id = get_stack_id(ctx);

    emit_event(ctx, &evt);
    return 0;
}
