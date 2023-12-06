//go:build ignore
#include <vmlinux.h>

#include <bpf_helpers.h>
#include <bpf_tracing.h>

struct mem_info {
    u64 size;
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 << 20);
} mem_map SEC(".maps");

SEC("uprobe/runtime.mallocgc")
int uprobe_mallocgc(struct pt_regs* ctx) {
    struct mem_info* mem = NULL;
    mem = bpf_ringbuf_reserve(&mem_map, sizeof(*mem), 0);
    if (!mem) {
        return 0;
    }
    // PT_REGS_PARM1取出第一个参数
    mem->size = (u64)PT_REGS_PARM1(ctx);
    bpf_ringbuf_submit(mem, 0);
    return 0;
}