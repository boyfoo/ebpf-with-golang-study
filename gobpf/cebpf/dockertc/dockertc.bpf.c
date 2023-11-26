//go:build ignore
#include <vmlinux.h>

#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("classifier")
int mytc(struct __sk_buff* skb) {
    bpf_printk("zxzx");
    return 0;
}