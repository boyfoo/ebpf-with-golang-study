//go:build ignore
#include <vmlinux.h>

#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#define ETH_ALEN 6
char LICENSE[] SEC("license") = "Dual BSD/GPL";
#define ARP_PROTO 2054
SEC("xdp")
int myarp(struct xdp_md* ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    struct ethhdr* eth = data;  // 链路层
    if ((void*)eth + sizeof(*eth) > data_end) {
        return XDP_DROP;
    }
    if (bpf_htons(eth->h_proto) == ARP_PROTO) {
        bpf_printk("arp packet\n");
    }
    return XDP_PASS;
}