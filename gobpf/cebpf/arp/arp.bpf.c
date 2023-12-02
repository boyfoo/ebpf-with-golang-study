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
        //          bpf_printk("arp packet\n");
        struct arphdr* arp = (struct arphdr*)((char*)eth + sizeof(struct ethhdr));
        if ((void*)arp + sizeof(*arp) > data_end) {
            return XDP_DROP;
        }
        // 打印类型 到底是请求还是响应
        bpf_printk("arp-op:%d", bpf_htons(arp->ar_op));
    }
    return XDP_PASS;
}
