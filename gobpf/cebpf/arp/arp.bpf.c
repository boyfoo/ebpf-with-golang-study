//go:build ignore
#include <vmlinux.h>

#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#define ETH_ALEN 6
char LICENSE[] SEC("license") = "Dual BSD/GPL";
#define ARP_PROTO 2054

struct arp_data {
    unsigned char smac[ETH_ALEN];  // 来源mac
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} arp_map SEC(".maps");

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
        // 不是arp请求跳过
        if (bpf_htons(arp->ar_op) != 1) {
            return XDP_PASS;
        }
        struct arp_data* data = NULL;
        data = bpf_ringbuf_reserve(&arp_map, sizeof(*data), 0);
        if (!data) {
            return XDP_DROP;
        }
        bpf_probe_read_kernel(data->smac, ETH_ALEN, eth->h_source);
        bpf_ringbuf_submit(data, 0);
    }
    return XDP_PASS;
}
