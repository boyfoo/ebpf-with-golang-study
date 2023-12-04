//go:build ignore
#include <vmlinux.h>

#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#include "xdp_helper.h"
#define ETH_ALEN 6
char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct arp_data {
    unsigned char smac[ETH_ALEN];  // 来源mac
    __u32 sip;                     // 来源ip
    __u32 dip;                     // 目标地址
    __be16 op;                     // ARP类型 譬如 1：请求 2：应答
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} arp_map SEC(".maps");

SEC("xdp")
int myarp(struct xdp_md* ctx) {
    struct ethhdr* eth;  // 链路层

    if (get_eth(ctx, &eth) < 0) {
        return XDP_PASS;
    };

    if (!is_arp(eth)) {
        return XDP_PASS;
    };

    struct arphdr* arp;

    if (get_arp(ctx, eth, &arp) < 0) {
        return XDP_PASS;
    };

    // // 不是arp请求跳过
    // if (!is_arp_request(arp)) {
    //     return XDP_PASS;
    // };

    struct iphdr* iph;
    if (get_iphdr(ctx, eth, &iph) < 0) {
        return XDP_PASS;
    };

    struct arp_data* data = NULL;
    data = bpf_ringbuf_reserve(&arp_map, sizeof(*data), 0);
    if (!data) {
        return XDP_PASS;
    }

    // ip层直接获取源ip
    // data->sip = bpf_ntohl(iph->saddr);

    // 解析arp包获取源ip
    data->sip = get_arp_sourceip(ctx, arp);
    data->dip = get_arp_targetip(ctx, arp);
    data->op = bpf_htons(arp->ar_op);

    bpf_probe_read_kernel(data->smac, ETH_ALEN, eth->h_source);
    bpf_ringbuf_submit(data, 0);
    return XDP_PASS;
}
