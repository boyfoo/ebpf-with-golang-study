//go:build ignore
#include <vmlinux.h>

#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct tc_data {
    __u32 sip;  // 来源
    __u32 dip;  // 目标
    __be16 sport;
    __be16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} tc_map SEC(".maps");

static inline int ip_hdr(struct __sk_buff* skb, struct iphdr* iph) {
    int offset = sizeof(struct ethhdr);
    return bpf_skb_load_bytes(skb, offset, iph, sizeof(*iph));
}

static inline int tcp_hdr(struct __sk_buff* skb, struct iphdr* iph, struct tcphdr* tcph) {
    int offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (iph->protocol != IPPROTO_TCP) {
        return -1;
    }
    return bpf_skb_load_bytes(skb, offset, tcph, sizeof(*tcph));
}

SEC("classifier")
int mytc(struct __sk_buff* skb) {
    struct iphdr iph;

    if (ip_hdr(skb, &iph) < 0) {
        return 0;
    }
    struct tcphdr tcph;
    if (tcp_hdr(skb, &iph, &tcph) < 0) {
        return 0;
    }

    struct tc_data* data = NULL;
    data = bpf_ringbuf_reserve(&tc_map, sizeof(*data), 0);
    if (!data) {
        return 0;
    }
    data->sip = bpf_ntohl(iph.saddr);
    data->dip = bpf_ntohl(iph.daddr);
    data->sport = bpf_ntohs(tcph.source);
    data->dport = bpf_ntohs(tcph.dest);
    bpf_ringbuf_submit(data, 0);
    return 0;
}