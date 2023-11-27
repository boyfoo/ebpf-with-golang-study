//go:build ignore
#include <vmlinux.h>

#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct tc_data {
    __u32 sip;  // 来源
    __u32 dip;  // 目标
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} tc_map SEC(".maps");

static inline int iph_dr(struct __sk_buff* skb, struct iphdr* iph) {
    int offset = sizeof(struct ethhdr);
    return bpf_skb_load_bytes(skb, offset, iph, sizeof(*iph));
}

SEC("classifier")
int mytc(struct __sk_buff* skb) {
    struct iphdr iph;

    if (iph_dr(skb, &iph) < 0) {
        return 0;
    }

    bpf_printk("proto: %d\n", iph.protocol);

    if (iph.protocol != IPPROTO_TCP) {
        return 0;
    }
    struct tc_data* data = NULL;
    data = bpf_ringbuf_reserve(&tc_map, sizeof(*data), 0);
    if (!data) {
        return 0;
    }
    data->sip = bpf_ntohl(iph.saddr);
    data->dip = bpf_ntohl(iph.daddr);
    bpf_ringbuf_submit(data, 0);
    return 0;
}