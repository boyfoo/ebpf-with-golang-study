//go:build ignore
#include <common.h>

struct ip_data {
    __u32 sip;     // 来源ip
    __u32 pkt_sz;  // 包大小
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} ip_map SEC(".maps");

SEC("xdp")
int my_pass(struct xdp_md* ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    int pkt_sz = data_end - data;

    struct ethhdr* eth = data;  // 链路层
    if ((void*)eth + sizeof(*eth) > data_end) {
        bpf_printk("Invalid ethernet header\n");
        return XDP_DROP;
    }

    struct iphdr* ip = data + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) > data_end) {
        bpf_printk("Invalid IP header\n");
        return XDP_DROP;
    }

    struct ip_data* ipdata;
    ipdata = bpf_ringbuf_reserve(&ip_map, sizeof(*ipdata), 0);
    if (!ipdata) {
        return 0;
    }
    ipdata->sip = ip->saddr;
    ipdata->pkt_sz = pkt_sz;

    bpf_ringbuf_submit(ipdata, 0);
    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";