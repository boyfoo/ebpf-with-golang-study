//go:build ignore
#include <bpf_endian.h>
#include <common.h>
#include <linux/in.h>
#include <linux/tcp.h>

struct ip_data {
    __u32 sip;     // 来源ip
    __u32 dip;     // 目标ip
    __u32 pkt_sz;  // 包大小
    __u32 iii;     // ingress ifindex
    __be16 sport;  // 来源端口
    __be16 dport;  // 目的端口
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} ip_map SEC(".maps");

struct bpf_map_def SEC("maps") allow_ips_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u8),
    .max_entries = 1024,
};

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

    // 不是tcp不处理
    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    struct tcphdr* tcp = data + sizeof(*eth) + sizeof(*ip);
    if ((void*)tcp + sizeof(*tcp) > data_end) {
        bpf_printk("Invalid TCP header\n");
        return XDP_DROP;
    }

    struct ip_data* ipdata;
    ipdata = bpf_ringbuf_reserve(&ip_map, sizeof(*ipdata), 0);
    if (!ipdata) {
        return 0;
    }

    ipdata->sip = bpf_ntohl(ip->saddr);
    ipdata->dip = bpf_ntohl(ip->daddr);
    ipdata->pkt_sz = pkt_sz;
    ipdata->iii = ctx->ingress_ifindex;
    ipdata->sport = bpf_ntohs(tcp->source);  // 网络字节序转成主机字节序号
    ipdata->dport = bpf_ntohs(tcp->dest);

    // 发送当前的tcp访问数据
    bpf_ringbuf_submit(ipdata, 0);

    __u32 sip = bpf_ntohl(ip->saddr);

    // 对应的sip是否在map里
    __u8* allow = bpf_map_lookup_elem(&allow_ips_map, &sip);

    // 为什么等于1 因为用户态设置map的时候值都设置为了1
    if (allow && *allow == 1) {
        return XDP_PASS;
    }

    return XDP_DROP;
}

char __license[] SEC("license") = "GPL";