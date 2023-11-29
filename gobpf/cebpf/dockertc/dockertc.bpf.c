//go:build ignore
#include <vmlinux.h>

#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include "bpf_legacy.h"
char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ETH_HLEN 14  // 以太网头部，写死 14
#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define TOS_OFF (ETH_HLEN + offsetof(struct iphdr, tos))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define TCP_SPORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source))
#define TCP_DPORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))

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

// 获取ip相关数据
static inline int ip_hdr(struct __sk_buff* skb, struct iphdr* iph) {
    int offset = sizeof(struct ethhdr);
    return bpf_skb_load_bytes(skb, offset, iph, sizeof(*iph));
}
// 获取tcp相关数据
static inline int tcp_hdr(struct __sk_buff* skb, struct iphdr* iph, struct tcphdr* tcph) {
    int offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (iph->protocol != IPPROTO_TCP) {
        return -1;
    }
    return bpf_skb_load_bytes(skb, offset, tcph, sizeof(*tcph));
}

// 设置新的去向端口
static inline void set_tcp_dest_port(struct __sk_buff* skb, __u16 new_port_host) {
    __u16 old_port = bpf_htons(load_half(skb, TCP_DPORT_OFF));
    __u16 new_port = bpf_htons(new_port_host);
    bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_port, new_port, sizeof(new_port));
    bpf_skb_store_bytes(skb, TCP_DPORT_OFF, &new_port, sizeof(new_port), 0);
}

// 设置来源端口
static inline void set_tcp_src_port(struct __sk_buff* skb, __u16 new_port_host) {
    __u16 old_port = bpf_htons(load_half(skb, TCP_DPORT_OFF));
    __u16 new_port = bpf_htons(new_port_host);
    bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_port, new_port, sizeof(new_port));
    bpf_skb_store_bytes(skb, TCP_SPORT_OFF, &new_port, sizeof(new_port), 0);
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

    __u16 source_port = bpf_ntohs(tcph.source);  // 来源端口
    // 当前的端口
    __u16 watch_port = bpf_ntohs(tcph.dest);
    __u32 watch_ip = bpf_htonl(0xAC120003);  // 172.18.0.3 docker的ip，此处应该改成自己要测试的docker ip
    // A -> B 把访问172.18.0.3 8080的网络修改转发到80端口
    if (iph.daddr == watch_ip && watch_port == 8080) {
        set_tcp_dest_port(skb, 80);
        // 因为被改掉了端口 所以在重新执行赋值一下
        tcp_hdr(skb, &iph, &tcph);
    }

    // B -> A 要把返回的时候改回来
    if (iph.saddr == watch_ip && source_port == 80) {
        set_tcp_src_port(skb, 8080);
        tcp_hdr(skb, &iph, &tcph);
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