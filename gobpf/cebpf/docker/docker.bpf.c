//go:build ignore
#include <vmlinux.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";
#define HTTP_PAYLOAD_MAX 1024
struct ip_data {
    __u32 sip;     // 来源IP
    __u32 dip;     // 目标IP
    __be16 sport;  // 来源端口
    __be16 dport;  // 目的端口
    char payload[HTTP_PAYLOAD_MAX];
};
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} ip_map SEC(".maps");

SEC("xdp")
int mydocker(struct xdp_md* ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    struct ethhdr* eth = data;  // 链路层
    if ((void*)eth + sizeof(*eth) > data_end) {
        return XDP_DROP;
    }
    struct iphdr* ip = data + sizeof(*eth);  // 得到了 ip层
    if ((void*)ip + sizeof(*ip) > data_end) {
        return XDP_DROP;
    }
    if (ip->protocol != 6) {  // 如果不是TCP 就不处理了。累死了
        return XDP_PASS;
    }
    struct tcphdr* tcp = (void*)ip + sizeof(*ip);  // 得到tcp层
    if ((void*)tcp + sizeof(*tcp) > data_end) {
        return XDP_DROP;
    }
    unsigned int tcp_data_len = bpf_ntohs(ip->tot_len) - (ip->ihl * 4) - (tcp->doff * 4);
    // 表示是tcp握手的请求，直接不要了
    // 这是有个粗糙的过滤方法，可以使用更准确的判断ack的方法
    if (tcp_data_len == 0) {
        return XDP_PASS;
    }
    char* payload = (char*)(data + sizeof(*eth) + ip->ihl * 4 + tcp->doff * 4);
    if (tcp_data_len > HTTP_PAYLOAD_MAX) {
        tcp_data_len = HTTP_PAYLOAD_MAX;
    }

    // 开始构建业务数据和ringbuf初始化
    struct ip_data* ipdata = NULL;
    ipdata = bpf_ringbuf_reserve(&ip_map, sizeof(*ipdata), 0);
    if (!ipdata) {
        return XDP_PASS;
    }
    bpf_probe_read_kernel(ipdata->payload, tcp_data_len, payload);
    ipdata->sip = bpf_ntohl(ip->saddr);  // 网络字节序 转换成 主机字节序  32位
    ipdata->dip = bpf_ntohl(ip->daddr);
    ipdata->sport = bpf_ntohs(tcp->source);  // 16位
    ipdata->dport = bpf_ntohs(tcp->dest);

    bpf_ringbuf_submit(ipdata, 0);
    return XDP_PASS;
}