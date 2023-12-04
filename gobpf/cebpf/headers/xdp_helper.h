
static inline int get_eth(struct xdp_md* ctx,struct ethhdr **ethhdr) {
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) > data_end) {
       return -1;
    }
    *ethhdr = eth;
    return 0;
}
//判断是否是否arp协议
static inline bool is_arp(struct ethhdr *eth){
     return bpf_htons(eth->h_proto) == 2054;
}
static inline int get_arp(struct xdp_md* ctx,struct ethhdr *eth,struct arphdr **arp) {
    void *data_end = (void*)(long)ctx->data_end;
    struct arphdr *arp_p = (struct arphdr *)((char *)eth + sizeof(struct ethhdr));
    if ((void*)arp_p + sizeof(*arp_p) > data_end) {
       return -1;
    }
    *arp = arp_p;
    return 0;
}
static inline bool is_arp_request(struct arphdr *arp){

    return bpf_htons(arp->ar_op) == 1;
}
static inline bool is_arp_reply(struct arphdr *arp){
    return bpf_htons(arp->ar_op) == 2;
}
// 下面是获取IP数据包
static inline int get_iphdr(struct xdp_md* ctx,struct ethhdr *eth,struct iphdr **iph) {
     void *data = (void*)(long)ctx->data;
     void *data_end = (void*)(long)ctx->data_end;
     struct iphdr *ip_p = data + sizeof(*eth); // 得到了 ip层
     if ((void*)ip_p + sizeof(*ip_p) > data_end) {
         return -1;
     }
     *iph = ip_p;
     return 0;
}
