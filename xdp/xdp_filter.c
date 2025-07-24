#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

#define VPN_PORT 9000

SEC("xdp")
int xdp_vpn_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_hdr_len = ip->ihl * 4;
    struct udphdr *udp = (void*)ip + ip_hdr_len;
    if ((void*)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest == __constant_htons(VPN_PORT)) {
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
