#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP   0x0800
#define ETH_P_ARP  0x0806

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // 1. Boundary Check
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 2. Safety: Always let ARP through to the Kernel
    if (eth->h_proto == bpf_htons(ETH_P_ARP))
        return XDP_PASS;

    // 3. Safety: Check for IP and SSH
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        if (ip->protocol == IPPROTO_TCP) {
            int ip_hdr_len = ip->ihl * 4;
            struct tcphdr *tcp = (void *)ip + ip_hdr_len;
            if ((void *)(tcp + 1) > data_end)
                return XDP_PASS;

            // IF PORT 22, PASS TO KERNEL (Keep SSH alive)
            if (tcp->dest == bpf_htons(22) || tcp->source == bpf_htons(22))
                return XDP_PASS;
        }
    }

    // 4. Redirect everything else to AF_XDP
    __u32 index = ctx->rx_queue_index;
    if (bpf_map_lookup_elem(&xsks_map, &index)) {
        return bpf_redirect_map(&xsks_map, index, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";