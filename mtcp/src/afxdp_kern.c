/*
 * AF_XDP kernel-side BPF program for mTCP.
 *
 * Built with vmlinux.h (CO-RE / BTF-based). Generate vmlinux.h once via:
 *     bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
 *
 * Compatibility contract with afxdp_module.c:
 *   - Map MUST be named "xsks_map" so that
 *         bpf_object__find_map_by_name(prog_obj, "xsks_map")
 *     in afxdp_module.c::afxdp_load_module() resolves correctly.
 *   - The XDP program MUST be in section "xdp" so libxdp's
 *     xdp_program__create() picks it up as the default program.
 *
 * Behavior:
 *   - ARP frames -> XDP_PASS (kernel handles ARP, otherwise the box
 *     can't talk to its gateway).
 *   - IPv4 + TCP + (src or dst port 22) -> XDP_PASS (keeps SSH alive
 *     on remote test machines like CloudLab nodes).
 *   - Everything else with an AF_XDP socket bound for the matching
 *     RX queue -> bpf_redirect_map() into that socket.
 *   - If no socket is bound for the queue (or the redirect fails for
 *     any reason), the kernel takes the packet via XDP_PASS — that's
 *     the third-arg flag to bpf_redirect_map below.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP   0x0800
#define ETH_P_ARP  0x0806

struct bpf_map_def SEC("maps") xsks_map = {
    .type = BPF_MAP_TYPE_XSKMAP,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 64,
};

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    /* 1. Ethernet boundary check. */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* 2. Always let ARP through to the kernel. */
    if (eth->h_proto == bpf_htons(ETH_P_ARP))
        return XDP_PASS;

    /* 3. For IPv4+TCP, keep SSH (port 22, either direction) on the
     *    kernel stack so remote management connections survive. */
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        if (ip->protocol == IPPROTO_TCP) {
            int ip_hdr_len = ip->ihl * 4;
            struct tcphdr *tcp = (void *)ip + ip_hdr_len;
            if ((void *)(tcp + 1) > data_end)
                return XDP_PASS;

            if (tcp->dest == bpf_htons(22) ||
                tcp->source == bpf_htons(22))
                return XDP_PASS;
        }
    }

    /* 4. Redirect everything else to the AF_XDP socket bound for this
     *    RX queue. If the slot isn't populated, fall back to XDP_PASS
     *    (third arg to bpf_redirect_map) so the kernel handles it
     *    instead of the packet being dropped (XDP_ABORTED). */
    __u32 index = ctx->rx_queue_index;
    if (bpf_map_lookup_elem(&xsks_map, &index))
        return bpf_redirect_map(&xsks_map, index, XDP_PASS);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
