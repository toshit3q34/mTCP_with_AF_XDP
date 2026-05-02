// AF_XDP kernel-side BPF program for mTCP.
// Built with vmlinux.h (CO-RE / BTF-based). Generate vmlinux.h once via:
// bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

// The eBPF Map xsks_map maps the queue index of the received packet
// to the corresponding AF_XDP socket fd. This makes sure that multiple cores
// can share the same interface through different RX queues.
// For example :
// Packet received on RX queue 0 => xsks_map[0] = AF_XDP socket fd used by core 0
// Packet received on RX queue 1 => xsks_map[1] = AF_XDP socket fd used by core 1
// The only limitation is that multiple interfaces can have same queue number
// overwriting the map index entries.
// Uses XDP_PASS for SSH packets to prevent interference with CloudLab (testing website).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define BPF_PRINTK(fmt, ...)                            \
({                                                      \
    char f[] = fmt;                                     \
    bpf_trace_printk(f, sizeof(f), ##__VA_ARGS__);      \
})

#define ETH_P_IP   0x0800
#define ETH_P_ARP  0x0806

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 256);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // Ethernet boundary check.
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Specifically catching SSH to avoid any connection loss
	// from the remote server.
	// IPv4 + TCP + (src or dst port 22) -> XDP_PASS (keeps SSH alive
	// on remote test machines like CloudLab nodes).
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

    // Redirect everything to their corresponding slot
	// xsk_map[receive_queue_index] => xsk_socket_fd
    __u32 index = ctx->rx_queue_index;
    if (bpf_map_lookup_elem(&xsks_map, &index)){
    	BPF_PRINTK("Interface index: %d\n", index);
        return bpf_redirect_map(&xsks_map, index, XDP_PASS);
	}

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";