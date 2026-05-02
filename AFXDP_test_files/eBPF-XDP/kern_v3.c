#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME); // <--- Add this
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_pass_prog(struct xdp_md *ctx)
{
    __u32 index = ctx->rx_queue_index;

    // Check if our user-space app has registered itself in the map
    if (bpf_map_lookup_elem(&xsks_map, &index)) {
        bpf_printk("Redirecting to AF_XDP socket on queue %d\n", index);
        return bpf_redirect_map(&xsks_map, index, 0);
    }

    // If no socket is found (or for all other queues), let the kernel have it
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";