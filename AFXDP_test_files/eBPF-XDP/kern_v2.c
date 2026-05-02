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
    bpf_printk("Packet Received\n");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";