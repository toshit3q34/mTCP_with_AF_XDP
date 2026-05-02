#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass_prog(struct xdp_md *ctx)
{
    // The simplest possible print to verify the hook is hitting
    bpf_printk("Packet Received\n");

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";