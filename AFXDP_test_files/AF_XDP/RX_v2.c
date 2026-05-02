#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <errno.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>

#define NUM_FRAMES 4096
#define FRAME_SIZE 2048
#define BATCH_SIZE 64

/* * After 'sudo ethtool -L <iface> combined 1', 
 * the only valid queue index is 0.
 */
#define QUEUE_ID 0 

struct xsk_umem_info {
    struct xsk_umem *umem;
    void *buffer;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
};

static struct xsk_umem_info *configure_umem(void) {
    struct xsk_umem_info *umem = calloc(1, sizeof(*umem));
    void *bufs;
    if (posix_memalign(&bufs, getpagesize(), NUM_FRAMES * FRAME_SIZE)) {
        fprintf(stderr, "Could not allocate buffer\n");
        exit(1);
    }

    struct xsk_umem_config cfg = {
        .fill_size = NUM_FRAMES,
        .comp_size = NUM_FRAMES,
        .frame_size = FRAME_SIZE,
        .frame_headroom = 0,
        .flags = 0
    };

    int ret = xsk_umem__create(&umem->umem, bufs, NUM_FRAMES * FRAME_SIZE,
                               &umem->fq, &umem->cq, &cfg);
    if (ret) {
        fprintf(stderr, "UMEM creation failed: %s\n", strerror(errno));
        exit(1);
    }
    umem->buffer = bufs;
    return umem;
}

static void fill_fq(struct xsk_umem_info *umem) {
    uint32_t idx;
    if (xsk_ring_prod__reserve(&umem->fq, NUM_FRAMES, &idx) != NUM_FRAMES)
        return;

    for (int i = 0; i < NUM_FRAMES; i++)
        *xsk_ring_prod__fill_addr(&umem->fq, idx++) = i * FRAME_SIZE;

    xsk_ring_prod__submit(&umem->fq, NUM_FRAMES);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <iface>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    int ifindex = if_nametoindex(ifname);

    // Ensure locked memory limits are high enough for UMEM
    // Note: You should still run 'ulimit -l unlimited' in your shell
    struct xsk_umem_info *umem = configure_umem();
    fill_fq(umem);

    struct xsk_socket *xsk;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;

    struct xsk_socket_config cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        /* * XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD tells libbpf NOT to 
         * replace the XDP program you manually loaded via 'ip link'.
         */
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = XDP_FLAGS_SKB_MODE, // Generic mode for stability
        .bind_flags = XDP_COPY,          // Required for SKB_MODE
    };

    if (xsk_socket__create(&xsk, ifname, QUEUE_ID, umem->umem, &rx, &tx, &cfg)) {
        fprintf(stderr, "xsk_socket__create failed: %s\n", strerror(errno));
        return 1;
    }

    /*
     * We need the FD of the 'xsks_map' from your loaded BPF object.
     * Since you loaded it manually, we search for the map by name.
     */
    int map_fd = bpf_map_get_fd_by_id(0); // Dummy start
    
    // Better way: find map by name using bpftool logic
    struct bpf_map_info info = {};
    uint32_t len = sizeof(info);
    uint32_t id = 0;
    int found_map_fd = -1;

    while (bpf_map_get_next_id(id, &id) == 0) {
        int fd = bpf_map_get_fd_by_id(id);
        if (fd < 0) continue;
        bpf_obj_get_info_by_fd(fd, &info, &len);
        if (strncmp(info.name, "xsks_map", 8) == 0) {
            found_map_fd = fd;
            break;
        }
        close(fd);
    }

    if (found_map_fd < 0) {
        fprintf(stderr, "Error: xsks_map not found. Is your XDP program loaded?\n");
        return 1;
    }

    int xsks_fd = xsk_socket__fd(xsk);
    uint32_t key = QUEUE_ID;

    if (bpf_map_update_elem(found_map_fd, &key, &xsks_fd, 0)) {
        perror("bpf_map_update_elem");
        return 1;
    }

    printf("Successfully bound to %s (Queue %d)\n", ifname, QUEUE_ID);
    printf("Check 'sudo cat /sys/kernel/debug/tracing/trace_pipe' for logs.\n");

    while (1) {
        uint32_t idx;
        int rcvd = xsk_ring_cons__peek(&rx, BATCH_SIZE, &idx);
        if (!rcvd) {
            // In SKB/Copy mode, we need to poke the kernel to keep RX moving
            if (xsk_ring_prod__needs_wakeup(&umem->fq)) {
                recvfrom(xsks_fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
            }
            continue;
        }

        for (int i = 0; i < rcvd; i++) {
            const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&rx, idx + i);
            printf("Socket received packet! Length: %u\n", desc->len);
        }

        xsk_ring_cons__release(&rx, rcvd);
    }

    return 0;
}