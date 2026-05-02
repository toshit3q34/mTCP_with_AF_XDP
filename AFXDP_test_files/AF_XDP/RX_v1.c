#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>

#define NUM_FRAMES 4096
#define FRAME_SIZE 2048
#define BATCH_SIZE 64

#define QUEUE_ID 0

struct xsk_umem_info {
    struct xsk_umem *umem;
    void *buffer;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
};

static struct xsk_umem_info *configure_umem(void)
{
    struct xsk_umem_info *umem = calloc(1, sizeof(*umem));
    posix_memalign(&umem->buffer, getpagesize(),
                   NUM_FRAMES * FRAME_SIZE);

    xsk_umem__create(&umem->umem,
                     umem->buffer,
                     NUM_FRAMES * FRAME_SIZE,
                     &umem->fq,
                     &umem->cq,
                     NULL);

    return umem;
}

static void fill_fq(struct xsk_umem_info *umem)
{
    uint32_t idx;
    xsk_ring_prod__reserve(&umem->fq, NUM_FRAMES, &idx);

    for (int i = 0; i < NUM_FRAMES; i++)
        *xsk_ring_prod__fill_addr(&umem->fq, idx++) = i * FRAME_SIZE;

    xsk_ring_prod__submit(&umem->fq, NUM_FRAMES);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: %s <iface>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    int ifindex = if_nametoindex(ifname);

    struct xsk_umem_info *umem = configure_umem();
    fill_fq(umem);

    struct xsk_socket *xsk;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;

    struct xsk_socket_config cfg = {
        .rx_size = 2048,
        .tx_size = 2048,
        .xdp_flags = 0,
        .bind_flags = 0,
    };

    if (xsk_socket__create(&xsk, ifname, QUEUE_ID,
                           umem->umem, &rx, &tx, &cfg)) {
        perror("xsk_socket__create");
        return 1;
    }

    // -------------------------
    // Load XDP program
    // -------------------------
    struct bpf_object *obj;
    obj = bpf_object__open_file("xdp_kern.o", NULL);
    bpf_object__load(obj);

    struct bpf_program *prog =
        bpf_object__find_program_by_name(obj, "xdp_sock_prog");

    int prog_fd = bpf_program__fd(prog);

    bpf_set_link_xdp_fd(ifindex, prog_fd, 0);

    // -------------------------
    // Bind socket to map
    // -------------------------
    int map_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");
    int xsks_fd = xsk_socket__fd(xsk);

    int key = QUEUE_ID;
    bpf_map_update_elem(map_fd, &key, &xsks_fd, 0);

    printf("Receiving packets on %s (queue %d)...\n", ifname, QUEUE_ID);

    while (1) {
        uint32_t idx;
        int rcvd = xsk_ring_cons__peek(&rx, BATCH_SIZE, &idx);

        if (!rcvd)
            continue;

        for (int i = 0; i < rcvd; i++) {
            const struct xdp_desc *desc =
                xsk_ring_cons__rx_desc(&rx, idx + i);

            printf("Packet len = %u\n", desc->len);
        }

        xsk_ring_cons__release(&rx, rcvd);
    }
}