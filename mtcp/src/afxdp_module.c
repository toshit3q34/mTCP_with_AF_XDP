/* for io_module_func def'ns */
#include "io_module.h"
#ifndef DISABLE_AFXDP
/* for mtcp related def'ns */
#include "mtcp.h"
/* for bool */
#include <stdbool.h>
/* for errno */
#include <errno.h>
/* for exit, calloc, free */
#include <stdlib.h>
/* for fprintf */
#include <stdio.h>
/* for strerror */
#include <string.h>
/* for getpagesize */
#include <unistd.h>
/* for sendto */
#include <sys/socket.h>
/* for setrlimit / RLIMIT_MEMLOCK */
#include <sys/resource.h>
/* for ifreq, IFF_PROMISC, IFNAMSIZ */
#include <net/if.h>
/* for ioctl */
#include <sys/ioctl.h>

/* for libbpf / AF_XDP. We use libbpf-only APIs (no libxdp dependency)
 * because Ubuntu 22.04 ships libbpf-dev but not libxdp-dev. */
#include <bpf/bpf.h>
/* for XDP_FLAGS_* constants (DRV_MODE, SKB_MODE, UPDATE_IF_NOEXIST) */
#include <linux/if_link.h>
#include <xdp/libxdp.h>
#include <xdp/xdp_helpers.h>
#include <xdp/xsk.h>
/* for logging */
#include "debug.h"
/* for num_devices_* */
#include "config.h"

#define NUM_FRAMES     16384   // critical: shared across all interfaces

#define FRAME_SIZE     XSK_UMEM__DEFAULT_FRAME_SIZE

#define RX_BATCH_SIZE  64
#define TX_BATCH_SIZE  64

// Rings
#define TX_RING_SIZE   512     // per interface (scaled down from 2048)
#define RX_RING_SIZE   1024    // enough to absorb bursts
#define FQ_RING_SIZE   4096    // shared: must be large to avoid RX starvation
#define CQ_RING_SIZE   2048    // handles TX completion backlog
// MAX_DEVICES -> MAX interfaces
#define INVALID_UMEM_FRAME UINT64_MAX

/* Default install location of the BPF kernel object. The build system
 * may override this with -DAFXDP_KERN_PATH="..." to bake in an absolute
 * path. At runtime, the AFXDP_KERN_PATH env var (if set & non-empty)
 * takes precedence over the compile-time default. */
#ifndef AFXDP_KERN_PATH
#define AFXDP_KERN_PATH "afxdp_kern.o"
#endif

static const char *afxdp_resolve_kern_path(void)
{
	const char *p = getenv("AFXDP_KERN_PATH");
	if (p && p[0] != '\0')
		return p;
	return AFXDP_KERN_PATH;
}

static struct xdp_program *prog;
static bool custom_xsk = false;
static int xsk_map_fd;
static int err;
static char errmsg[1024];
static int xdp_cleaned = 0;

/* Per-iface XDP attach mode, recorded at attach time so cleanup can
 * detach with the same mode. XDP_MODE_UNSPEC (= 0) means "not attached". */
static enum xdp_attach_mode attached_mode[MAX_DEVICES];

/* Enable promiscuous mode on `ifname` so AF_XDP can see all frames,
 * not just those addressed to the iface MAC. Returns 0 on success or
 * if promisc was already on. Returns -1 on failure (errno set). */
static int afxdp_set_promisc(const char *ifname)
{
	struct ifreq ifr;
	int sock, rc;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

	if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
		rc = -1;
		goto out;
	}

	if (ifr.ifr_flags & IFF_PROMISC) {
		rc = 0;     /* already promiscuous */
		goto out;
	}

	ifr.ifr_flags |= IFF_PROMISC;
	if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
		rc = -1;
		goto out;
	}
	rc = 0;
out:
	close(sock);
	return rc;
}

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_if_socket {
	struct xsk_socket    *xsk;
	struct xsk_ring_prod  tx;
	struct xsk_ring_cons  rx;
};

struct xsk_socket_info {
	struct xsk_umem_info	*umem;
	struct xsk_if_socket	sock[MAX_DEVICES];
	void			*umem_area;			/* replaces rte_mempool */
	uint64_t		umem_frame_addr[NUM_FRAMES];	/* replaces m_table */
	uint32_t		umem_frame_free;
	uint32_t		outstanding_tx;
	struct {
		uint32_t cnt;
		uint64_t addr[RX_BATCH_SIZE];
		uint32_t len[RX_BATCH_SIZE];
	} rx_batch[MAX_DEVICES];
	struct {
		uint32_t cnt;
		uint64_t addr[TX_BATCH_SIZE];
		uint32_t len[TX_BATCH_SIZE];
	} tx_batch[MAX_DEVICES];
} __attribute__((aligned(64)));

static inline void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t addr)
{
	if (xsk->umem_frame_free >= NUM_FRAMES)
		return;
	xsk->umem_frame_addr[xsk->umem_frame_free++] = addr;
}

static inline void complete_tx(struct xsk_socket_info *xsk)
{
	uint32_t idx_cq = 0;
	uint32_t i;
	uint32_t completed = xsk_ring_cons__peek(&xsk->umem->cq, TX_BATCH_SIZE, &idx_cq);

	if (!completed)
		return;

	for (i = 0; i < completed; i++) {
		uint64_t addr = *xsk_ring_cons__comp_addr(&xsk->umem->cq, idx_cq + i);
		xsk_free_umem_frame(xsk, addr);
	}

	xsk_ring_cons__release(&xsk->umem->cq, completed);

	if (xsk->outstanding_tx >= completed)
		xsk->outstanding_tx -= completed;
	else
		xsk->outstanding_tx = 0;
}

void afxdp_load_module(void){
	const char *kern_path = afxdp_resolve_kern_path();

	/* Skip libxdp's multi-prog dispatcher *before* xdp_program__create —
	 * this env var is consulted at create/attach time. If we set it later,
	 * libxdp may wrap our program in the dispatcher, which leaves us with
	 * a dispatcher attached on the netdev and our program running as a
	 * sub-program. In that case bpf_object__find_map_by_name() can resolve
	 * to a different xsks_map than the one the running program actually
	 * uses, so xsk_socket__update_xskmap() updates the wrong map and the
	 * redirect lands in a socket nobody is polling. */
	setenv("LIBXDP_SKIP_DISPATCHER", "1", 1);

	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, .open_filename = kern_path,);
	custom_xsk = true;

	prog = xdp_program__create(&xdp_opts);
	err = libxdp_get_error(prog);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERROR: loading XDP program from '%s': %s (%d)\n"
			"Hint: set AFXDP_KERN_PATH env var or rebuild with "
			"-DAFXDP_KERN_PATH=\"/abs/path/to/afxdp_kern.o\"\n",
			kern_path, errmsg, err);
		exit(EXIT_FAILURE);
	}

	struct bpf_object *obj = xdp_program__bpf_obj(prog);
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: Kernel rejected BPF object: %s\n", strerror(-err));
        /* Hint: If this fails, run 'sudo dmesg' to see the verifier log */
        exit(EXIT_FAILURE);
    }

	/* Attach the program on all configured interfaces. Try native (driver)
	 * mode first for best performance; fall back to SKB (generic) mode if
	 * the driver doesn't support native XDP. Bail hard if both fail —
	 * mTCP can't function without an attached program.
	 *
	 * Note: devices_attached[ifidx] is the real Linux kernel ifindex
	 * (populated by SetNetEnv via if_nametoindex). CONFIG.eths[ifidx].ifindex
	 * is mTCP's internal small port number — different thing, do not pass
	 * it to xdp_program__attach(). */
	for (int ifidx = 0; ifidx < num_devices_attached; ifidx++) {
		const int ifindex  = devices_attached[ifidx];
		const char *ifname = CONFIG.eths[ifidx].dev_name;
		if(ifindex != 3){
			continue;
		}
		printf("HERE\n");
		attached_mode[ifidx] = 0;

		if (ifindex <= 0)
			continue;

		/* Try SKB mode directly (best for mlx4_en) */
		err = xdp_program__attach(prog, ifindex,
								XDP_MODE_SKB,
								0);

		if (err) {
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr,
				"XDP attach failed on iface '%s' (ifindex=%d): %s (%d)\n",
				ifname ? ifname : "?", ifindex, errmsg, err);
			exit(EXIT_FAILURE);
		}

		attached_mode[ifidx] = XDP_MODE_SKB;

		fprintf(stderr,
			"AFXDP: attached XDP (SKB mode) on iface '%s' kernel_ifindex=%d eidx=%d\n",
			ifname ? ifname : "?", ifindex, ifidx);

		/* Promiscuous mode */
		if (ifname && ifname[0] != '\0') {
			if (afxdp_set_promisc(ifname) < 0) {
				fprintf(stderr,
					"WARN: couldn't enable promisc on '%s': %s\n",
					ifname, strerror(errno));
			}
		}
	}

    // Use the more efficient find_map_by_name instead of a manual loop
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "xsks_map");

    if (!map) {
        fprintf(stderr, "ERROR: no xsks map found in the BPF object\n");
        exit(EXIT_FAILURE);
    }

    xsk_map_fd = bpf_map__fd(map);
    if (xsk_map_fd < 0) {
        // If it's still < 0 here, the load itself failed (check dmesg)
        fprintf(stderr, "ERROR: xsks_map fd is invalid (%d). Is the program loaded?\n", xsk_map_fd);
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "AFXDP: xsks_map resolved (fd=%d). Sockets will be inserted "
                    "via xsk_socket__update_xskmap at queue_id=ctxt->cpu.\n",
            xsk_map_fd);
}

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{
	struct xsk_umem_info *umem;
	int ret;

	struct xsk_umem_config umem_cfg = {
		.fill_size      = FQ_RING_SIZE,
		.comp_size      = CQ_RING_SIZE,
		.frame_size     = FRAME_SIZE,
		.frame_headroom = 0,
		.flags          = 0,
	};

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return NULL;

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
			       &umem_cfg);
	if (ret) {
		errno = -ret;
		free(umem);
		return NULL;
	}

	umem->buffer = buffer;
	return umem;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
	uint64_t frame;
	if (xsk->umem_frame_free == 0)
		return INVALID_UMEM_FRAME;

	frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
	xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
	return frame;
}

static int xsk_configure_socket(struct xsk_socket_info *xsk_info, int ifidx,
				const char *ifname, uint32_t queue_id,
				int kernel_ifindex, bool first_on_umem)
{
	struct xsk_socket_config xsk_cfg;
	struct xsk_if_socket *xsk_if;
	int ret;

	if (ifidx < 0 || ifidx >= MAX_DEVICES) {
		errno = EINVAL;
		return -1;
	}

	xsk_if = &xsk_info->sock[ifidx];
	memset(&xsk_cfg, 0, sizeof(xsk_cfg));
	xsk_cfg.rx_size      = RX_RING_SIZE;
	xsk_cfg.tx_size      = TX_RING_SIZE;
	xsk_cfg.xdp_flags    = 0;
	/* XDP_USE_NEED_WAKEUP lets the kernel signal when it needs userspace
	 * to wake it (cheap when idle, required on some drivers in SKB+COPY
	 * mode for timely RX). We must respect xsk_ring_prod__needs_wakeup()
	 * on the FQ in the recv path below, otherwise we can stall waiting
	 * for the kernel to fill an RX descriptor that it'll only fill after
	 * we kick it. */
	xsk_cfg.bind_flags   = XDP_USE_NEED_WAKEUP;
	xsk_cfg.libbpf_flags = custom_xsk ? XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD : 0;
	if (first_on_umem) {
		/* First socket on this UMEM: standard create */
		ret = xsk_socket__create(&xsk_if->xsk, ifname, queue_id,
					 xsk_info->umem->umem,
					 &xsk_if->rx, &xsk_if->tx, &xsk_cfg);
	} else {
		/* Subsequent socket: must use _shared and pass the UMEM's FQ/CQ */
		ret = xsk_socket__create_shared(&xsk_if->xsk, ifname, queue_id,
						xsk_info->umem->umem,
						&xsk_if->rx, &xsk_if->tx,
						&xsk_info->umem->fq,
						&xsk_info->umem->cq,
						&xsk_cfg);
	}
	if (ret)
		goto error_exit;

	if (custom_xsk) {
		/* IMPORTANT: do NOT use xsk_socket__update_xskmap() — it inserts
		 * the socket fd at index = queue_id, which collides across NICs
		 * when each NIC has only one queue. We key the map by kernel
		 * ifindex instead, matching what afxdp_kern.c looks up via
		 * ctx->ingress_ifindex. */
		__u32 key = (__u32)queue_id;
		int xsk_fd = xsk_socket__fd(xsk_if->xsk);
		ret = bpf_map_update_elem(xsk_map_fd, &key, &xsk_fd, BPF_ANY);
		if (ret) {
			fprintf(stderr,
				"ERROR: bpf_map_update_elem(xsks_map[%u]=%d) failed: %s\n",
				key, xsk_fd, strerror(-ret));
			goto error_exit;
		}
	}

	fprintf(stderr, "AFXDP: Socket created.\n");

	return 0;

error_exit:
	errno = -ret;
	return -1;
}

void afxdp_init_handle(struct mtcp_thread_context *ctxt){

	/* Allow unlimited locking of memory so the UMEM allocation
	 * can be pinned. Required on kernels < 5.11 (and on 5.11+
	 * when CONFIG_MEMCG is not in effect). Idempotent across
	 * threads, so calling it per-init is harmless. */
	struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Allocate memory for NUM_FRAMES of the default XDP frame size */
	uint64_t packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
	void *packet_buffer;
	if (posix_memalign(&packet_buffer,
			   getpagesize(), /* PAGE_SIZE aligned */
			   packet_buffer_size)) {
		fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct xsk_umem_info *umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
	if (umem == NULL) {
		fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	ctxt->io_private_context = calloc(1, sizeof(struct xsk_socket_info));
	if (ctxt->io_private_context == NULL) {
		fprintf(stderr, "ERROR: Can't allocate afxdp context \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct xsk_socket_info *xsk_info = (struct xsk_socket_info *)ctxt->io_private_context;

	xsk_info->umem = umem;

	if (num_devices_attached > MAX_DEVICES) {
		fprintf(stderr, "ERROR: num_devices_attached (%d) exceeds MAX_DEVICES (%d)\n",
			num_devices_attached, MAX_DEVICES);
		exit(EXIT_FAILURE);
	}

	/* Initialize umem frame allocation */
	for (uint32_t i = 0; i < NUM_FRAMES; i++)
		xsk_info->umem_frame_addr[i] = (uint64_t)i * FRAME_SIZE;
	xsk_info->umem_frame_free = NUM_FRAMES;

	/* Pre-fill the shared UMEM fill queue once */
	{
		uint32_t idx_fq = 0;
		const uint32_t fq_descs = FQ_RING_SIZE;
		uint32_t reserved = xsk_ring_prod__reserve(&xsk_info->umem->fq, fq_descs, &idx_fq);
		if (reserved != fq_descs) {
			fprintf(stderr, "ERROR: Can't reserve FQ descs (want=%u got=%u): \"%s\"\n",
				fq_descs, reserved, strerror(errno));
			exit(EXIT_FAILURE);
		}

		for (uint32_t i = 0; i < fq_descs; i++) {
			uint64_t addr = xsk_alloc_umem_frame(xsk_info);
			if (addr == INVALID_UMEM_FRAME) {
				fprintf(stderr, "ERROR: Out of UMEM frames during FQ prefill\n");
				exit(EXIT_FAILURE);
			}
			*xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx_fq + i) = addr;
		}
		xsk_ring_prod__submit(&xsk_info->umem->fq, fq_descs);
	}

	/* Create one socket per configured interface for this core(queue).
	 * Each socket is registered into xsks_map at key = kernel ifindex
	 * (NOT queue_id) so that multiple NICs each with their own queue 0
	 * don't all collide on xsks_map[0]. See afxdp_kern.c which looks
	 * the socket up via ctx->ingress_ifindex. */
	bool first_on_umem = true;
	for (int ifidx = 0; ifidx < MAX_DEVICES; ifidx++) {
		const char *ifname = CONFIG.eths[ifidx].dev_name;
		const int kifindex = devices_attached[ifidx];
		if(kifindex != 3){
			continue;
		}
		if (ifname == NULL || ifname[0] == '\0')
			continue;

		uint32_t qid = (uint32_t)ctxt->cpu;
		if (xsk_configure_socket(xsk_info, ifidx, ifname,
					 qid, kifindex,
					 first_on_umem) != 0) {
			fprintf(stderr, "ERROR: Can't setup AF_XDP socket on iface '%s' q=%d: \"%s\"\n",
				ifname, ctxt->cpu, strerror(errno));
			exit(EXIT_FAILURE);
		}

		fprintf(stderr,
            "AFXDP: cpu=%d bound xsk on iface '%s' queue_id=%u -> xsks_map[key=%u]\n",
            ctxt->cpu, ifname, qid, qid);

		first_on_umem = false;
	}
}

int32_t afxdp_link_devices(struct mtcp_thread_context *ctxt){
	/* linking takes place during mtcp_init() */

	return 0;
}

void afxdp_release_pkt(struct mtcp_thread_context *ctxt, int ifidx, unsigned char *pkt_data, int len){
	/* 
	 * do nothing over here - memory reclamation
	 * will take place in afxdp_recv_pkts 
	 */
}

uint8_t * afxdp_get_wptr(struct mtcp_thread_context *ctxt, int ifidx, uint16_t len){
	struct xsk_socket_info *xsk_info = (struct xsk_socket_info *)ctxt->io_private_context;
	struct xsk_if_socket *xsk_if;
	uint64_t addr;

	if (!xsk_info || ifidx < 0 || ifidx >= MAX_DEVICES)
		return NULL;

	xsk_if = &xsk_info->sock[ifidx];
	if (!xsk_if->xsk)
		return NULL;

	if (xsk_info->tx_batch[ifidx].cnt >= TX_BATCH_SIZE)
		return NULL;

	addr = xsk_alloc_umem_frame(xsk_info);
	if (addr == INVALID_UMEM_FRAME)
		return NULL;

	xsk_info->tx_batch[ifidx].addr[xsk_info->tx_batch[ifidx].cnt] = addr;
	xsk_info->tx_batch[ifidx].len[xsk_info->tx_batch[ifidx].cnt] = len;
	xsk_info->tx_batch[ifidx].cnt++;

	return (uint8_t *)xsk_umem__get_data(xsk_info->umem->buffer, addr);
}

int32_t afxdp_send_pkts(struct mtcp_thread_context *ctxt, int nif){
	struct xsk_socket_info *xsk_info = (struct xsk_socket_info *)ctxt->io_private_context;
	struct xsk_if_socket *xsk_if;
	uint32_t idx_tx = 0;
	uint32_t n;
	uint32_t i;
	int ret;

	if (!xsk_info || nif < 0 || nif >= MAX_DEVICES)
		return 0;

	xsk_if = &xsk_info->sock[nif];
	if (!xsk_if->xsk)
		return 0;

	/* Reclaim completed TX frames back to free list */
	complete_tx(xsk_info);

	n = xsk_info->tx_batch[nif].cnt;
	if (!n)
		return 0;

	ret = xsk_ring_prod__reserve(&xsk_if->tx, n, &idx_tx);
	if (ret != (int)n)
		return 0;

	for (i = 0; i < n; i++) {
		struct xdp_desc *d = xsk_ring_prod__tx_desc(&xsk_if->tx, idx_tx + i);
		d->addr = xsk_info->tx_batch[nif].addr[i];
		d->len = xsk_info->tx_batch[nif].len[i];
	}

	xsk_ring_prod__submit(&xsk_if->tx, n);
	xsk_info->outstanding_tx += n;

	/* Kick kernel if needed */
	if (xsk_ring_prod__needs_wakeup(&xsk_if->tx))
		sendto(xsk_socket__fd(xsk_if->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

	xsk_info->tx_batch[nif].cnt = 0;
	return (int32_t)n;
}
	
uint8_t * afxdp_get_rptr(struct mtcp_thread_context *ctxt, int ifidx, int index, uint16_t *len){
	struct xsk_socket_info *xsk_info = (struct xsk_socket_info *)ctxt->io_private_context;

	if (!xsk_info || ifidx < 0 || ifidx >= MAX_DEVICES || index < 0) {
		if (len)
			*len = 0;
		return NULL;
	}

	if ((uint32_t)index >= xsk_info->rx_batch[ifidx].cnt) {
		if (len)
			*len = 0;
		return NULL;
	}

	if (len)
		*len = (uint16_t)xsk_info->rx_batch[ifidx].len[index];

	return (uint8_t *)xsk_umem__get_data(xsk_info->umem->buffer,
					     xsk_info->rx_batch[ifidx].addr[index]);
}

int32_t afxdp_recv_pkts(struct mtcp_thread_context *ctxt, int ifidx){
	// fprintf(stderr, "AFXDP: Want to receive packets\n");
	struct xsk_socket_info *xsk_info = (struct xsk_socket_info *)ctxt->io_private_context;
	struct xsk_if_socket *xsk_if;
	uint32_t idx_rx = 0, idx_fq = 0;
	uint32_t rcvd;
	uint32_t i;

	if (!xsk_info || ifidx < 0 || ifidx >= MAX_DEVICES)
		return 0;

	xsk_if = &xsk_info->sock[ifidx];
	if (!xsk_if->xsk)
		return 0;

	/* Recycle previous batch back into the fill queue (DPDK-style: free previous on next recv) */
	if (xsk_info->rx_batch[ifidx].cnt) {
		uint32_t n = xsk_info->rx_batch[ifidx].cnt;

		if (xsk_prod_nb_free(&xsk_info->umem->fq, n) < n)
			return 0;	/* FQ has no room; try again next call */

		/* xsk_prod_nb_free above guarantees this returns n exactly. */
		(void)xsk_ring_prod__reserve(&xsk_info->umem->fq, n, &idx_fq);

		for (i = 0; i < n; i++)
			*xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx_fq + i) =
				xsk_info->rx_batch[ifidx].addr[i];

		xsk_ring_prod__submit(&xsk_info->umem->fq, n);
		xsk_info->rx_batch[ifidx].cnt = 0;
	}

	/* Always service the FQ wakeup on every poll, not just after the first
	 * batch lands. Otherwise on the very first call rx_batch.cnt == 0, we
	 * skip the recycle block entirely, never kick the kernel, and the
	 * kernel may sit waiting for a wakeup before it processes the FQ we
	 * pre-filled in init_handle. With XDP_USE_NEED_WAKEUP set in
	 * bind_flags, this is the chicken-and-egg case the user is likely
	 * hitting: ping is redirected at XDP, but the RX descriptor never
	 * surfaces because we never told the kernel "go". */
	if (xsk_ring_prod__needs_wakeup(&xsk_info->umem->fq))
		recvfrom(xsk_socket__fd(xsk_if->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

	rcvd = xsk_ring_cons__peek(&xsk_if->rx, RX_BATCH_SIZE, &idx_rx);
	// fprintf(stderr, "AFXDP: Number of packets received atp : %d\n", (int)rcvd);
	if (!rcvd)
		return 0;

	for (i = 0; i < rcvd; i++) {
		const struct xdp_desc *d = xsk_ring_cons__rx_desc(&xsk_if->rx, idx_rx + i);
		xsk_info->rx_batch[ifidx].addr[i] = d->addr;
		xsk_info->rx_batch[ifidx].len[i] = d->len;
	}

	xsk_ring_cons__release(&xsk_if->rx, rcvd);
	xsk_info->rx_batch[ifidx].cnt = rcvd;

	/* One-shot debug print so you can confirm packets are surfacing to
	 * userspace at all. Remove (or wrap in TRACE_DBG) once verified. */
	{
		static __thread uint64_t total_rcvd = 0;
		static __thread uint64_t last_print = 0;
		total_rcvd += rcvd;
		if (total_rcvd - last_print >= 1) {
			fprintf(stderr,
				"AFXDP: cpu=%d ifidx=%d rcvd=%u total=%lu\n",
				ctxt->cpu, ifidx, rcvd,
				(unsigned long)total_rcvd);
			last_print = total_rcvd;
		}
	}

	return (int32_t)rcvd;
}
	
int32_t	afxdp_select(struct mtcp_thread_context *ctxt){
#if RX_IDLE_ENABLE
// Can add idleness optimization here
#endif
	return 0;
}

static void afxdp_prog_cleanup(void)
{
	if (!prog)
		return;

	for (int ifidx = 0; ifidx < num_devices_attached; ifidx++) {
		int ifindex = devices_attached[ifidx];	/* real kernel ifindex */
		if (ifindex <= 0)
			continue;
		if (attached_mode[ifidx] == XDP_MODE_UNSPEC)
			continue;       /* never attached on this iface */

		xdp_program__detach(prog, ifindex, attached_mode[ifidx], 0);
		attached_mode[ifidx] = XDP_MODE_UNSPEC;
	}

	xdp_program__close(prog);
	prog = NULL;
}

void
afxdp_destroy_handle(struct mtcp_thread_context *ctxt){
	struct xsk_socket_info *xsk_info = (struct xsk_socket_info *)ctxt->io_private_context;

	if (!xsk_info)
		return;

	for (int i = 0; i < MAX_DEVICES; i++) {
		if (xsk_info->sock[i].xsk)
			xsk_socket__delete(xsk_info->sock[i].xsk);
	}

	if (xsk_info->umem) {
		if (xsk_info->umem->umem)
			xsk_umem__delete(xsk_info->umem->umem);
		free(xsk_info->umem->buffer);
		free(xsk_info->umem);
	}

	free(xsk_info);
	ctxt->io_private_context = NULL;

	if (__sync_bool_compare_and_swap(&xdp_cleaned, 0, 1)) {
		afxdp_prog_cleanup();
	}
}

int32_t
afxdp_dev_ioctl(struct mtcp_thread_context *ctx, int nif, int cmd, void *argp){
	(void)ctx;
	(void)nif;
	(void)cmd;
	(void)argp;
	return -1;
}

struct io_module_func afxdp_module_func = {
	.load_module	= afxdp_load_module,
	.init_handle	= afxdp_init_handle,
	.link_devices	= afxdp_link_devices,
	.release_pkt	= afxdp_release_pkt,
	.send_pkts	= afxdp_send_pkts,
	.get_wptr	= afxdp_get_wptr,
	.recv_pkts	= afxdp_recv_pkts,
	.get_rptr	= afxdp_get_rptr,
	.select		= afxdp_select,
	.destroy_handle	= afxdp_destroy_handle,
	.dev_ioctl	= afxdp_dev_ioctl,
};
#else
io_module_func afxdp_module_func = {
	.load_module		   = NULL,
	.init_handle		   = NULL,
	.link_devices		   = NULL,
	.release_pkt		   = NULL,
	.send_pkts		   = NULL,
	.get_wptr   		   = NULL,
	.recv_pkts		   = NULL,
	.get_rptr	   	   = NULL,
	.select			   = NULL,
	.destroy_handle		   = NULL,
	.dev_ioctl		   = NULL
};
/*----------------------------------------------------------------------------*/
#endif /* !DISABLE_AFXDP */