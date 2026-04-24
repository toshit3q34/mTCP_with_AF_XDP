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

/* for libbpf/libxdp/AF_XDP */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>
/* for logging */
#include "debug.h"
/* for num_devices_* */
#include "config.h"

#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define TX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

static struct xdp_program *prog;
static const char filename[] = "afxdp_kern.o";
static bool custom_xsk = false;
static int xsk_map_fd;
static int err;
static char errmsg[1024];

struct xsk_umem_info{
    struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_if_socket {
	struct xsk_socket    *xsk;
	struct xsk_ring_prod  tx;
	struct xsk_ring_cons  rx;
	uint32_t              outstanding_tx;
};

struct xsk_socket_info {
    struct xsk_umem_info  *umem;
    struct xsk_if_socket   sock[MAX_IFPORTS];
    void                  *umem_area;  // replaces rte_mempool
    uint64_t               umem_frame_addr[NUM_FRAMES]; // replaces m_table
    uint32_t               umem_frame_free;
	struct {
		uint32_t cnt;
		uint64_t addr[RX_BATCH_SIZE];
		uint32_t len[RX_BATCH_SIZE];
	} rx_batch[MAX_IFPORTS];
	struct {
		uint32_t cnt;
		uint64_t addr[TX_BATCH_SIZE];
		uint32_t len[TX_BATCH_SIZE];
	} tx_batch[MAX_IFPORTS];
} __attribute__((aligned(64)));

static inline void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t addr)
{
	if (xsk->umem_frame_free >= NUM_FRAMES)
		return;
	xsk->umem_frame_addr[xsk->umem_frame_free++] = addr;
}

static inline void complete_tx(struct xsk_socket_info *xsk, struct xsk_if_socket *xsk_if)
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

	if (xsk_if->outstanding_tx >= completed)
		xsk_if->outstanding_tx -= completed;
	else
		xsk_if->outstanding_tx = 0;
}

void afxdp_load_module(void){
    DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, .open_filename = filename,);
    struct bpf_map *map;
	int ifidx;
	custom_xsk = true;
    prog = xdp_program__create(&xdp_opts);
    err = libxdp_get_error(prog);
    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        fprintf(stderr, "ERR: loading program: %s\n", errmsg);
        return;
    }

	if (num_devices_attached > MAX_IFPORTS) {
		fprintf(stderr, "ERROR: num_devices_attached (%d) exceeds MAX_IFPORTS (%d)\n",
			num_devices_attached, MAX_IFPORTS);
		exit(EXIT_FAILURE);
	}

	/* Attach the program on all configured interfaces */
	for (ifidx = 0; ifidx < num_devices_attached; ifidx++) {
		const int ifindex = CONFIG.eths[ifidx].ifindex;
		const char *ifname = CONFIG.eths[ifidx].dev_name;

		if (ifindex <= 0)
			continue;

		err = xdp_program__attach(prog, ifindex, XDP_MODE_NATIVE, 0);
		if (err) {
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr,
				"Couldn't attach XDP program on iface '%s' (ifindex=%d): %s (%d)\n",
				ifname ? ifname : "?", ifindex, errmsg, err);
			return;
		}
	}

    /* We also need to load the xsks_map */
    map = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), "xsks_map");
    xsk_map_fd = bpf_map__fd(map);
    if (xsk_map_fd < 0) {
        fprintf(stderr, "ERROR: no xsks map found: %s\n",
            strerror(xsk_map_fd));
        exit(EXIT_FAILURE);
    }
}

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{
	struct xsk_umem_info *umem;
	int ret;

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return NULL;

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
			       NULL);
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
				const char *ifname, uint32_t queue_id)
{
	struct xsk_socket_config xsk_cfg;
	struct xsk_if_socket *xsk_if;
	int i;
	int ret;

	if (ifidx < 0 || ifidx >= MAX_IFPORTS) {
		errno = EINVAL;
		return -1;
	}

	xsk_if = &xsk_info->sock[ifidx];
	xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	xsk_cfg.xdp_flags = 0;
	xsk_cfg.bind_flags = 0;
	xsk_cfg.libbpf_flags = (custom_xsk) ? XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD: 0;
	ret = xsk_socket__create(&xsk_if->xsk, ifname,
				 queue_id, xsk_info->umem->umem, &xsk_if->rx,
				 &xsk_if->tx, &xsk_cfg);
	if (ret)
		goto error_exit;

	if (custom_xsk) {
		ret = xsk_socket__update_xskmap(xsk_if->xsk, xsk_map_fd);
		if (ret)
			goto error_exit;
	}

	return 0;

error_exit:
	errno = -ret;
	return -1;
}

void afxdp_init_handle(struct mtcp_thread_context *ctxt){

    // CHECK IF NEED TO BE ADDED
    // if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
	// 	fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
	// 		strerror(errno));
	// 	exit(EXIT_FAILURE);
	// }

    uint64_t packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
    /* Allocate memory for NUM_FRAMES of the default XDP frame size */
    void* packet_buffer;
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
	int ifidx, i;

	xsk_info->umem = umem;

	if (num_devices_attached > MAX_IFPORTS) {
		fprintf(stderr, "ERROR: num_devices_attached (%d) exceeds MAX_IFPORTS (%d)\n",
			num_devices_attached, MAX_IFPORTS);
		exit(EXIT_FAILURE);
	}

	/* Initialize umem frame allocation */
	for (i = 0; i < NUM_FRAMES; i++)
		xsk_info->umem_frame_addr[i] = (uint64_t)i * FRAME_SIZE;
	xsk_info->umem_frame_free = NUM_FRAMES;

	/* Pre-fill the shared UMEM fill queue once */
	{
		uint32_t idx_fq = 0;
		const uint32_t fq_descs = XSK_RING_PROD__DEFAULT_NUM_DESCS;
		int reserved = xsk_ring_prod__reserve(&xsk_info->umem->fq, fq_descs, &idx_fq);
		if (reserved != (int)fq_descs) {
			fprintf(stderr, "ERROR: Can't reserve FQ descs (want=%u got=%d): \"%s\"\n",
				fq_descs, reserved, strerror(errno));
			exit(EXIT_FAILURE);
		}

		for (i = 0; i < (int)fq_descs; i++) {
			uint64_t addr = xsk_alloc_umem_frame(xsk_info);
			if (addr == INVALID_UMEM_FRAME) {
				fprintf(stderr, "ERROR: Out of UMEM frames during FQ prefill\n");
				exit(EXIT_FAILURE);
			}
			*xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx_fq + i) = addr;
		}
		xsk_ring_prod__submit(&xsk_info->umem->fq, fq_descs);
	}

	/* Create one socket per configured interface for this core(queue) */
	for (ifidx = 0; ifidx < num_devices_attached; ifidx++) {
		const char *ifname = CONFIG.eths[ifidx].dev_name;
		if (ifname == NULL || ifname[0] == '\0')
			continue;

		if (xsk_configure_socket(xsk_info, ifidx, ifname, (uint32_t)ctxt->cpu) != 0) {
			fprintf(stderr, "ERROR: Can't setup AF_XDP socket on iface '%s' q=%d: \"%s\"\n",
				ifname, ctxt->cpu, strerror(errno));
			exit(EXIT_FAILURE);
		}
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

	if (!xsk_info || ifidx < 0 || ifidx >= MAX_IFPORTS)
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

	if (!xsk_info || nif < 0 || nif >= MAX_IFPORTS)
		return 0;

	xsk_if = &xsk_info->sock[nif];
	if (!xsk_if->xsk)
		return 0;

	/* Reclaim completed TX frames back to free list */
	complete_tx(xsk_info, xsk_if);

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
	xsk_if->outstanding_tx += n;

	/* Kick kernel if needed */
	if (xsk_ring_prod__needs_wakeup(&xsk_if->tx))
		sendto(xsk_socket__fd(xsk_if->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

	xsk_info->tx_batch[nif].cnt = 0;
	return (int32_t)n;
}
	
uint8_t * afxdp_get_rptr(struct mtcp_thread_context *ctxt, int ifidx, int index, uint16_t *len){
	struct xsk_socket_info *xsk_info = (struct xsk_socket_info *)ctxt->io_private_context;

	if (!xsk_info || ifidx < 0 || ifidx >= MAX_IFPORTS || index < 0) {
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
	struct xsk_socket_info *xsk_info = (struct xsk_socket_info *)ctxt->io_private_context;
	struct xsk_if_socket *xsk_if;
	uint32_t idx_rx = 0, idx_fq = 0;
	uint32_t rcvd;
	uint32_t i;
	int ret;

	if (!xsk_info || ifidx < 0 || ifidx >= MAX_IFPORTS)
		return 0;

	xsk_if = &xsk_info->sock[ifidx];
	if (!xsk_if->xsk)
		return 0;

	/* Recycle previous batch back into the fill queue (DPDK-style: free previous on next recv) */
	if (xsk_info->rx_batch[ifidx].cnt) {
		uint32_t n = xsk_info->rx_batch[ifidx].cnt;

		/* One attempt: recycle what we can, don't spin */
		ret = xsk_ring_prod__reserve(&xsk_info->umem->fq, n, &idx_fq);
		if (ret != (int)n)
			return 0;

		for (i = 0; i < n; i++)
			*xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx_fq + i) =
				xsk_info->rx_batch[ifidx].addr[i];

		xsk_ring_prod__submit(&xsk_info->umem->fq, n);
		xsk_info->rx_batch[ifidx].cnt = 0;
	}

	rcvd = xsk_ring_cons__peek(&xsk_if->rx, RX_BATCH_SIZE, &idx_rx);
	if (!rcvd)
		return 0;

	for (i = 0; i < rcvd; i++) {
		const struct xdp_desc *d = xsk_ring_cons__rx_desc(&xsk_if->rx, idx_rx + i);
		xsk_info->rx_batch[ifidx].addr[i] = d->addr;
		xsk_info->rx_batch[ifidx].len[i] = d->len;
	}

	xsk_ring_cons__release(&xsk_if->rx, rcvd);
	xsk_info->rx_batch[ifidx].cnt = rcvd;

	return (int32_t)rcvd;
}
	
int32_t	afxdp_select(struct mtcp_thread_context *ctxt){
#if RX_IDLE_ENABLE
// Can add idleness optimization here
#endif
	return 0;
}

void
afxdp_destroy_handle(struct mtcp_thread_context *ctxt){
	struct xsk_socket_info *xsk_info = (struct xsk_socket_info *)ctxt->io_private_context;
	int i;

	if (!xsk_info)
		return;

	for (i = 0; i < MAX_IFPORTS; i++) {
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
    .load_module     = afxdp_load_module,
    .init_handle     = afxdp_init_handle,
    .link_devices    = afxdp_link_devices,
    .release_pkt     = afxdp_release_pkt,
    .send_pkts       = afxdp_send_pkts,
    .get_wptr        = afxdp_get_wptr,
    .recv_pkts       = afxdp_recv_pkts,
    .get_rptr        = afxdp_get_rptr,
    .select          = afxdp_select,
    .destroy_handle  = afxdp_destroy_handle,
    .dev_ioctl       = afxdp_dev_ioctl,
};

#endif