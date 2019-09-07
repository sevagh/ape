/* SPDX-License-Identifier: GPL-2.0 */

#include <limits.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/resource.h>

#include <bpf/bpf.h>
#include <bpf/xsk.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

#include "common/common_params.h"
#include "common/common_user_bpf_xdp.h"
#include "common/common_libbpf.h"
#include "headers/bpf_endian.h"
//#include "headers/bpf_helpers.h"
#include "common/parsing_helpers.h"

#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE 64
#define INVALID_UMEM_FRAME UINT64_MAX

#ifndef MAX_SLEEP_MS
#define MAX_SLEEP_MS 1000
#endif

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;

	uint64_t umem_frame_addr[NUM_FRAMES];
	uint32_t umem_frame_free;

	uint32_t outstanding_tx;
};

static inline __u32 xsk_ring_prod__free(struct xsk_ring_prod *r)
{
	r->cached_cons = *r->consumer + r->size;
	return r->cached_cons - r->cached_prod;
}

static const char *__doc__ = "AF_XDP kernel bypass example\n";

static const struct option_wrapper long_options[] = {

	{ { "help", no_argument, NULL, 'h' }, "Show help", false },

	{ { "dev", required_argument, NULL, 'd' },
	  "Operate on device <ifname>",
	  "<ifname>",
	  true },

	{ { "skb-mode", no_argument, NULL, 'S' },
	  "Install XDP program in SKB (AKA generic) mode" },

	{ { "native-mode", no_argument, NULL, 'N' },
	  "Install XDP program in native mode" },

	{ { "auto-mode", no_argument, NULL, 'A' },
	  "Auto-detect SKB or native mode" },

	{ { "force", no_argument, NULL, 'F' },
	  "Force install, replacing existing program on interface" },

	{ { "copy", no_argument, NULL, 'c' }, "Force copy mode" },

	{ { "zero-copy", no_argument, NULL, 'z' }, "Force zero-copy mode" },

	{ { "queue", required_argument, NULL, 'Q' },
	  "Configure interface receive queue for AF_XDP, default=0" },

	{ { "poll-mode", no_argument, NULL, 'p' },
	  "Use the poll() API waiting for packets to arrive" },

	{ { "unload", no_argument, NULL, 'U' },
	  "Unload XDP program instead of loading" },

	{ { "reuse-maps", no_argument, NULL, 'M' }, "Reuse pinned maps" },

	{ { "quiet", no_argument, NULL, 'q' }, "Quiet mode (no output)" },

	{ { "filename", required_argument, NULL, 1 },
	  "Load program from <file>",
	  "<file>" },

	{ { "progsec", required_argument, NULL, 2 },
	  "Load program in <section> of the ELF file",
	  "<section>" },

	{ { 0, 0, NULL, 0 }, NULL, false }
};

static bool global_exit;

static void dawdle()
{
	/* https://gist.github.com/justinloundagin/5536640 */
	struct timespec tv;
	int msec = (int)(((double)random() / INT_MAX) * MAX_SLEEP_MS);
	tv.tv_sec = 0;
	tv.tv_nsec = 1000000 * msec;
	if (nanosleep(&tv, NULL) == -1) {
		perror("nanosleep");
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

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
	assert(xsk->umem_frame_free < NUM_FRAMES);

	xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk)
{
	return xsk->umem_frame_free;
}

static struct xsk_socket_info *xsk_configure_socket(struct config *cfg,
						    struct xsk_umem_info *umem)
{
	struct xsk_socket_config xsk_cfg;
	struct xsk_socket_info *xsk_info;
	uint32_t idx;
	uint32_t prog_id = 0;
	int i;
	int ret;

	xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info)
		return NULL;

	xsk_info->umem = umem;
	xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	xsk_cfg.libbpf_flags = 0;
	xsk_cfg.xdp_flags = cfg->xdp_flags;
	xsk_cfg.bind_flags = cfg->xsk_bind_flags;

	ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname, cfg->xsk_if_queue,
				 umem->umem, &xsk_info->rx, &xsk_info->tx,
				 &xsk_cfg);

	if (ret)
		goto error_exit;

	ret = bpf_get_link_xdp_id(cfg->ifindex, &prog_id, cfg->xdp_flags);
	if (ret)
		goto error_exit;

	/* Initialize umem frame allocation */

	for (i = 0; i < NUM_FRAMES; i++)
		xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

	xsk_info->umem_frame_free = NUM_FRAMES;

	/* Stuff the receive path with buffers, we assume we have enough */
	ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
				     XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);

	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
		goto error_exit;

	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
		*xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
			xsk_alloc_umem_frame(xsk_info);

	xsk_ring_prod__submit(&xsk_info->umem->fq,
			      XSK_RING_PROD__DEFAULT_NUM_DESCS);

	return xsk_info;

error_exit:
	errno = -ret;
	return NULL;
}

static void complete_tx(struct xsk_socket_info *xsk)
{
	unsigned int completed;
	uint32_t idx_cq;

	if (!xsk->outstanding_tx)
		return;

	sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

	/* Collect/free completed TX buffers */
	completed = xsk_ring_cons__peek(
		&xsk->umem->cq, XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx_cq);

	if (completed > 0) {
		for (int i = 0; i < completed; i++)
			xsk_free_umem_frame(
				xsk, *xsk_ring_cons__comp_addr(&xsk->umem->cq,
							       idx_cq++));

		xsk_ring_cons__release(&xsk->umem->cq, completed);
	}
}

static bool process_packet(struct xsk_socket_info *xsk, uint64_t addr,
			   uint32_t len, int udp4_out, int udp6_out)
{
	uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

	int eth_type, ip_type;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct udphdr *udphdr;
	void *data = (void *)pkt;
	void *data_end = (void *)pkt + len;
	struct hdr_cursor nh = { .pos = data };

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0) {
		return false;
	}

	bool use_ipv6 = false;

	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		use_ipv6 = true;
	} else {
		return false;
	}

	// only support UDP for now
	if (ip_type != IPPROTO_UDP)
		return false;

	// invalid udp
	if (parse_udphdr(&nh, data_end, &udphdr) < 0) {
		return false;
	}

	// sleep randomly to scramble
	dawdle();

	ssize_t sent_bytes;
	if (use_ipv6) {
		struct sockaddr_in6 sin;
		sin.sin6_family = AF_INET6;
		sin.sin6_port = udphdr->dest;
		inet_pton(AF_INET6, "::1", &sin.sin6_addr);
		sent_bytes = sendto(udp6_out, (void *)nh.pos, len, 0,
				    (struct sockaddr *)&sin, sizeof(sin));
	} else {
		struct sockaddr_in sin;
		sin.sin_family = AF_INET;
		sin.sin_port = udphdr->dest;
		sin.sin_addr.s_addr = inet_addr("127.0.0.1");
		sent_bytes = sendto(udp4_out, (void *)nh.pos, len, 0,
				    (struct sockaddr *)&sin, sizeof(sin));
	}

	return true;
}

static void handle_receive_packets(struct xsk_socket_info *xsk, int udp4_out,
				   int udp6_out)
{
	unsigned int rcvd, stock_frames, i;
	uint32_t idx_rx = 0, idx_fq = 0;
	int ret;

	rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
	if (!rcvd)
		return;

	/* Stuff the ring with as much frames as possible */
	stock_frames =
		xsk_prod_nb_free(&xsk->umem->fq, xsk_umem_free_frames(xsk));

	if (stock_frames > 0) {
		ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames,
					     &idx_fq);

		/* This should not happen, but just in case */
		while (ret != stock_frames)
			ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd,
						     &idx_fq);

		for (i = 0; i < stock_frames; i++)
			*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
				xsk_alloc_umem_frame(xsk);

		xsk_ring_prod__submit(&xsk->umem->fq, stock_frames);
	}

	/* Process received packets */
	for (i = 0; i < rcvd; i++) {
		uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
		uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

		if (!process_packet(xsk, addr, len, udp4_out, udp6_out))
			xsk_free_umem_frame(xsk, addr);
	}

	xsk_ring_cons__release(&xsk->rx, rcvd);

	/* Do we need to wake up the kernel for transmission */
	complete_tx(xsk);
}

static void rx_and_process(struct config *cfg,
			   struct xsk_socket_info *xsk_socket, int udp4_out,
			   int udp6_out)
{
	struct pollfd fds[2];
	int ret, nfds = 1;

	memset(fds, 0, sizeof(fds));
	fds[0].fd = xsk_socket__fd(xsk_socket->xsk);
	fds[0].events = POLLIN;

	while (!global_exit) {
		if (cfg->xsk_poll_mode) {
			ret = poll(fds, nfds, -1);
			if (ret <= 0 || ret > 1)
				continue;
		}
		handle_receive_packets(xsk_socket, udp4_out, udp6_out);
	}
}

static void exit_application(int signal)
{
	signal = signal;
	global_exit = true;
}

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir = "/sys/fs/bpf";
const char *map_name = "scramble_count";

/* Pinning maps under /sys/fs/bpf in subdir */
int pin_maps_in_bpf_object(struct bpf_object *bpf_obj, struct config *cfg)
{
	char map_filename[PATH_MAX];
	int err, len;

	len = snprintf(map_filename, PATH_MAX, "%s/%s/%s", pin_basedir,
		       cfg->ifname, map_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating map_name\n");
		return EXIT_FAIL_OPTION;
	}

	/* Existing/previous XDP prog might not have cleaned up */
	if (access(map_filename, F_OK) != -1) {
		if (verbose)
			printf(" - Unpinning (remove) prev maps in %s/\n",
			       cfg->pin_dir);

		/* Basically calls unlink(3) on map_filename */
		err = bpf_object__unpin_maps(bpf_obj, cfg->pin_dir);
		if (err) {
			fprintf(stderr, "ERR: UNpinning maps in %s\n",
				cfg->pin_dir);
			return EXIT_FAIL_BPF;
		}
	}
	if (verbose)
		printf(" - Pinning maps in %s/\n", cfg->pin_dir);

	/* This will pin all maps in our bpf_object */
	err = bpf_object__pin_maps(bpf_obj, cfg->pin_dir);
	if (err)
		return EXIT_FAIL_BPF;

	return 0;
}

int main(int argc, char **argv)
{
	struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK)");
		return 1;
	}

	int xsks_map_fd, err;
	void *packet_buffer;
	uint64_t packet_buffer_size;
	struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
	struct config cfg = { .ifindex = -1,
			      .do_unload = false,
			      .filename = "",
			      .progsec = "xdp_ape_scramble" };
	struct xsk_umem_info *umem;
	struct xsk_socket_info *xsk_socket;
	struct bpf_object *bpf_obj = NULL;

	/* Global shutdown handler */
	signal(SIGINT, exit_application);

	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERROR: Required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	/* Unload XDP program if requested */
	if (cfg.do_unload)
		return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);

	int len = snprintf(cfg.pin_dir, PATH_MAX, "%s/%s", pin_basedir,
			   cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	/* Load custom program if configured */
	if (cfg.filename[0] != 0) {
		struct bpf_map *map;

		bpf_obj = load_bpf_and_xdp_attach(&cfg);
		if (!bpf_obj) {
			/* Error handling done in load_bpf_and_xdp_attach() */
			exit(EXIT_FAILURE);
		}

		/* We also need to load the xsks_map */
		map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
		xsks_map_fd = bpf_map__fd(map);
		if (xsks_map_fd < 0) {
			fprintf(stderr, "ERROR: no xsks map found: %s\n",
				strerror(xsks_map_fd));
			exit(EXIT_FAILURE);
		}
	}

	/* Use the --dev name as subdir for exporting/pinning maps */
	if (!cfg.reuse_maps) {
		err = pin_maps_in_bpf_object(bpf_obj, &cfg);
		if (err) {
			fprintf(stderr, "ERR: pinning maps\n");
			return err;
		}
	}

	/* Allow unlimited locking of memory, so all memory needed for packet
	 * buffers can be locked.
	 */
	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Allocate memory for NUM_FRAMES of the default XDP frame size */
	packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
	if (posix_memalign(&packet_buffer,
			   getpagesize(), /* PAGE_SIZE aligned */
			   packet_buffer_size)) {
		fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Initialize shared packet_buffer for umem usage */
	umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
	if (umem == NULL) {
		fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Open and configure the AF_XDP (xsk) socket */
	xsk_socket = xsk_configure_socket(&cfg, umem);
	if (xsk_socket == NULL) {
		fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* set up udp4 sender socket */
	int udp4_sender_sock_fd;
	err = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (err < 0) {
		perror("cannot create socket");
		return err;
	}
	udp4_sender_sock_fd = err;

	struct sockaddr_in udp4_sender_sockaddr;

	memset((char *)&udp4_sender_sockaddr, 0, sizeof(udp4_sender_sockaddr));
	udp4_sender_sockaddr.sin_family = AF_INET;
	udp4_sender_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	udp4_sender_sockaddr.sin_port = htons(0);

	err = bind(udp4_sender_sock_fd,
		   (struct sockaddr *)&udp4_sender_sockaddr,
		   sizeof(udp4_sender_sockaddr));
	if (err < 0) {
		perror("bind failed");
		return err;
	}

	/* set up udp6 sender socket */
	int udp6_sender_sock_fd;
	err = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (err < 0) {
		perror("cannot create socket");
		return err;
	}
	udp6_sender_sock_fd = err;

	struct sockaddr_in6 udp6_sender_sockaddr;

	memset((char *)&udp6_sender_sockaddr, 0, sizeof(udp6_sender_sockaddr));
	udp6_sender_sockaddr.sin6_family = AF_INET6;
	udp6_sender_sockaddr.sin6_addr = in6addr_any;
	udp6_sender_sockaddr.sin6_port = htons(0);

	err = bind(udp6_sender_sock_fd,
		   (struct sockaddr *)&udp6_sender_sockaddr,
		   sizeof(udp6_sender_sockaddr));
	if (err < 0) {
		perror("bind failed");
		return err;
	}

	/* Receive and count packets than drop them */
	rx_and_process(&cfg, xsk_socket, udp4_sender_sock_fd,
		       udp6_sender_sock_fd);

	/* Cleanup */
	xsk_socket__delete(xsk_socket->xsk);
	xsk_umem__delete(umem->umem);
	xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
	close(udp4_sender_sock_fd);
	close(udp6_sender_sock_fd);

	return EXIT_OK;
}
