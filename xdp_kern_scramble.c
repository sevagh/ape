#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>

#include "headers/bpf_endian.h"
#include "headers/bpf_helpers.h"
#include "common/parsing_helpers.h"

struct bpf_map_def SEC("maps") scramble_count = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(long),
	.max_entries = 2,
};

struct bpf_map_def SEC("maps") xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 64,
};

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))
#endif

SEC("xdp_ape_scramble")
int xdp_ape_scramble_func(struct xdp_md *ctx)
{
	int eth_type, ip_type, map_key, index;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };
	long *value;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0)
		return XDP_ABORTED;

	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	} else {
		return XDP_PASS;
	}

	// only support UDP for now
	if (ip_type != IPPROTO_UDP)
		return XDP_PASS;

#ifdef UDP_PORT
	struct udphdr *udphdr;
	// don't mess with ports outside our purview, if specified
	if (parse_udphdr(&nh, data_end, &udphdr) < 0)
		return XDP_ABORTED;
	if (bpf_ntohs(udphdr->dest) != UDP_PORT)
		return XDP_PASS;
#endif /* UDP_PORT */

	//if we're here, it's a UDP packet with dst port we care about
	map_key = 0;
	value = bpf_map_lookup_elem(&scramble_count, &map_key);
	if (value)
		lock_xadd(value, 1);

	if ((bpf_get_prandom_u32() % 100) < UDP_SCRAMBLE_PROB) {
		map_key = 1;
		value = bpf_map_lookup_elem(&scramble_count, &map_key);
		if (value)
			lock_xadd(value, 1);

		index = ctx->rx_queue_index;
		if (bpf_map_lookup_elem(&xsks_map, &index))
			return bpf_redirect_map(&xsks_map, index, 0);
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
