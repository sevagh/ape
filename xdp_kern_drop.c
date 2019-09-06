#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>

#include "xdp-tutorial/common/parsing_helpers.h"
#include "xdp-tutorial/headers/bpf_endian.h"
#include "xdp-tutorial/headers/bpf_helpers.h"

/*
 * 0 = UDP
 * 1 = total
 */
struct bpf_map_def SEC("maps") drop_count = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(long),
    .max_entries = 2,
};

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))
#endif

#define UDP_TABLE_KEY 0
#define TOTAL_TABLE_KEY 1

SEC("xdp_ape_drop")
int xdp_ape_drop_func(struct xdp_md *ctx) {
  int eth_type, ip_type, map_key;
  struct ethhdr *eth;
  struct iphdr *iphdr;
  struct ipv6hdr *ipv6hdr;
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct hdr_cursor nh = {.pos = data};
  long *value;

  eth_type = parse_ethhdr(&nh, data_end, &eth);
  if (eth_type < 0)
    return XDP_ABORTED;

  if (eth_type == ETH_P_IP) {
    ip_type = parse_iphdr(&nh, data_end, &iphdr);
  } else if (eth_type == ETH_P_IPV6) {
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

  // if we're here, it's a UDP packet with dst port we care about
  map_key = TOTAL_TABLE_KEY;
  value = bpf_map_lookup_elem(&drop_count, &map_key);
  if (value)
    lock_xadd(value, 1);

  if ((bpf_get_prandom_u32() % 100) < UDP_DROP_PROB) {
    map_key = UDP_TABLE_KEY;
    value = bpf_map_lookup_elem(&drop_count, &map_key);
    if (value)
      lock_xadd(value, 1);
    return XDP_DROP;
  }

  return XDP_PASS;
}
