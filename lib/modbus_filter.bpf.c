// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "modbus_filter.h"

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define ETH_P_IP 0x0800
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8
#define IPPROTO_TCP 6
#define MODBUS_PORT 502

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct flow_policy);
} policy_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, COUNTER_MAX);
  __type(key, __u32);
  __type(value, __u64);
} counters SEC(".maps");

static __always_inline void bump_counter(__u32 idx) {
  __u64 *v;
  v = bpf_map_lookup_elem(&counters, &idx);
  if (v)
    __sync_fetch_and_add(v, 1);
}

static __always_inline int is_read_fn(__u8 fn) {
  return fn == 0x01 || fn == 0x02 || fn == 0x03 || fn == 0x04;
}

static __always_inline int is_write_fn(__u8 fn) {
  return fn == 0x05 || fn == 0x06 || fn == 0x0f || fn == 0x10 || fn == 0x16 || fn == 0x17;
}

SEC("tc")
int modbus_filter_ingress(struct __sk_buff *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  __u16 h_proto;
  __u64 nhoff;
  struct iphdr *ip;
  struct tcphdr *tcp;
  __u16 dport;
  __u16 sport;
  __u32 key0 = 0;
  struct flow_policy *policy;
  __u8 *payload;
  __u16 mbap_proto;
  __u16 mbap_len;
  __u8 fn;

  bump_counter(COUNTER_TOTAL);

  if ((void *)(eth + 1) > data_end)
    return TC_ACT_OK;

  h_proto = bpf_ntohs(eth->h_proto);
  nhoff = sizeof(*eth);

  if (h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD) {
    struct vlan_hdr *vh;
    vh = data + nhoff;
    if ((void *)(vh + 1) > data_end)
      return TC_ACT_OK;
    h_proto = bpf_ntohs(vh->h_vlan_encapsulated_proto);
    nhoff += sizeof(*vh);
  }

  if (h_proto != ETH_P_IP) {
    bump_counter(COUNTER_NON_IPV4);
    return TC_ACT_OK;
  }

  ip = data + nhoff;
  if ((void *)(ip + 1) > data_end)
    return TC_ACT_OK;

  if (ip->ihl < 5)
    return TC_ACT_OK;

  if (ip->protocol != IPPROTO_TCP) {
    bump_counter(COUNTER_NON_TCP);
    return TC_ACT_OK;
  }

  tcp = (void *)ip + (ip->ihl * 4);
  if ((void *)(tcp + 1) > data_end)
    return TC_ACT_OK;

  if (tcp->doff < 5)
    return TC_ACT_OK;

  dport = bpf_ntohs(tcp->dest);
  sport = bpf_ntohs(tcp->source);

  if (sport == MODBUS_PORT) {
    bump_counter(COUNTER_RESPONSE_ALLOWED);
    return TC_ACT_OK;
  }

  if (dport != MODBUS_PORT) {
    bump_counter(COUNTER_NON_MODBUS);
    return TC_ACT_OK;
  }

  policy = bpf_map_lookup_elem(&policy_map, &key0);
  if (!policy || ip->saddr != policy->src_ip || ip->daddr != policy->dst_ip) {
    bump_counter(COUNTER_POLICY_MISS_ALLOWED);
    return TC_ACT_OK;
  }

  payload = (void *)tcp + (tcp->doff * 4);
  if (payload + 8 > (unsigned char *)data_end) {
    bump_counter(COUNTER_MALFORMED_DROPPED);
    return TC_ACT_SHOT;
  }

  mbap_proto = ((__u16)payload[2] << 8) | payload[3];
  mbap_len = ((__u16)payload[4] << 8) | payload[5];
  if (mbap_proto != 0x0000 || mbap_len < 2) {
    bump_counter(COUNTER_MALFORMED_DROPPED);
    return TC_ACT_SHOT;
  }

  fn = payload[7];
  if (is_read_fn(fn)) {
    bump_counter(COUNTER_READ_ALLOWED);
    return TC_ACT_OK;
  }

  if (is_write_fn(fn)) {
    bump_counter(COUNTER_WRITE_DROPPED);
    return TC_ACT_SHOT;
  }

  bump_counter(COUNTER_UNKNOWN_DROPPED);
  return TC_ACT_SHOT;
}

char __license[] SEC("license") = "GPL";
