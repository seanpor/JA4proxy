// SPDX-License-Identifier: GPL-2.0
//
// ja4block.c — XDP program for JA4proxy kernel-level IP blocking.
//
// Drops packets from IPv4 source addresses listed in the ``blocked_ips``
// BPF hash map, which is populated by the ``scripts/redis-to-ebpf.py``
// sidecar process.
//
// Compile:
//   clang -O2 -target bpf -c ja4block.c -o ja4block.o
//
// Load (root required):
//   ip link set dev eth0 xdpgeneric obj ja4block.o sec xdp
//
// Maps
// ----
// blocked_ips (BPF_MAP_TYPE_HASH)
//   Key  : __u32 — IPv4 source address in network byte order
//   Value: __u8  — 1 = drop, 0 = pass (any non-zero value = drop)
//
// drop_counters (BPF_MAP_TYPE_PERCPU_ARRAY)
//   Key 0: __u64 — packets dropped due to blacklist match
//   Key 1: __u64 — packets dropped due to ban match
//
// Note: the redis-to-ebpf.py sidecar currently uses a single map for both
// blacklist and ban entries; the reason field is tracked in the sidecar.
// The XDP program increments counter[0] for all drops (both reasons) —
// the sidecar provides the per-reason breakdown in Prometheus via its own
// tracking logic.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

// ── BPF Maps ──────────────────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);    /* IPv4 address (network byte order) */
    __type(value, __u8);   /* 1 = drop                          */
} blocked_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} drop_counters SEC(".maps");  /* 0 = blacklist drops, 1 = ban drops */

// ── XDP Program ──────────────────────────────────────────────────────────

SEC("xdp")
int ja4_block(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // ── Parse Ethernet header ─────────────────────────────────────────
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only handle IPv4; pass everything else (IPv6, ARP, etc.)
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // ── Parse IPv4 header ─────────────────────────────────────────────
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Sanity-check IHL (minimum 5 × 4 = 20 bytes)
    if (ip->ihl < 5)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;  /* already in network byte order */

    // ── Blocklist lookup ──────────────────────────────────────────────
    __u8 *verdict = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (!verdict || *verdict == 0)
        return XDP_PASS;

    // ── Drop and count ────────────────────────────────────────────────
    __u32 counter_key = 0;  /* index 0 = blacklist/ban (combined) */
    __u64 *cnt = bpf_map_lookup_elem(&drop_counters, &counter_key);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
