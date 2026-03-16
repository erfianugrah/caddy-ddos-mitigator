// SPDX-License-Identifier: GPL-2.0
// XDP program for caddy-ddos-mitigator: drops packets from jailed IPs
// at the NIC driver level before they reach the kernel network stack.
//
// Uses an LPM trie map for source IP lookup, supporting both IPv4 and IPv6.
// The map is maintained by the Go userspace program (xdp.go) which syncs
// the IP jail state into the BPF map.
//
// Compiled to eBPF bytecode via bpf2go (go generate).

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ─── BPF Map: Jailed IPs ───────────────────────────────────────────

// Key for LPM trie: prefix length + IP address (16 bytes for v4-mapped-v6).
struct lpm_key {
    __u32 prefixlen;
    __u8  addr[16];
};

// Map: jailed IPs. Managed by userspace. Value is a dummy byte (presence = jailed).
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key);
    __type(value, __u8);
    __uint(max_entries, 100000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} jail_map SEC(".maps");

// Counter map for observability: [0] = passed, [1] = dropped
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} stats_map SEC(".maps");

// ─── Helpers ────────────────────────────────────────────────────────

static __always_inline void count(int idx) {
    __u32 key = idx;
    __u64 *val = bpf_map_lookup_elem(&stats_map, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

// ─── XDP Program ────────────────────────────────────────────────────

SEC("xdp")
int xdp_ddos_drop(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct lpm_key key = {};
    key.prefixlen = 128; // full match (v4-mapped-v6 = /128)

    __u16 eth_proto = bpf_ntohs(eth->h_proto);

    if (eth_proto == ETH_P_IP) {
        // IPv4
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        // Map IPv4 src addr to v4-mapped-v6: ::ffff:a.b.c.d
        __builtin_memset(key.addr, 0, 10);
        key.addr[10] = 0xff;
        key.addr[11] = 0xff;
        __builtin_memcpy(&key.addr[12], &ip->saddr, 4);

    } else if (eth_proto == ETH_P_IPV6) {
        // IPv6
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;

        __builtin_memcpy(key.addr, &ip6->saddr, 16);

    } else {
        // Not IP traffic — pass through
        return XDP_PASS;
    }

    // Lookup source IP in jail map
    __u8 *jailed = bpf_map_lookup_elem(&jail_map, &key);
    if (jailed) {
        count(1); // dropped
        return XDP_DROP;
    }

    count(0); // passed
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
