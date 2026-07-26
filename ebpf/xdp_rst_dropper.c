// SPDX-License-Identifier: GPL-2.0
//
// Aether-X XDP TCP RST Dropper — drops forged RST packets from Iranian DPI
// middleboxes directly at the NIC level, before the kernel TCP stack sees
// them. This prevents session disruption caused by SIAM / national filtering
// infrastructure injecting fake TCP resets.
//
// Compile:
//   clang -O2 -g -target bpf -Wall -c xdp_rst_dropper.c -o xdp_rst_dropper.o
//
// Attach (requires CAP_BPF + CAP_NET_ADMIN):
//   ip link set dev eth0 xdpgeneric obj xdp_rst_dropper.o sec xdp
//
// The hash map `dpi_sources` is populated from userspace (via the Rust loader
// or bpftool) with the IPv4 addresses of known DPI middleboxes.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

// Hash map: source IPv4 -> flag (1 = known DPI middlebox, drop RSTs from here).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);    // source IPv4 address (network byte order)
    __type(value, __u8);   // 1 = drop RST from this source
    __uint(max_entries, 4096);
} dpi_sources SEC(".maps");

// Stats: count of dropped RST packets (read from userspace for monitoring).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} rst_drop_count SEC(".maps");

// Parse Ethernet -> IPv4 -> TCP headers with verifier-safe bounds checks.
// Drop if TCP RST flag is set AND the source IP is in the dpi_sources map.
// Otherwise pass the packet through.
SEC("xdp")
int xdp_drop_forged_rst(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // --- Ethernet header ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only IPv4.
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // --- IPv4 header ---
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // Only TCP.
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Verify IP header length (IHL field, 32-bit words).
    __u32 ihl = (__u32)iph->ihl * 4;
    if (ihl < sizeof(*iph))
        return XDP_PASS;

    // --- TCP header ---
    // Compute TCP start with overflow-safe pointer arithmetic.
    char *ip_start = (char *)iph;
    if (ip_start + ihl > (char *)data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (struct tcphdr *)(ip_start + ihl);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // --- RST check ---
    if (!tcp->rst)
        return XDP_PASS;

    // --- DPI source lookup ---
    __u32 src_ip = iph->saddr;
    __u8 *flag = bpf_map_lookup_elem(&dpi_sources, &src_ip);
    if (flag && *flag == 1) {
        // Forged RST from known DPI middlebox — drop at NIC level.
        __u32 key = 0;
        __u64 *count = bpf_map_lookup_elem(&rst_drop_count, &key);
        if (count)
            __sync_fetch_and_add(count, 1);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
