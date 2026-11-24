// SPDX-License-Identifier: MIT
// enclave-xdp: Zero-Copy eBPF/XDP Pod Egress & RoCEv2 Anomaly Monitor
// Built for Fox Hackerz Sovereign AI & Confidential Computing clusters

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ROCE_V2_PORT          4791
#define EVENT_ROCE_ANOMALY    1
#define EVENT_EGRESS_BLOCK    2

// RoCEv2 InfiniBand BTH Opcode definitions
#define BTH_OP_RDMA_WRITE_FIRST     0x06
#define BTH_OP_RDMA_WRITE_ONLY      0x0A
#define BTH_OP_RDMA_WRITE_ONLY_IMM  0x0B
#define BTH_OP_RDMA_READ_REQ        0x0C
#define BTH_OP_RDMA_READ_RESP_ONLY  0x10
#define BTH_OP_ATOMIC_CSWAP         0x13
#define BTH_OP_ATOMIC_FADD          0x14

// Ring buffer alert event (16 bytes, strictly 32-bit/64-bit aligned)
struct alert_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  event_type;
    __u8  roce_opcode;
    __u16 roce_pkey;
};

// Ensure BTF type collector preserves struct alert_event for bpf2go / userspace loaders
struct alert_event unused_alert_event __attribute__((unused));

// Key definition for Longest Prefix Match (LPM) Trie IPv4 lookups
struct bpf_lpm_trie_key {
    __u32 prefixlen;
    __u32 data; // Network byte order IPv4 address
};

// LPM Trie map for allowlisted cluster, KMS, and authorized tenant CIDRs
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 2048);
    __type(key, struct bpf_lpm_trie_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} allowed_egress_cidrs SEC(".maps");

// Zero-copy ring buffer for low-overhead security alert telemetry
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB buffer
} events SEC(".maps");

static __always_inline void emit_alert(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport,
                                       __u8 type, __u8 opcode, __u16 pkey) {
    struct alert_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    e->src_ip = saddr;
    e->dst_ip = daddr;
    e->src_port = sport;
    e->dst_port = dport;
    e->event_type = type;
    e->roce_opcode = opcode;
    e->roce_pkey = pkey;

    bpf_ringbuf_submit(e, 0);
}

static __always_inline int is_ip_allowed(__u32 ip) {
    struct bpf_lpm_trie_key key;
    key.prefixlen = 32;
    key.data = ip;

    __u8 *val = bpf_map_lookup_elem(&allowed_egress_cidrs, &key);
    return val != 0;
}

SEC("xdp")
int enclave_xdp_guard(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // 1. Boundary check: Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Ignore non-IPv4 frames at wire speed
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // 2. Boundary check: IPv4 Base Header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Dynamic inner IHL bounds check
    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    void *l4_header = (void *)ip + ip_hdr_len;

    // 3. Inspect RoCEv2 east-west fabric traffic (UDP/4791)
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4_header;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        if (udp->dest == __constant_htons(ROCE_V2_PORT)) {
            // InfiniBand Base Transport Header (BTH) starts immediately after UDP header
            __u8 *bth = (__u8 *)(udp + 1);
            if ((void *)(bth + 12) > data_end)
                return XDP_DROP; // Truncated RoCEv2 frame

            __u8 opcode = bth[0];
            __u16 pkey = __constant_ntohs(*(__u16 *)(bth + 2));

            // Detect raw RDMA Write, Read, or Atomic operations crossing unauthorized boundaries
            // (Opcodes 0x06..0x14 cover RC RDMA Write/Read/Atomic variants)
            if ((opcode >= BTH_OP_RDMA_WRITE_FIRST && opcode <= BTH_OP_RDMA_READ_RESP_ONLY) ||
                opcode == BTH_OP_ATOMIC_CSWAP || opcode == BTH_OP_ATOMIC_FADD) {

                // Both source and destination endpoints must belong to allowed tenant CIDRs
                if (!is_ip_allowed(ip->saddr) || !is_ip_allowed(ip->daddr)) {
                    emit_alert(ip->saddr, ip->daddr, __constant_ntohs(udp->source),
                               ROCE_V2_PORT, EVENT_ROCE_ANOMALY, opcode, pkey);
                    return XDP_DROP; // Drop unauthorized cross-tenant RDMA injection / exfiltration
                }
            }

            // Normal authorized line-rate RDMA traffic passes without kernel overhead
            return XDP_PASS;
        }
    }

    // 4. Enforce strict egress allowlist on non-RoCE traffic from inference enclaves
    if (!is_ip_allowed(ip->daddr)) {
        __u16 sport = 0;
        __u16 dport = 0;

        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = l4_header;
            if ((void *)(udp + 1) <= data_end) {
                sport = __constant_ntohs(udp->source);
                dport = __constant_ntohs(udp->dest);
            }
        }

        emit_alert(ip->saddr, ip->daddr, sport, dport, EVENT_EGRESS_BLOCK, 0, 0);
        return XDP_DROP; // Block unauthorized external egress
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "MIT";
