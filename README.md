# `enclave-xdp`

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/foxhackerzdevs/enclave-xdp)](https://goreportcard.com/report/github.com/foxhackerzdevs/enclave-xdp)
[![eBPF: XDP](https://img.shields.io/badge/eBPF-XDP-orange.svg)](https://ebpf.io/)
[![Layer 3](https://img.shields.io/badge/Architecture-Layer%203%20Fabric%20Guard-brightgreen.svg)](#threat-model-fit)

**Zero-copy eBPF/XDP pod egress guard and RoCEv2 (RDMA over Converged Ethernet) anomaly monitor for sovereign AI factories and multi-tenant GPU enclaves.**

Built by [Fox Hackerz](https://github.com/foxhackerzdevs) as the **Layer 3 network fabric defense** companion to [`stverify`](https://github.com/foxhackerzdevs/stverify) at Layer 4.

---

## Why `enclave-xdp`?

In multi-tenant sovereign AI factories—such as multi-thousand-GPU NVIDIA B300 clusters—tenants share bare-metal physical InfiniBand and RoCEv2 network fabrics. Because RDMA uses **kernel-bypass** (zero-copy OS bypass) to achieve microsecond tensor-parallel latency, conventional Linux userspace intrusion detection agents, `iptables`, and socket monitors are completely blind to east-west RDMA traffic.

If a rogue container or compromised inference workload attempts to:
1. **Exfiltrate model weights or tensor data** to unauthorized external endpoints, or
2. **Inject or read unauthorized RDMA WRITE / READ opcodes** across tenant fabric boundaries,

`enclave-xdp` intercepts the packet at the driver layer (**XDP**) before it touches the kernel networking stack, verifies tenant CIDR allowlists via an in-kernel **LPM Trie**, and drops unauthorized traffic (`XDP_DROP`) while streaming security events to userspace via a zero-copy **Ring Buffer**.

---

## Threat Model Fit: Four-Layer Zero-Trust AI Architecture

`enclave-xdp` bridges the Layer 3 kernel-bypass telemetry blind spot in the defense-in-depth architecture detailed in:  
📖 [**Zero-Trust Silicon to VRAM: Securing Multi-Tenant Sovereign AI Factories**](https://abhrankan.duckdns.org/writing/zero-trust-silicon-to-vram/)

| Layer | Security Perimeter | Implementation / Tool |
| :--- | :--- | :--- |
| **Layer 1** | **Silicon Root of Trust & Boot** | NVIDIA GPU Silicon RoT + SPDM Remote Attestation |
| **Layer 2** | **Memory & Interconnect** | CPU-to-GPU TEE Boundary + 5th-Gen NVLink Line-Rate Encryption |
| **Layer 3** | **Fabric & Network Boundary** | **`enclave-xdp`** *(XDP Driver Hook + RoCEv2 BTH Opcode & Egress LPM Trie)* |
| **Layer 4** | **Model Weight Integrity** | [**`stverify`**](https://github.com/foxhackerzdevs/stverify) *(Pre-Load Safetensors Ed25519 Verification)* |

---

## Architecture

```text
                  Incoming / Outgoing Wire Traffic
                                 │
                                 ▼
                     Physical NIC / Driver Level
                                 │
                                 ▼
                 ┌───────────────────────────────┐
                 │       enclave_xdp_guard       │
                 │   (eBPF XDP In-Kernel Hook)   │
                 └───────────────┬───────────────┘
                                 │
        ┌────────────────────────┴────────────────────────┐
        ▼                                                 ▼
[RoCEv2: UDP/4791]                               [Non-RoCE Traffic]
Parse BTH Header (Opcode, PKey)                  Check Destination IP
Check RDMA Read/Write/Atomic Opcodes                      │
        │                                                 ▼
        ▼                                      In-Kernel LPM Trie Match
Tenant CIDR Boundary Check?                   (allowed_egress_cidrs)
  ├── Yes ──> XDP_PASS (Line-rate zero-copy)      ├── Match ──> XDP_PASS
  └── No  ──> XDP_DROP + Emit Ringbuf Alert       └── Miss  ──> XDP_DROP + Emit Ringbuf Alert
                                 │
                                 ▼
                   BPF_MAP_TYPE_RINGBUF (256 KB)
                                 │
                                 ▼
                      Go Userspace Consumer
             (cilium/ebpf, zero-cgo, async reader)
                                 │
                 ┌───────────────┴───────────────┐
                 ▼                               ▼
       JSON Security Alerts             Prometheus Metrics
         (stdout / SIEM)                 (:9090/metrics)
```

---

## Key Features

- **Driver-Level XDP Interception**: Runs before socket allocation and Linux kernel TCP/IP stack overhead, dropping malicious packets with sub-microsecond latency.
- **RoCEv2 BTH Protocol Inspection**: Dissects InfiniBand Base Transport Headers (BTH) on UDP port `4791`, extracting opcodes and 16-bit Partition Keys (`P_Key`).
- **RDMA Attack Detection**: Flags and drops raw RDMA Write (`0x06..0x0B`), RDMA Read (`0x0C..0x10`), and Atomic (`0x13..0x14`) operations crossing unauthorized tenant IP boundaries.
- **LPM Trie CIDR Filtering (`BPF_MAP_TYPE_LPM_TRIE`)**: In-kernel longest-prefix match allowlist supporting entire VPC and cluster subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and `/32` host IPs without linear lookups.
- **Zero-Copy Ring Buffer**: Emits compact 16-byte alert structs to userspace only when policy violations occur, preserving 100% throughput for authorized workloads.
- **Pure Go Userspace CLI**: Powered by [`cilium/ebpf`](https://github.com/cilium/ebpf), requiring zero CGo runtime overhead and zero host C library dependencies.
- **SIEM & Prometheus Ready**: Streams structured JSON security events to stdout (for FluentBit, Vector, Datadog) and serves Prometheus counters on `/metrics`.

---

## Monitored RoCEv2 Opcodes

| Opcode Range | IB Transport / Type | Risk / Threat Mitigated |
| :--- | :--- | :--- |
| `0x06 - 0x09` | **RC RDMA WRITE (First / Middle / Last / Imm)** | Unauthorized memory write into remote tenant GPU memory |
| `0x0A - 0x0B` | **RC RDMA WRITE ONLY / ONLY IMM** | Raw zero-copy weight or activation overwriting |
| `0x0C` | **RC RDMA READ REQUEST** | Unauthorized exfiltration of remote model weights / KV cache |
| `0x0D - 0x10` | **RC RDMA READ RESPONSE (First / Last / Only)** | Plaintext tenant tensor data in-flight over unauthorized routes |
| `0x13 - 0x14` | **RC ATOMIC (Compare & Swap / Fetch & Add)** | Hardware-level memory state manipulation across enclaves |

---

## Installation & Building

### Prerequisites

- Linux Kernel 5.8+ (kernel supporting `BPF_MAP_TYPE_RINGBUF` and `BPF_MAP_TYPE_LPM_TRIE`)
- `clang` & `llvm` 11+
- `libbpf-dev`
- `go` 1.22+

### 1. Clone & Build

```bash
git clone https://github.com/foxhackerzdevs/enclave-xdp.git
cd enclave-xdp

# Compile eBPF C probe and Go userspace binary
make all
```

### 2. Run Locally

```bash
# Attach to primary interface and allow KMS, internal registry, and cluster subnets
sudo ./enclave-xdp \
  -iface eth0 \
  -obj bpf/enclave_xdp.o \
  -allow "127.0.0.1/32,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16" \
  -metrics-addr :9090
```

---

## CLI Options

```text
Usage of enclave-xdp:
  -allow string
        Comma-separated allowlisted CIDRs/IPs for KMS, registry, and cluster fabric 
        (default "127.0.0.1/32,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
  -iface string
        Network interface to attach XDP probe (e.g. eth0, enp1s0f0, bond0) (default "eth0")
  -metrics-addr string
        Optional HTTP address for Prometheus metrics (e.g. :9090)
  -obj string
        Compiled eBPF ELF object path (default "bpf/enclave_xdp.o")
  -version
        Print enclave-xdp version and exit
```

---

## JSON Alert Specification

When an anomaly or unauthorized egress packet is dropped, `enclave-xdp` outputs a single-line JSON log to stdout:

### Example: RoCEv2 Cross-Tenant RDMA WRITE Dropped
```json
{
  "timestamp": "2026-11-24T21:15:32.184912000Z",
  "severity": "HIGH",
  "type": "ROCEV2_UNAUTHORIZED_RDMA_OPCODE",
  "action": "XDP_DROP",
  "src_ip": "10.244.3.45",
  "dst_ip": "10.244.8.12",
  "src_port": 54210,
  "dst_port": 4791,
  "roce_opcode": "RC_RDMA_WRITE_ONLY (0x0a)",
  "roce_pkey": "0x8001",
  "message": "Unauthorized RoCEv2 RDMA operation (RC_RDMA_WRITE_ONLY (0x0a)) with PKey 0x8001 crossing fabric partition boundary"
}
```

### Example: Pod External Exfiltration Attempt Dropped
```json
{
  "timestamp": "2026-11-24T21:16:05.891230000Z",
  "severity": "HIGH",
  "type": "UNAUTHORIZED_EGRESS_DROP",
  "action": "XDP_DROP",
  "src_ip": "10.244.3.45",
  "dst_ip": "198.51.100.24",
  "src_port": 49202,
  "dst_port": 443,
  "message": "Unauthorized pod egress attempt to non-allowlisted external destination 198.51.100.24"
}
```

---

## Kubernetes DaemonSet Deployment

Deploy `enclave-xdp` as a privileged DaemonSet across all GPU nodes:

```bash
kubectl apply -f deploy/k8s-enclave-xdp-daemonset.yaml
```

Combined with [`stverify`](https://github.com/foxhackerzdevs/stverify), your confidential GPU nodes achieve end-to-end enforcement:
- **`enclave-xdp` (Layer 3 DaemonSet)**: Runs continuously in the background on the host network, dropping unauthorized RDMA opcodes and blocking rogue egress.
- **`stverify` (Layer 4 InitContainer)**: Blocks container startup until all `.safetensors` model weights verify cryptographically before entering VRAM.

---

## Repository Structure

```text
enclave-xdp/
├── bpf/
│   ├── headers/bpf/          # Standard libbpf helper and endian definitions
│   └── enclave_xdp.c         # XDP C kernel probe: RoCEv2 BTH parser & LPM Trie
├── cmd/
│   └── enclave-xdp/
│       ├── main.go           # Cilium/ebpf loader, ringbuf consumer, JSON/Prometheus server
│       └── main_test.go      # Unit tests for LPM CIDR parsing and RoCEv2 decoding
├── deploy/
│   └── k8s-enclave-xdp-daemonset.yaml # Production Kubernetes DaemonSet manifest
├── Dockerfile                # Multi-stage container build
├── Makefile                  # Build and deployment automation
├── go.mod                    # Go module definition
├── go.sum                    # Checksums
├── LICENSE                   # MIT License
└── README.md                 # Technical architecture documentation
```

---

## License

MIT License — see [LICENSE](./LICENSE) for details. Built by [Fox Hackerz](https://github.com/foxhackerzdevs).
