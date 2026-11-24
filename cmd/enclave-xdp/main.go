package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Ring buffer event matches the C struct alert_event
type AlertEvent struct {
	SrcIP      uint32
	DstIP      uint32
	SrcPort    uint16
	DstPort    uint16
	EventType  uint8
	RoceOpcode uint8
	RocePkey   uint16
}

// BPF LPM Trie key structure (4 bytes prefixlen + 4 bytes IPv4 data)
type BpfLpmKey struct {
	PrefixLen uint32
	Data      uint32
}

type JSONAlert struct {
	Timestamp  string `json:"timestamp"`
	Severity   string `json:"severity"`
	Type       string `json:"type"`
	Action     string `json:"action"`
	SrcIP      string `json:"src_ip"`
	DstIP      string `json:"dst_ip"`
	SrcPort    uint16 `json:"src_port,omitempty"`
	DstPort    uint16 `json:"dst_port,omitempty"`
	RoceOpcode string `json:"roce_opcode,omitempty"`
	RocePkey   string `json:"roce_pkey,omitempty"`
	Message    string `json:"message"`
}

// Global telemetry counters for Prometheus scraping
var (
	roceAnomaliesTotal uint64
	egressDropsTotal   uint64
	totalAlerts        uint64
)

func intToIP(ip uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, ip)
	return net.IP(b).String()
}

func parseCIDRToLPM(cidrStr string) (BpfLpmKey, error) {
	s := strings.TrimSpace(cidrStr)
	if s == "" {
		return BpfLpmKey{}, errors.New("empty CIDR entry")
	}
	if !strings.Contains(s, "/") {
		s += "/32"
	}

	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return BpfLpmKey{}, fmt.Errorf("invalid CIDR %q: %w", s, err)
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return BpfLpmKey{}, fmt.Errorf("only IPv4 is supported, got %q", s)
	}

	ones, _ := ipnet.Mask.Size()
	// Network byte order (big endian) directly aligns with BPF packet lookup
	data := binary.BigEndian.Uint32(ipv4)

	return BpfLpmKey{
		PrefixLen: uint32(ones),
		Data:      data,
	}, nil
}

func formatRoceOpcode(opcode uint8) string {
	switch opcode {
	case 0x00:
		return "RC_SEND_FIRST (0x00)"
	case 0x01:
		return "RC_SEND_MIDDLE (0x01)"
	case 0x02:
		return "RC_SEND_LAST (0x02)"
	case 0x03:
		return "RC_SEND_LAST_IMM (0x03)"
	case 0x04:
		return "RC_SEND_ONLY (0x04)"
	case 0x05:
		return "RC_SEND_ONLY_IMM (0x05)"
	case 0x06:
		return "RC_RDMA_WRITE_FIRST (0x06)"
	case 0x07:
		return "RC_RDMA_WRITE_MIDDLE (0x07)"
	case 0x08:
		return "RC_RDMA_WRITE_LAST (0x08)"
	case 0x09:
		return "RC_RDMA_WRITE_LAST_IMM (0x09)"
	case 0x0A:
		return "RC_RDMA_WRITE_ONLY (0x0a)"
	case 0x0B:
		return "RC_RDMA_WRITE_ONLY_IMM (0x0b)"
	case 0x0C:
		return "RC_RDMA_READ_REQUEST (0x0c)"
	case 0x0D:
		return "RC_RDMA_READ_RESP_FIRST (0x0d)"
	case 0x0E:
		return "RC_RDMA_READ_RESP_MIDDLE (0x0e)"
	case 0x0F:
		return "RC_RDMA_READ_RESP_LAST (0x0f)"
	case 0x10:
		return "RC_RDMA_READ_RESP_ONLY (0x10)"
	case 0x11:
		return "RC_ACK (0x11)"
	case 0x12:
		return "RC_ATOMIC_ACK (0x12)"
	case 0x13:
		return "RC_ATOMIC_CSWAP (0x13)"
	case 0x14:
		return "RC_ATOMIC_FETCH_ADD (0x14)"
	default:
		return fmt.Sprintf("UNKNOWN_ROCE_OP (0x%02x)", opcode)
	}
}

func startMetricsServer(addr string) {
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# HELP enclave_xdp_alerts_total Total security alerts emitted\n")
		fmt.Fprintf(w, "# TYPE enclave_xdp_alerts_total counter\n")
		fmt.Fprintf(w, "enclave_xdp_alerts_total %d\n", atomic.LoadUint64(&totalAlerts))

		fmt.Fprintf(w, "# HELP enclave_xdp_roce_anomalies_total Total unauthorized RoCEv2 RDMA anomalies dropped\n")
		fmt.Fprintf(w, "# TYPE enclave_xdp_roce_anomalies_total counter\n")
		fmt.Fprintf(w, "enclave_xdp_roce_anomalies_total %d\n", atomic.LoadUint64(&roceAnomaliesTotal))

		fmt.Fprintf(w, "# HELP enclave_xdp_egress_drops_total Total unauthorized pod external egress drops\n")
		fmt.Fprintf(w, "# TYPE enclave_xdp_egress_drops_total counter\n")
		fmt.Fprintf(w, "enclave_xdp_egress_drops_total %d\n", atomic.LoadUint64(&egressDropsTotal))
	})

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	log.Printf("[+] Prometheus telemetry & health server listening on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("[!] Metrics server error: %v", err)
	}
}

func main() {
	ifaceName := flag.String("iface", "eth0", "Network interface to attach XDP probe (e.g. eth0, enp1s0f0)")
	objPath := flag.String("obj", "bpf/enclave_xdp.o", "Compiled eBPF ELF object path")
	allowList := flag.String("allow", "127.0.0.1/32,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16", "Comma-separated allowlisted CIDRs/IPs for KMS, registry, and cluster fabric")
	metricsAddr := flag.String("metrics-addr", "", "Optional HTTP address for Prometheus metrics (e.g. :9090)")
	showVersion := flag.Bool("version", false, "Print enclave-xdp version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("enclave-xdp v0.1.0 — Fox Hackerz Layer 3 RoCEv2 & Egress Guard")
		return
	}

	// Remove memlock limits for eBPF maps
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("[~] Notice: remove memlock limit: %v (continuing)", err)
	}

	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("[!] Network interface %q not found: %v", *ifaceName, err)
	}

	spec, err := ebpf.LoadCollectionSpec(*objPath)
	if err != nil {
		log.Fatalf("[!] Failed loading eBPF spec from %s: %v", *objPath, err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("[!] Failed creating eBPF collection: %v", err)
	}
	defer coll.Close()

	// Populate LPM Trie CIDR map
	allowMap, ok := coll.Maps["allowed_egress_cidrs"]
	if !ok {
		log.Fatalf("[!] Map 'allowed_egress_cidrs' not found in eBPF ELF")
	}

	var loadedCIDRs int
	for _, entry := range strings.Split(*allowList, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		lpmKey, err := parseCIDRToLPM(entry)
		if err != nil {
			log.Fatalf("[!] Invalid allowlist entry %q: %v", entry, err)
		}

		var val uint8 = 1
		if err := allowMap.Put(lpmKey, val); err != nil {
			log.Fatalf("[!] Failed inserting LPM CIDR %s into eBPF map: %v", entry, err)
		}
		loadedCIDRs++
	}
	log.Printf("[+] Initialized LPM Trie with %d authorized CIDRs/IPs", loadedCIDRs)

	// Attach XDP Program to Network Interface
	xdpProg, ok := coll.Programs["enclave_xdp_guard"]
	if !ok {
		log.Fatalf("[!] Program 'enclave_xdp_guard' not found in eBPF ELF")
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   xdpProg,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("[!] Failed attaching XDP program to %s: %v", *ifaceName, err)
	}
	defer xdpLink.Close()

	// Open Ring Buffer Reader
	eventsMap, ok := coll.Maps["events"]
	if !ok {
		log.Fatalf("[!] Map 'events' not found in eBPF ELF")
	}

	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		log.Fatalf("[!] Failed opening ring buffer reader: %v", err)
	}
	defer rd.Close()

	if *metricsAddr != "" {
		go startMetricsServer(*metricsAddr)
	}

	log.Printf("[+] enclave-xdp active on %s (Interface Index: %d, Driver Level)", *ifaceName, iface.Index)
	log.Printf("[+] Monitoring RoCEv2 (UDP/4791) BTH Opcode boundaries & Enforcing Egress CIDRs")

	// Graceful termination handling
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("[~] Shutdown signal received, detaching XDP and flushing ringbuf...")
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			continue
		}

		var ev AlertEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			log.Printf("[!] Error decoding alert event: %v", err)
			continue
		}

		atomic.AddUint64(&totalAlerts, 1)

		var alertType string
		var opcodeStr string
		var pkeyStr string
		var message string

		if ev.EventType == 1 {
			atomic.AddUint64(&roceAnomaliesTotal, 1)
			alertType = "ROCEV2_UNAUTHORIZED_RDMA_OPCODE"
			opcodeStr = formatRoceOpcode(ev.RoceOpcode)
			pkeyStr = fmt.Sprintf("0x%04x", ev.RocePkey)
			message = fmt.Sprintf("Unauthorized RoCEv2 RDMA operation (%s) with PKey %s crossing fabric partition boundary", opcodeStr, pkeyStr)
		} else {
			atomic.AddUint64(&egressDropsTotal, 1)
			alertType = "UNAUTHORIZED_EGRESS_DROP"
			message = fmt.Sprintf("Unauthorized pod egress attempt to non-allowlisted external destination %s", intToIP(ev.DstIP))
		}

		alert := JSONAlert{
			Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
			Severity:   "HIGH",
			Type:       alertType,
			Action:     "XDP_DROP",
			SrcIP:      intToIP(ev.SrcIP),
			DstIP:      intToIP(ev.DstIP),
			SrcPort:    ev.SrcPort,
			DstPort:    ev.DstPort,
			RoceOpcode: opcodeStr,
			RocePkey:   pkeyStr,
			Message:    message,
		}

		out, err := json.Marshal(alert)
		if err == nil {
			fmt.Println(string(out))
		}
	}

	log.Println("[+] enclave-xdp successfully stopped and detached.")
}
