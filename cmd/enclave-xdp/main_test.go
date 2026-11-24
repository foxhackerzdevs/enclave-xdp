package main

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"
)

func TestParseCIDRToLPM(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantPrefix uint32
		wantData   uint32
		wantErr    bool
	}{
		{
			name:       "Single IPv4 host without prefix",
			input:      "127.0.0.1",
			wantPrefix: 32,
			wantData:   binary.BigEndian.Uint32(net.ParseIP("127.0.0.1").To4()),
			wantErr:    false,
		},
		{
			name:       "Single IPv4 host with /32",
			input:      "10.0.0.50/32",
			wantPrefix: 32,
			wantData:   binary.BigEndian.Uint32(net.ParseIP("10.0.0.50").To4()),
			wantErr:    false,
		},
		{
			name:       "Class A /8 subnet",
			input:      "10.0.0.0/8",
			wantPrefix: 8,
			wantData:   binary.BigEndian.Uint32(net.ParseIP("10.0.0.0").To4()),
			wantErr:    false,
		},
		{
			name:       "Class B /12 subnet",
			input:      "172.16.0.0/12",
			wantPrefix: 12,
			wantData:   binary.BigEndian.Uint32(net.ParseIP("172.16.0.0").To4()),
			wantErr:    false,
		},
		{
			name:       "Class C /24 subnet",
			input:      "192.168.1.0/24",
			wantPrefix: 24,
			wantData:   binary.BigEndian.Uint32(net.ParseIP("192.168.1.0").To4()),
			wantErr:    false,
		},
		{
			name:       "Subnet with whitespace",
			input:      "  192.168.0.0/16  ",
			wantPrefix: 16,
			wantData:   binary.BigEndian.Uint32(net.ParseIP("192.168.0.0").To4()),
			wantErr:    false,
		},
		{
			name:    "Invalid IP string",
			input:   "not-an-ip",
			wantErr: true,
		},
		{
			name:    "Invalid prefix /33",
			input:   "10.0.0.0/33",
			wantErr: true,
		},
		{
			name:    "Empty string",
			input:   "  ",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCIDRToLPM(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseCIDRToLPM(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr {
				if got.PrefixLen != tt.wantPrefix {
					t.Errorf("PrefixLen = %d, want %d", got.PrefixLen, tt.wantPrefix)
				}
				if got.Data != tt.wantData {
					t.Errorf("Data = 0x%08x, want 0x%08x", got.Data, tt.wantData)
				}
			}
		})
	}
}

func TestIntToIP(t *testing.T) {
	// 192.168.1.10 in LittleEndian encoding
	val := uint32(192) | (uint32(168) << 8) | (uint32(1) << 16) | (uint32(10) << 24)
	got := intToIP(val)
	want := "192.168.1.10"
	if got != want {
		t.Errorf("intToIP() = %s, want %s", got, want)
	}
}

func TestFormatRoceOpcode(t *testing.T) {
	tests := []struct {
		opcode uint8
		want   string
	}{
		{0x00, "RC_SEND_FIRST (0x00)"},
		{0x06, "RC_RDMA_WRITE_FIRST (0x06)"},
		{0x0A, "RC_RDMA_WRITE_ONLY (0x0a)"},
		{0x0C, "RC_RDMA_READ_REQUEST (0x0c)"},
		{0x10, "RC_RDMA_READ_RESP_ONLY (0x10)"},
		{0x13, "RC_ATOMIC_CSWAP (0x13)"},
		{0x14, "RC_ATOMIC_FETCH_ADD (0x14)"},
		{0xfe, "UNKNOWN_ROCE_OP (0xfe)"},
	}

	for _, tt := range tests {
		got := formatRoceOpcode(tt.opcode)
		if got != tt.want {
			t.Errorf("formatRoceOpcode(0x%02x) = %q, want %q", tt.opcode, got, tt.want)
		}
	}
}

func TestJSONAlertSerialization(t *testing.T) {
	alert := JSONAlert{
		Timestamp:  "2026-11-24T21:00:00Z",
		Severity:   "HIGH",
		Type:       "ROCEV2_UNAUTHORIZED_RDMA_OPCODE",
		Action:     "XDP_DROP",
		SrcIP:      "10.0.1.20",
		DstIP:      "10.0.2.30",
		SrcPort:    12345,
		DstPort:    4791,
		RoceOpcode: "RC_RDMA_WRITE_ONLY (0x0a)",
		RocePkey:   "0x8001",
		Message:    "Unauthorized RDMA Write crossing tenant boundary",
	}

	b, err := json.Marshal(alert)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if parsed["severity"] != "HIGH" {
		t.Errorf("severity = %v, want HIGH", parsed["severity"])
	}
	if parsed["action"] != "XDP_DROP" {
		t.Errorf("action = %v, want XDP_DROP", parsed["action"])
	}
	if parsed["roce_opcode"] != "RC_RDMA_WRITE_ONLY (0x0a)" {
		t.Errorf("roce_opcode = %v, want RC_RDMA_WRITE_ONLY (0x0a)", parsed["roce_opcode"])
	}
}
