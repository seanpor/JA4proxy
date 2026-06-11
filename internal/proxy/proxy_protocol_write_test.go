package proxy

import (
	"bytes"
	"net"
	"testing"
)

func TestBuildBackendProxyHeaderV1(t *testing.T) {
	tests := []struct {
		name         string
		src, dst     string
		sport, dport int
		want         string
	}{
		{"ipv4", "1.2.3.4", "5.6.7.8", 1111, 443, "PROXY TCP4 1.2.3.4 5.6.7.8 1111 443\r\n"},
		{"ipv6", "2001:db8::1", "2001:db8::2", 4000, 443, "PROXY TCP6 2001:db8::1 2001:db8::2 4000 443\r\n"},
		{"mixed family -> unknown", "1.2.3.4", "2001:db8::2", 80, 443, "PROXY UNKNOWN\r\n"},
		{"bad port -> unknown", "1.2.3.4", "5.6.7.8", 70000, 443, "PROXY UNKNOWN\r\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildBackendProxyHeader(1, net.ParseIP(tt.src), tt.sport, net.ParseIP(tt.dst), tt.dport)
			if string(got) != tt.want {
				t.Fatalf("v1 header = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildBackendProxyHeaderV2IPv4(t *testing.T) {
	got := BuildBackendProxyHeader(2, net.ParseIP("1.2.3.4"), 0x0457, net.ParseIP("5.6.7.8"), 443)
	if !bytes.Equal(got[:12], proxyV2Signature) {
		t.Fatalf("missing v2 signature: %x", got[:12])
	}
	if len(got) != 28 { // sig(12)+ver/cmd(1)+fam(1)+len(2)+addrs(8)+ports(4)
		t.Fatalf("v2 ipv4 len = %d, want 28", len(got))
	}
	if got[12] != 0x21 || got[13] != 0x11 {
		t.Fatalf("v2 ver/cmd/family = %x %x, want 21 11", got[12], got[13])
	}
	if got[14] != 0x00 || got[15] != 0x0C {
		t.Fatalf("v2 length field = %x %x, want 00 0C", got[14], got[15])
	}
	if !bytes.Equal(got[16:20], []byte{1, 2, 3, 4}) || !bytes.Equal(got[20:24], []byte{5, 6, 7, 8}) {
		t.Fatalf("v2 addresses wrong: src=%x dst=%x", got[16:20], got[20:24])
	}
	if got[24] != 0x04 || got[25] != 0x57 || got[26] != 0x01 || got[27] != 0xBB {
		t.Fatalf("v2 ports wrong: %x", got[24:28])
	}
}

func TestBuildBackendProxyHeaderV2LocalFallback(t *testing.T) {
	// Mixed family -> cannot represent -> LOCAL command, AF_UNSPEC, zero len.
	got := BuildBackendProxyHeader(2, net.ParseIP("1.2.3.4"), 80, net.ParseIP("2001:db8::2"), 443)
	if !bytes.Equal(got[:12], proxyV2Signature) {
		t.Fatalf("missing v2 signature")
	}
	if len(got) != 16 || got[12] != 0x20 || got[13] != 0x00 || got[14] != 0x00 || got[15] != 0x00 {
		t.Fatalf("v2 LOCAL fallback wrong: len=%d hdr=%x", len(got), got[12:16])
	}
}
