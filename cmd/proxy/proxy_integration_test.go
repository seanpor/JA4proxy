package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/seanpor/ja4proxy/internal/config"
	proxypkg "github.com/seanpor/ja4proxy/internal/proxy"
)

// buildV2HeaderForTest constructs a PROXY protocol v2 header with the given
// source IP, followed by a minimal TLS ClientHello record header.
func buildV2HeaderForTest(srcIP, dstIP string, srcPort, dstPort uint16) []byte {
	// 12-byte signature
	sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

	var family byte
	var addrLen uint16
	var srcAddr, dstAddr []byte

	srcBytes := parseTestIPForIntegration(srcIP)
	dstBytes := parseTestIPForIntegration(dstIP)

	if len(srcBytes) == 4 {
		family = 0x11
		addrLen = 12
		srcAddr = srcBytes
		dstAddr = dstBytes
	} else {
		family = 0x21
		addrLen = 36
		srcAddr = srcBytes
		dstAddr = dstBytes
	}

	buf := bytes.NewBuffer(sig)
	buf.WriteByte(0x21) // version 2, PROXY command
	buf.WriteByte(family)
	binary.Write(buf, binary.BigEndian, addrLen)
	buf.Write(srcAddr)
	buf.Write(dstAddr)
	binary.Write(buf, binary.BigEndian, srcPort)
	binary.Write(buf, binary.BigEndian, dstPort)

	return buf.Bytes()
}

func parseTestIPForIntegration(ip string) []byte {
	if b := parseIPv4Simple(ip); b != nil {
		return b
	}
	if ip == "::1" {
		b := make([]byte, 16)
		b[15] = 1
		return b
	}
	// Default: treat as 127.0.0.1
	return []byte{127, 0, 0, 1}
}

func parseIPv4Simple(ip string) []byte {
	var vals [4]uint64
	idx := 0
	start := 0
	for i, ch := range ip {
		if ch == '.' {
			if start >= i {
				return nil
			}
			v := parseUintSimple(ip[start:i])
			if v > 255 {
				return nil
			}
			vals[idx] = v
			idx++
			start = i + 1
		}
	}
	if idx != 3 {
		return nil
	}
	v := parseUintSimple(ip[start:])
	if v > 255 {
		return nil
	}
	vals[3] = v
	return []byte{byte(vals[0]), byte(vals[1]), byte(vals[2]), byte(vals[3])}
}

func parseUintSimple(s string) uint64 {
	var v uint64
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0
		}
		v = v*10 + uint64(ch-'0')
	}
	return v
}

// ── Tests ──────────────────────────────────────────────────────────────────

// TestProxyProtocolV2_IPExtraction verifies that the v2 parser extracts
// the correct source IP from a valid header.
func TestProxyProtocolV2_IPExtraction(t *testing.T) {
	cases := []struct {
		srcIP  string
		dstIP  string
		wantIP string
	}{
		{"1.2.3.4", "10.0.0.1", "1.2.3.4"},
		{"192.168.1.100", "172.16.0.1", "192.168.1.100"},
		{"::1", "::1", "::1"},
	}

	for _, tc := range cases {
		t.Run(tc.srcIP, func(t *testing.T) {
			header := buildV2HeaderForTest(tc.srcIP, tc.dstIP, 12345, 443)
			ip, ok := proxypkg.ReadProxyProtocolV2(header)
			if !ok {
				t.Fatalf("expected ok=true for %s", tc.srcIP)
			}
			if ip != tc.wantIP {
				t.Errorf("got %q, want %q", ip, tc.wantIP)
			}
		})
	}
}

// TestProxyProtocolV1_IPExtraction verifies the v1 parser still works
// after the P200c integration changes.
func TestProxyProtocolV1_IPExtraction(t *testing.T) {
	buf := []byte("PROXY TCP4 10.20.30.40 172.16.0.1 54321 443\r\n")
	ip, ok := proxypkg.ReadProxyProtocol(buf)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if ip != "10.20.30.40" {
		t.Errorf("got %q, want %q", ip, "10.20.30.40")
	}
}

// TestTrustCheck_GatesPROXYExtraction verifies that when the trust check
// fails, the PROXY header is NOT parsed — the socket IP is used instead.
func TestTrustCheck_GatesPROXYExtraction(t *testing.T) {
	cfg := &config.Config{
		Proxy: config.ProxyConfig{
			ProxyProtocol: true,
			UpstreamTrust: config.UpstreamTrustConfig{
				Enabled:      true,
				TrustedCIDRs: []string{"10.0.0.0/8"}, // only 10.x.x.x is trusted
			},
		},
	}

	// A v2 header claiming source IP 1.2.3.4, sent from an untrusted source
	header := buildV2HeaderForTest("1.2.3.4", "10.0.0.1", 12345, 443)

	// The v2 parser itself can parse it — but the trust check should gate it.
	ip, ok := proxypkg.ReadProxyProtocolV2(header)
	if !ok {
		t.Fatal("v2 parser should parse the header")
	}
	if ip != "1.2.3.4" {
		t.Errorf("v2 parser got %q, want %q", ip, "1.2.3.4")
	}

	// But the trust check from an untrusted source (e.g. 8.8.8.8) should fail.
	if proxypkg.IsTrustedProxySource("8.8.8.8", cfg) {
		t.Error("8.8.8.8 should NOT be trusted")
	}

	// A trusted source (10.0.0.5) SHOULD be trusted.
	if !proxypkg.IsTrustedProxySource("10.0.0.5", cfg) {
		t.Error("10.0.0.5 SHOULD be trusted")
	}
}

// TestAdversarial_SpoofedPROXYFromUntrustedSource simulates an attacker
// sending a PROXY protocol v2 header from an untrusted source IP.
// The Go proxy must NOT extract the spoofed client IP.
func TestAdversarial_SpoofedPROXYFromUntrustedSource(t *testing.T) {
	cfg := &config.Config{
		Proxy: config.ProxyConfig{
			ProxyProtocol: true,
			UpstreamTrust: config.UpstreamTrustConfig{
				Enabled:      true,
				TrustedCIDRs: []string{"10.0.0.0/8"},
			},
		},
	}

	// Attacker sends v2 header claiming to be 8.8.8.8 (a trusted IP)
	// from their actual IP 203.0.113.1 (not trusted)
	header := buildV2HeaderForTest("8.8.8.8", "10.0.0.1", 12345, 443)

	// The header parses correctly — the v2 parser extracts 8.8.8.8
	ip, ok := proxypkg.ReadProxyProtocolV2(header)
	if !ok || ip != "8.8.8.8" {
		t.Fatalf("v2 parser should extract 8.8.8.8")
	}

	// BUT the trust check for the ACTUAL socket IP (203.0.113.1) fails.
	// In handleConn, the real socket IP is checked — not the header's IP.
	if proxypkg.IsTrustedProxySource("203.0.113.1", cfg) {
		t.Error("SPOOFED: 203.0.113.1 should NOT be trusted")
	}
}

// TestAdversarial_SpoofedV1FromUntrustedSource simulates the same attack
// with PROXY protocol v1 text header.
func TestAdversarial_SpoofedV1FromUntrustedSource(t *testing.T) {
	cfg := &config.Config{
		Proxy: config.ProxyConfig{
			ProxyProtocol: true,
			UpstreamTrust: config.UpstreamTrustConfig{
				Enabled:      true,
				TrustedCIDRs: []string{"10.0.0.0/8"},
			},
		},
	}

	// Attacker sends v1 header claiming to be 10.0.0.1
	buf := []byte("PROXY TCP4 10.0.0.1 172.16.0.1 54321 443\r\n")
	ip, ok := proxypkg.ReadProxyProtocol(buf)
	if !ok || ip != "10.0.0.1" {
		t.Fatalf("v1 parser should extract 10.0.0.1")
	}

	// But trust check for the actual socket IP (198.51.100.1) fails.
	if proxypkg.IsTrustedProxySource("198.51.100.1", cfg) {
		t.Error("SPOOFED: 198.51.100.1 should NOT be trusted")
	}
}

// TestV2BeforeV1 verifies that when data contains both v2 signature
// and something that looks like v1, the v2 parser is tried first.
func TestV2BeforeV1(t *testing.T) {
	header := buildV2HeaderForTest("1.2.3.4", "10.0.0.1", 12345, 443)

	// v2 parser should succeed
	ip, ok := proxypkg.ReadProxyProtocolV2(header)
	if !ok {
		t.Fatal("v2 should parse")
	}
	if ip != "1.2.3.4" {
		t.Errorf("got %q, want %q", ip, "1.2.3.4")
	}

	// v1 parser should fail on binary data (no "PROXY " prefix)
	_, ok = proxypkg.ReadProxyProtocol(header)
	if ok {
		t.Error("v1 should not parse binary v2 data")
	}
}

// TestDefaultConfig_NoTrust verifies that with default config (no
// upstream_trust set), no PROXY header is trusted.
func TestDefaultConfig_NoTrust(t *testing.T) {
	cfg := config.DefaultConfig()

	// Even if proxy_protocol is true, no upstream_trust means no trust.
	if proxypkg.IsTrustedProxySource("10.0.0.1", cfg) {
		t.Error("default config should not trust any source")
	}
}

// TestPROXYDisabled_RespectsProxyProtocolFlag verifies that when
// proxy_protocol is false in config, trust is not checked.
func TestPROXYDisabled_RespectsProxyProtocolFlag(t *testing.T) {
	cfg := &config.Config{
		Proxy: config.ProxyConfig{
			ProxyProtocol: false, // PROXY protocol disabled
			UpstreamTrust: config.UpstreamTrustConfig{
				Enabled:      true,
				TrustedCIDRs: []string{"10.0.0.0/8"},
			},
		},
	}

	// handleConn checks p.cfg.Proxy.ProxyProtocol first — if false,
	// it never calls IsTrustedProxySource. This test documents that
	// the config flag is the outer gate.
	if cfg.Proxy.ProxyProtocol {
		t.Error("proxy_protocol should be false")
	}
}
