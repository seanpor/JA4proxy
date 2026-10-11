package proxy

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestProxyProtocolV1_LineLengthBound(t *testing.T) {
	// RFC / HAProxy spec 2.1: line must not exceed 107 characters.
	// Input with > 107 chars before CRLF must be rejected.
	padding := strings.Repeat(" ", 100)
	buf := []byte("PROXY TCP4 " + padding + "192.168.1.1 10.0.0.1 54321 443\r\n")
	_, ok := ReadProxyProtocol(buf)
	if ok {
		t.Error("expected ReadProxyProtocol to reject header exceeding 107 bytes")
	}
}

func TestProxyProtocolV1_InvalidTransportToken(t *testing.T) {
	// Must reject transport protocols other than TCP4 and TCP6
	buf := []byte("PROXY BOGUS 192.168.1.1 10.0.0.1 54321 443\r\n")
	_, ok := ReadProxyProtocol(buf)
	if ok {
		t.Error("expected ReadProxyProtocol to reject invalid transport token 'BOGUS'")
	}
}

func TestProxyProtocolV1_PortBounds(t *testing.T) {
	// Port > 65535 or non-numeric must be rejected
	buf := []byte("PROXY TCP4 192.168.1.1 10.0.0.1 70000 443\r\n")
	_, ok := ReadProxyProtocol(buf)
	if ok {
		t.Error("expected ReadProxyProtocol to reject port out of range (70000)")
	}

	buf2 := []byte("PROXY TCP4 192.168.1.1 10.0.0.1 notaport 443\r\n")
	_, ok2 := ReadProxyProtocol(buf2)
	if ok2 {
		t.Error("expected ReadProxyProtocol to reject non-numeric port")
	}
}

func TestProxyProtocolV2_LOCAL_Command_DiscardHeader(t *testing.T) {
	// PROXY v2 LOCAL command (0x20):
	// HAProxy spec 2.2: Receiver MUST discard the header and use real socket addresses.
	// It must return ok=true, headerLen=16, clientIP="" so the caller can advance
	// past the header without dropping the connection under TLS lockdown.
	header := make([]byte, 16)
	copy(header[:12], v2Signature)
	header[12] = 0x20 // ver 2, command LOCAL (0x00)
	header[13] = 0x00 // AF_UNSPEC
	header[14] = 0x00 // addrLen = 0
	header[15] = 0x00

	clientIP, ok, hdrLen := ReadProxyProtocolV2WithLength(header)
	if !ok {
		t.Fatal("expected ok=true for LOCAL command so header can be stripped")
	}
	if hdrLen != 16 {
		t.Errorf("expected hdrLen=16, got %d", hdrLen)
	}
	if clientIP != "" {
		t.Errorf("expected empty clientIP for LOCAL command, got %q", clientIP)
	}
}

func TestProxyProtocolV2_ExtendedTLVs(t *testing.T) {
	// PROXY v2 with TLVs exceeding 256 bytes (e.g. AWS NLB / HAProxy SSL client cert metadata).
	// Address block: 12 bytes (IPv4 src+dst+ports) + 300 bytes TLVs = 312 bytes.
	addrLen := 12 + 300
	buf := make([]byte, 16+addrLen)
	copy(buf[:12], v2Signature)
	buf[12] = 0x21 // ver 2, PROXY
	buf[13] = 0x11 // TCPv4
	binary.BigEndian.PutUint16(buf[14:16], uint16(addrLen))

	// Src IP: 198.51.100.1, Dst IP: 10.0.0.1
	copy(buf[16:20], []byte{198, 51, 100, 1})
	copy(buf[20:24], []byte{10, 0, 0, 1})
	binary.BigEndian.PutUint16(buf[24:26], 12345)
	binary.BigEndian.PutUint16(buf[26:28], 443)

	// Fill remaining 300 bytes with dummy TLVs
	for i := 28; i < len(buf); i++ {
		buf[i] = 0xAA
	}

	ip, ok, hdrLen := ReadProxyProtocolV2WithLength(buf)
	if !ok {
		t.Fatal("expected ok=true for valid PROXY v2 header with TLVs > 256 bytes")
	}
	if ip != "198.51.100.1" {
		t.Errorf("expected ip '198.51.100.1', got %q", ip)
	}
	if hdrLen != 16+addrLen {
		t.Errorf("expected hdrLen=%d, got %d", 16+addrLen, hdrLen)
	}
}

func TestIsTrustedIP_IPv4MappedIPv6(t *testing.T) {
	// IPv4-mapped IPv6 address ::ffff:10.0.0.1 matched against IPv4 CIDR 10.0.0.0/8
	if !IsTrustedProxySourceCIDRs("::ffff:10.0.0.1", []string{"10.0.0.0/8"}) {
		t.Error("expected ::ffff:10.0.0.1 to match 10.0.0.0/8")
	}

	// IPv4 10.0.0.1 matched against IPv6 mapped CIDR ::ffff:10.0.0.0/104
	if !IsTrustedProxySourceCIDRs("10.0.0.1", []string{"::ffff:10.0.0.0/104"}) {
		t.Error("expected 10.0.0.1 to match ::ffff:10.0.0.0/104")
	}

	// Zone identifier fe80::1%eth0 stripped and matched against fe80::/10
	if !IsTrustedProxySourceCIDRs("fe80::1%eth0", []string{"fe80::/10"}) {
		t.Errorf("expected %s to match fe80::/10", "fe80::1%eth0")
	}
}
