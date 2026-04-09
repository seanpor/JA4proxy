package proxy

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildV2Header constructs a minimal PROXY protocol v2 header with the given
// parameters. Returns the header bytes and the expected source IP string.
func buildV2Header(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16) []byte {
	t.Helper()

	// 12-byte signature
	sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

	var family byte
	var addrLen uint16
	var srcAddr, dstAddr []byte

	// Determine address family
	srcBytes := parseTestIP(t, srcIP)
	dstBytes := parseTestIP(t, dstIP)

	if len(srcBytes) == 4 {
		family = 0x11 // TCP over IPv4
		addrLen = 12  // 4 + 4 + 2 + 2
		srcAddr = srcBytes
		dstAddr = dstBytes
	} else {
		family = 0x21 // TCP over IPv6
		addrLen = 36  // 16 + 16 + 2 + 2
		srcAddr = srcBytes
		dstAddr = dstBytes
	}

	// Command 0x21 = PROXY + version 2
	cmdVer := byte(0x21)

	buf := bytes.NewBuffer(sig)
	buf.WriteByte(cmdVer)
	buf.WriteByte(family)
	binary.Write(buf, binary.BigEndian, addrLen)
	buf.Write(srcAddr)
	buf.Write(dstAddr)
	binary.Write(buf, binary.BigEndian, srcPort)
	binary.Write(buf, binary.BigEndian, dstPort)

	return buf.Bytes()
}

func parseTestIP(t *testing.T, ip string) []byte {
	t.Helper()
	// Simple parser for test IPs — supports dotted quad and ::1 style
	if bytes := parseIPv4(ip); bytes != nil {
		return bytes
	}
	if bytes := parseIPv6(ip); bytes != nil {
		return bytes
	}
	t.Fatalf("cannot parse test IP: %s", ip)
	return nil
}

func parseIPv4(ip string) []byte {
	var a, b, c, d uint8
	n := scanIPv4(ip, &a, &b, &c, &d)
	if n != 4 {
		return nil
	}
	return []byte{a, b, c, d}
}

func parseIPv6(ip string) []byte {
	// Only supports ::1 and ::X for tests — full parser not needed
	if ip == "::1" {
		b := make([]byte, 16)
		b[15] = 1
		return b
	}
	if ip == "2001:db8::1" {
		b := make([]byte, 16)
		b[0] = 0x20
		b[1] = 0x01
		b[2] = 0x0d
		b[3] = 0xb8
		b[15] = 1
		return b
	}
	if ip == "fd00::1" {
		b := make([]byte, 16)
		b[0] = 0xfd
		b[1] = 0
		b[15] = 1
		return b
	}
	return nil
}

// scanIPv4 parses a dotted-quad IP into four bytes.
func scanIPv4(s string, a, b, c, d *uint8) int {
	var vals [4]uint64
	idx := 0
	start := 0
	for i, ch := range s {
		if ch == '.' {
			if start >= i {
				return 0
			}
			v := parseUint(s[start:i])
			if v > 255 {
				return 0
			}
			vals[idx] = v
			idx++
			start = i + 1
		}
	}
	if idx != 3 {
		return 0
	}
	v := parseUint(s[start:])
	if v > 255 {
		return 0
	}
	vals[3] = v
	*a = uint8(vals[0])
	*b = uint8(vals[1])
	*c = uint8(vals[2])
	*d = uint8(vals[3])
	return 4
}

func parseUint(s string) uint64 {
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

// TestReadProxyProtocolV2_IPv4_Valid verifies extraction of source IP from
// a valid v2 header with IPv4 addresses.
func TestReadProxyProtocolV2_IPv4_Valid(t *testing.T) {
	// PROXY TCP4 1.2.3.4 5.6.7.8 1234 443
	header := buildV2Header(t, "1.2.3.4", "5.6.7.8", 1234, 443)

	ip, ok := ReadProxyProtocolV2(header)
	if !ok {
		t.Fatal("expected ok=true for valid v2 IPv4 header")
	}
	if ip != "1.2.3.4" {
		t.Errorf("got %q, want %q", ip, "1.2.3.4")
	}
}

// TestReadProxyProtocolV2_IPv6_Valid verifies extraction from a v2 header
// with IPv6 addresses.
func TestReadProxyProtocolV2_IPv6_Valid(t *testing.T) {
	header := buildV2Header(t, "::1", "::1", 1234, 443)

	ip, ok := ReadProxyProtocolV2(header)
	if !ok {
		t.Fatal("expected ok=true for valid v2 IPv6 header")
	}
	if ip != "::1" {
		t.Errorf("got %q, want %q", ip, "::1")
	}
}

// TestReadProxyProtocolV2_IPv6_Full verifies a full 16-byte IPv6 address.
func TestReadProxyProtocolV2_IPv6_Full(t *testing.T) {
	header := buildV2Header(t, "2001:db8::1", "::1", 54321, 443)

	ip, ok := ReadProxyProtocolV2(header)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if ip != "2001:db8::1" {
		t.Errorf("got %q, want %q", ip, "2001:db8::1")
	}
}

// TestReadProxyProtocolV2_TruncatedSignature rejects headers shorter than
// the 12-byte signature.
func TestReadProxyProtocolV2_TruncatedSignature(t *testing.T) {
	short := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00}
	_, ok := ReadProxyProtocolV2(short)
	if ok {
		t.Error("truncated signature: expected ok=false")
	}
}

// TestReadProxyProtocolV2_WrongSignature rejects headers with incorrect
// signature bytes.
func TestReadProxyProtocolV2_WrongSignature(t *testing.T) {
	buf := make([]byte, 16)
	copy(buf[:4], []byte{0x0D, 0x0A, 0x0D, 0x0A})
	// Bytes 4-11 are zeros instead of the correct signature
	_, ok := ReadProxyProtocolV2(buf)
	if ok {
		t.Error("wrong signature: expected ok=false")
	}
}

// TestReadProxyProtocolV2_LOCAL_Command returns false — LOCAL command has
// no address information.
func TestReadProxyProtocolV2_LOCAL_Command(t *testing.T) {
	// 12-byte signature + LOCAL command (0x20) + zero length
	buf := []byte{
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
		0x20,       // version=2, command=LOCAL
		0x00,       // UNSPEC transport + family
		0x00, 0x00, // address length = 0
	}
	_, ok := ReadProxyProtocolV2(buf)
	if ok {
		t.Error("LOCAL command: expected ok=false")
	}
}

// TestReadProxyProtocolV2_OversizedAddrLen rejects headers where the address
// length field exceeds the remaining buffer (prevents OOB read).
func TestReadProxyProtocolV2_OversizedAddrLen(t *testing.T) {
	buf := []byte{
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
		0x21,       // PROXY command
		0x11,       // IPv4
		0xFF, 0xFF, // address length = 65535 (way too big)
		1, 2, 3, 4, // only 4 bytes of data follow
	}
	_, ok := ReadProxyProtocolV2(buf)
	if ok {
		t.Error("oversized addr_len: expected ok=false")
	}
}

// TestReadProxyProtocolV2_EmptyBuffer returns false for zero-length input.
func TestReadProxyProtocolV2_EmptyBuffer(t *testing.T) {
	_, ok := ReadProxyProtocolV2([]byte{})
	if ok {
		t.Error("empty buffer: expected ok=false")
	}
}

// TestReadProxyProtocolV2_IPv4_ExactBufferSize verifies parsing when the
// buffer is exactly the header size (no trailing data).
func TestReadProxyProtocolV2_IPv4_ExactBufferSize(t *testing.T) {
	header := buildV2Header(t, "192.168.1.100", "10.0.0.1", 54321, 443)
	// No trailing data — just the header itself

	ip, ok := ReadProxyProtocolV2(header)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if ip != "192.168.1.100" {
		t.Errorf("got %q, want %q", ip, "192.168.1.100")
	}
}

// TestReadProxyProtocolV2_UnspecFamily rejects UNSPEC address family.
func TestReadProxyProtocolV2_UnspecFamily(t *testing.T) {
	buf := []byte{
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
		0x21,       // PROXY command
		0x00,       // UNSPEC family
		0x00, 0x00, // addr_len = 0
	}
	_, ok := ReadProxyProtocolV2(buf)
	if ok {
		t.Error("UNSPEC family: expected ok=false")
	}
}

// TestReadProxyProtocolV2_DoesNotPanic is a property-style test ensuring
// the function never panics on adversarial input.
func TestReadProxyProtocolV2_DoesNotPanic(t *testing.T) {
	adversarial := [][]byte{
		{},
		{0x00},
		{0x0D, 0x0A, 0x0D},
		bytes.Repeat([]byte{0x00}, 100),
		bytes.Repeat([]byte{0xFF}, 100),
		// A valid signature with garbage after it
		{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x99, 0x99, 0x00, 0x00},
	}

	for i, data := range adversarial {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("adversarial input %d panicked: %v", i, r)
				}
			}()
			_, _ = ReadProxyProtocolV2(data)
		}()
	}
}

// TestReadProxyProtocolV2_HeaderLength verifies that the function can
// report the header length for buffer advancement (internal validation).
func TestReadProxyProtocolV2_HeaderLength(t *testing.T) {
	// IPv4: 12 (sig) + 1 (cmd) + 1 (family) + 2 (len) + 12 (addrs+ports) = 28
	header := buildV2Header(t, "1.2.3.4", "5.6.7.8", 1234, 443)
	_, ok, hdrLen := ReadProxyProtocolV2WithLength(header)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if hdrLen != 28 {
		t.Errorf("IPv4 header length: got %d, want 28", hdrLen)
	}

	// IPv6: 12 (sig) + 1 (cmd) + 1 (family) + 2 (len) + 36 (addrs+ports) = 52
	header6 := buildV2Header(t, "2001:db8::1", "::1", 54321, 443)
	_, ok, hdrLen = ReadProxyProtocolV2WithLength(header6)
	if !ok {
		t.Fatal("expected ok=true for IPv6")
	}
	if hdrLen != 52 {
		t.Errorf("IPv6 header length: got %d, want 52", hdrLen)
	}
}
