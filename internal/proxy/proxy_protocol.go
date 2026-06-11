package proxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/seanpor/ja4proxy/internal/config"
)

// proxyV2Signature is the 12-byte PROXY protocol v2 magic preamble.
var proxyV2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

func validPort(p int) bool { return p >= 0 && p <= 65535 }

// ip6Only returns the 16-byte form of a genuine IPv6 address, or nil for an
// IPv4 (or invalid) address — so IPv4-mapped values don't masquerade as v6.
func ip6Only(ip net.IP) []byte {
	if ip == nil || ip.To4() != nil {
		return nil
	}
	return ip.To16()
}

// BuildBackendProxyHeader builds a PROXY protocol header to prepend to the
// backend connection (phase-231a), so a TLS-passthrough deployment preserves
// the real client IP without decrypting. version 2 emits the binary v2 header;
// any other value emits the human-readable v1 header.
//
// FP-safety (the project's core asymmetry — never drop a valid client): when
// the src/dst families are indeterminate or mismatched, or a port is out of
// range, it emits the spec's "no address" form — v1 "PROXY UNKNOWN\r\n", v2
// LOCAL command (AF_UNSPEC) — so the connection still proceeds and the backend
// falls back to the real socket address. It never returns an error.
func BuildBackendProxyHeader(version int, srcIP net.IP, srcPort int, dstIP net.IP, dstPort int) []byte {
	if version == 2 {
		return buildProxyV2(srcIP, srcPort, dstIP, dstPort)
	}
	return buildProxyV1(srcIP, srcPort, dstIP, dstPort)
}

func buildProxyV1(srcIP net.IP, srcPort int, dstIP net.IP, dstPort int) []byte {
	if !validPort(srcPort) || !validPort(dstPort) {
		return []byte("PROXY UNKNOWN\r\n")
	}
	if s4, d4 := srcIP.To4(), dstIP.To4(); s4 != nil && d4 != nil {
		return []byte(fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n", s4.String(), d4.String(), srcPort, dstPort))
	}
	if s6, d6 := ip6Only(srcIP), ip6Only(dstIP); s6 != nil && d6 != nil {
		return []byte(fmt.Sprintf("PROXY TCP6 %s %s %d %d\r\n", srcIP.String(), dstIP.String(), srcPort, dstPort))
	}
	return []byte("PROXY UNKNOWN\r\n")
}

func buildProxyV2(srcIP net.IP, srcPort int, dstIP net.IP, dstPort int) []byte {
	buf := new(bytes.Buffer)
	buf.Write(proxyV2Signature)
	if s4, d4 := srcIP.To4(), dstIP.To4(); s4 != nil && d4 != nil && validPort(srcPort) && validPort(dstPort) {
		buf.WriteByte(0x21) // version 2 (0x20) | PROXY command (0x01)
		buf.WriteByte(0x11) // AF_INET (0x10) | STREAM (0x01)
		_ = binary.Write(buf, binary.BigEndian, uint16(12))
		buf.Write(s4)
		buf.Write(d4)
		_ = binary.Write(buf, binary.BigEndian, uint16(srcPort))
		_ = binary.Write(buf, binary.BigEndian, uint16(dstPort))
		return buf.Bytes()
	}
	if s6, d6 := ip6Only(srcIP), ip6Only(dstIP); s6 != nil && d6 != nil && validPort(srcPort) && validPort(dstPort) {
		buf.WriteByte(0x21) // version 2 | PROXY command
		buf.WriteByte(0x21) // AF_INET6 (0x20) | STREAM (0x01)
		_ = binary.Write(buf, binary.BigEndian, uint16(36))
		buf.Write(s6)
		buf.Write(d6)
		_ = binary.Write(buf, binary.BigEndian, uint16(srcPort))
		_ = binary.Write(buf, binary.BigEndian, uint16(dstPort))
		return buf.Bytes()
	}
	// LOCAL command + AF_UNSPEC: the backend uses the real socket addresses.
	buf.WriteByte(0x20) // version 2 | LOCAL command (0x00)
	buf.WriteByte(0x00) // AF_UNSPEC
	_ = binary.Write(buf, binary.BigEndian, uint16(0))
	return buf.Bytes()
}

// IsTrustedProxySource returns true if the peer IP is allowed to provide
// PROXY protocol headers. Controlled by proxy.upstream_trust:
//   - enabled: must be true to trust any header
//   - trusted_cidrs: list of CIDRs allowed to provide headers
//
// Fail-open: nil config, disabled, empty CIDRs, or invalid IP all return false.
// Parity with Python proxy.py _is_trusted_proxy_source() (Phase 200a).
func IsTrustedProxySource(ip string, cfg *config.Config) bool {
	if cfg == nil {
		return false
	}

	trust := cfg.Proxy.UpstreamTrust
	if !trust.Enabled {
		return false
	}

	if len(trust.TrustedCIDRs) == 0 {
		return false
	}

	return isTrustedIP(ip, trust.TrustedCIDRs)
}

// IsTrustedProxySourceCIDRs returns true if the peer IP is within any of the
// provided CIDRs.  Used when the trusted CIDR list is populated dynamically
// (e.g. from NetBox) rather than from static config.
//
// Fail-open: empty CIDRs or invalid IP returns false.
func IsTrustedProxySourceCIDRs(ip string, cidrs []string) bool {
	if len(cidrs) == 0 {
		return false
	}
	return isTrustedIP(ip, cidrs)
}

// isTrustedIP checks whether addr is contained in any of the CIDRs.
// Invalid IPs and malformed CIDRs are silently skipped (fail-open).
func isTrustedIP(ip string, cidrs []string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}

	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			// Skip malformed CIDRs — fail-open on this entry.
			continue
		}
		if ipNet.Contains(addr) {
			return true
		}
	}

	return false
}

// ReadProxyProtocol parses a PROXY protocol v1 header from buf.
// Returns (realClientIP, true) if the header is valid.
// Returns ("", false) if not a PROXY protocol header.
// Never panics. Fails open.
func ReadProxyProtocol(buf []byte) (clientIP string, ok bool) {
	s := string(buf)
	crlfIdx := strings.Index(s, "\r\n")
	if crlfIdx < 0 {
		return "", false
	}
	if !strings.HasPrefix(s, "PROXY ") {
		return "", false
	}
	line := s[:crlfIdx]
	parts := strings.Fields(line)
	// PROXY TCP4 <src_ip> <dst_ip> <src_port> <dst_port>
	if len(parts) < 6 {
		return "", false
	}
	if parts[1] == "UNKNOWN" {
		return "", false
	}
	ip := net.ParseIP(parts[2])
	if ip == nil {
		return "", false
	}
	return ip.String(), true
}

// PROXY protocol v2 binary signature (12 bytes).
// Spec: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt (section 2.2)
var v2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

const (
	v2MinHeaderSize = 16 // 12 (sig) + 1 (cmd/ver) + 1 (family) + 2 (addr_len)
	v2CmdPROXY      = 0x01
	v2CmdLOCAL      = 0x00
	v2FamTCPv4      = 0x11
	v2FamTCPv6      = 0x21
)

// ReadProxyProtocolV2 parses a PROXY protocol v2 binary header from buf.
// Returns the source (client) IP if valid, ("", false) otherwise.
// Never panics. Fails open. Does not advance any buffer — use
// ReadProxyProtocolV2WithLength for that.
func ReadProxyProtocolV2(buf []byte) (clientIP string, ok bool) {
	ip, ok, _ := ReadProxyProtocolV2WithLength(buf)
	return ip, ok
}

// ReadProxyProtocolV2WithLength is like ReadProxyProtocolV2 but also returns
// the total header length in bytes. The caller uses this to advance past the
// v2 header before parsing the TLS ClientHello.
//
// Returns:
//   - clientIP: source IP string (empty if not valid)
//   - ok: true if a valid v2 PROXY header was parsed
//   - headerLen: total bytes of the v2 header (0 if !ok)
func ReadProxyProtocolV2WithLength(buf []byte) (clientIP string, ok bool, headerLen int) {
	// Minimum: 12-byte signature + 4 bytes (cmd, family, 2-byte addr_len)
	if len(buf) < v2MinHeaderSize {
		return "", false, 0
	}

	// Check 12-byte signature
	if !bytes.Equal(buf[:12], v2Signature) {
		return "", false, 0
	}

	cmdVer := buf[12]
	// Version must be 2 (high nibble)
	if (cmdVer >> 4) != 0x02 {
		return "", false, 0
	}
	command := cmdVer & 0x0F

	// LOCAL command has no address info — nothing to extract
	if command == v2CmdLOCAL {
		return "", false, 0
	}

	// Must be PROXY command
	if command != v2CmdPROXY {
		return "", false, 0
	}

	family := buf[13]

	// Address length (big-endian)
	addrLen := int(binary.BigEndian.Uint16(buf[14:16]))

	// Sanity check: addrLen must be reasonable (≤ 256 prevents overflow)
	// and the buffer must contain at least that many bytes after the 16-byte prefix.
	if addrLen > 256 || len(buf) < v2MinHeaderSize+addrLen {
		return "", false, 0
	}

	headerLen = v2MinHeaderSize + addrLen

	// Parse addresses based on family
	var srcIP net.IP

	switch family {
	case v2FamTCPv4:
		// IPv4: 4 bytes src + 4 bytes dst + 2 bytes src port + 2 bytes dst port
		if addrLen < 12 {
			return "", false, 0
		}
		srcIP = net.IPv4(buf[16], buf[17], buf[18], buf[19])

	case v2FamTCPv6:
		// IPv6: 16 bytes src + 16 bytes dst + 2 bytes src port + 2 bytes dst port
		if addrLen < 36 {
			return "", false, 0
		}
		srcIP = make(net.IP, 16)
		copy(srcIP, buf[16:32])

	default:
		// UNSPEC or unknown — cannot extract IP
		return "", false, 0
	}

	if srcIP == nil {
		return "", false, 0
	}

	return srcIP.String(), true, headerLen
}
