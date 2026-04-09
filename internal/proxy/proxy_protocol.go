package proxy

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"

	"github.com/anomalyco/ja4proxy/internal/config"
)

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

	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}

	for _, cidr := range trust.TrustedCIDRs {
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
