package proxy

import (
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
