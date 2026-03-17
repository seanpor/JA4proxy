package proxy

import (
	"net"
	"strings"
)

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
