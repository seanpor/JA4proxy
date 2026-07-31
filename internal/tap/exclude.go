package tap

import (
	"net/netip"
	"strings"
)

// ExcludeList matches a client IP against an operator-configured set of
// IPs/CIDRs that must never get a fingerprint or enforcement write
// (fp:os:ip, fp:ja4t:ip, fp:ban_intent:ip, ban:{ip}) — phase-809, P-003.
// This is the "prevent re-write" half of GDPR erasure: deleting existing
// Redis keys for an IP is not durable on its own, since the sensor would
// simply re-write them on that IP's next observed SYN/handshake.
type ExcludeList struct {
	prefixes []netip.Prefix
}

// NewExcludeList parses a comma-separated list of bare IPs and/or CIDRs
// (e.g. "203.0.113.5,198.51.100.0/24"). A bare IP is treated as a /32 (v4)
// or /128 (v6). Invalid entries are skipped rather than failing startup —
// consistent with the sensor's fail-open posture (better to run without one
// malformed exclusion entry than refuse to start).
func NewExcludeList(csv string) *ExcludeList {
	var prefixes []netip.Prefix
	for _, entry := range strings.Split(csv, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if p, err := netip.ParsePrefix(entry); err == nil {
			prefixes = append(prefixes, p)
			continue
		}
		if addr, err := netip.ParseAddr(entry); err == nil {
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return &ExcludeList{prefixes: prefixes}
}

// Contains reports whether ip (any parseable string form) matches an
// excluded IP or CIDR. A nil receiver or unparsable ip is never excluded
// (fail-open: an exclusion list that can't be evaluated must not silently
// suppress legitimate signal collection).
func (e *ExcludeList) Contains(ip string) bool {
	if e == nil || len(e.prefixes) == 0 {
		return false
	}
	addr, err := netip.ParseAddr(canonicalIP(ip))
	if err != nil {
		return false
	}
	for _, p := range e.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
