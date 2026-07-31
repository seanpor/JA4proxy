package fingerprint

import "net/netip"

// Redis key prefixes shared by the TAP sensor (writer) and the inline proxy
// consumers (readers) — D-003. Previously each side hard-coded its own copy
// of these strings; a future rename on only one side would silently break
// the signal (fail-open to "no signal" on a Redis miss, no error/alert).
const (
	KeyPrefixOSClass   = "fp:os:ip:"
	KeyPrefixJA4T      = "fp:ja4t:ip:"
	KeyPrefixBanIntent = "fp:ban_intent:ip:"
)

// CanonicalIP returns the canonical string form of a client IP address,
// matching how both the passive TAP sensor (writer of fp:os:ip / fp:ja4t:ip)
// and the inline proxy consumers (readers) must key their Redis lookups.
// Strips IPv6 brackets and zone IDs, and normalises via netip.Addr.String()
// (lowercase hex, no leading zeros). Returns "" for unparsable input — the
// fail-open sentinel every caller already treats as "no signal".
//
// This used to be duplicated verbatim in internal/tap/store.go and
// internal/security/tap_consumer.go (F-019): both packages already depend
// on this package for the shared OSClass vocabulary, so a silent drift
// between the two copies would have broken tap_os_mismatch/tap_ja4t_blocklist
// without either side noticing (fail-open to "no signal", not a crash).
func CanonicalIP(ip string) string {
	if len(ip) >= 2 && ip[0] == '[' && ip[len(ip)-1] == ']' {
		ip = ip[1 : len(ip)-1]
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	if addr.Zone() != "" {
		addr = addr.WithZone("")
	}
	return addr.String()
}
