package backup

import (
	"net/netip"
	"strings"
)

// KeyClass labels a key by restore risk (Phase 315b).
type KeyClass int

const (
	// ClassAllow is allow-state: whitelists, fingerprints, audit history, counters.
	// Restoring it can never re-block a real user.
	ClassAllow KeyClass = iota
	// ClassBlock is block-state: restoring it can re-block real users (a mass
	// false-positive event by construction), so it is gated behind --include-blocks.
	ClassBlock
)

// blockPrefixes are the keys whose restoration can re-block users: active bans
// (single IP and CIDR), the IP/JA4 block lists, and the dial.
var blockPrefixes = []string{
	"ban:",
	"ban_cidr:",
	"ip:blacklist",
	"ja4:blacklist",
	"config:dial",
}

// ClassifyKey labels a Redis key as allow- or block-state.
func ClassifyKey(key string) KeyClass {
	for _, p := range blockPrefixes {
		if strings.HasPrefix(key, p) {
			return ClassBlock
		}
	}
	return ClassAllow
}

// perIPExtractors maps a key prefix to the function that pulls the raw IP out of
// keys with that prefix. Order matters: the longer "fp:os:ip:" is tried before a
// hypothetical shorter "fp:" would be (there is none here, but keep it explicit).
//
// JA4 fingerprint strings contain only hex and '_' — never ':' — so for the
// compound beacon:{ip}:{ja4} key the IP is everything up to the LAST ':', which
// keeps IPv6 addresses intact.
var perIPExtractors = []struct {
	prefix string
	last   bool // true: IP runs up to the last ':' in the remainder; false: whole remainder
}{
	{"ban:", false},
	{"fp:os:ip:", false},
	{"fp:ip:", false},
	{"beacon:", true},
}

// SubjectIP returns the canonical IP (IPv4 or IPv6) that a per-IP key belongs to,
// or ("", false) if the key is not a tracked per-IP subject. The IP is never
// truncated; IPv6 is returned in canonical form. ban_cidr:* is intentionally NOT
// a per-IP subject (it is a CIDR, not a person), so it is never tombstone-skipped.
func SubjectIP(key string) (string, bool) {
	for _, ex := range perIPExtractors {
		if !strings.HasPrefix(key, ex.prefix) {
			continue
		}
		rest := key[len(ex.prefix):]
		raw := rest
		if ex.last {
			i := strings.LastIndexByte(rest, ':')
			if i < 0 {
				return "", false // e.g. beacon:suspects — not a per-IP key
			}
			raw = rest[:i]
		}
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return "", false
		}
		return addr.String(), true
	}
	return "", false
}
