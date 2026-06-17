package tap

import (
	"context"
	"net/netip"
	"time"

	"github.com/seanpor/ja4proxy/internal/fingerprint"
)

// osClassTTL bounds how long an observed OS class lives in Redis. 24h matches the
// freshness assumption documented in internal/security/tap_consumer.go (which
// does not enforce MaxAge precisely and relies on this TTL to cap staleness).
const osClassTTL = 24 * time.Hour

// ja4tTTL bounds how long an observed JA4T lives in Redis. It mirrors osClassTTL:
// the JA4T consumer relies on the TTL (not an embedded timestamp) to cap
// staleness, and a client's TCP stack signature is as stable as its OS class.
const ja4tTTL = 24 * time.Hour

// redisSetter is the narrow write interface the Store needs. It returns an error
// so the Store can count failures; the live go-redis client is adapted to it in
// cmd/ja4-tap.
type redisSetter interface {
	Set(ctx context.Context, key, value string, ttl time.Duration) error
}

// Store writes passive OS classifications to fp:os:ip:{ip}. Writes are
// fire-and-forget and fail-open: a Redis error is counted and dropped, never
// propagated — it must not stall capture or produce an enforcement action.
type Store struct {
	redis redisSetter
}

// NewStore builds a Store over the given setter. A nil setter yields a no-op
// store (used for offline pcap replay without Redis), which simply counts every
// would-be write as skipped.
func NewStore(r redisSetter) *Store { return &Store{redis: r} }

// WriteOSClass persists the observed OS class for clientIP, unless the class is
// not concrete (OSUnknown), in which case it writes nothing — the conservative
// default that avoids manufacturing false OS-mismatches. The IP is canonicalised
// to match the form the inline consumer reads (v4 and v6).
func (s *Store) WriteOSClass(ctx context.Context, clientIP string, class fingerprint.OSClass) {
	if !class.IsKnown() {
		FingerprintsWrittenTotal.WithLabelValues(fpSkippedUnknown).Inc()
		return
	}
	ip := canonicalIP(clientIP)
	if ip == "" {
		FingerprintsWrittenTotal.WithLabelValues(fpError).Inc()
		return
	}
	if s == nil || s.redis == nil {
		// No Redis backend (e.g. offline replay): count as skipped, not error.
		FingerprintsWrittenTotal.WithLabelValues(fpSkippedUnknown).Inc()
		return
	}
	if err := s.redis.Set(ctx, "fp:os:ip:"+ip, class.String(), osClassTTL); err != nil {
		FingerprintsWrittenTotal.WithLabelValues(fpError).Inc()
		return
	}
	FingerprintsWrittenTotal.WithLabelValues(fpWritten).Inc()
}

// WriteJA4T persists the observed JA4T TCP fingerprint for clientIP to
// fp:ja4t:ip:{ip}, unless ja4t is empty (no SYN seen → ComputeJA4T returned ""),
// in which case it writes nothing. Like WriteOSClass it is fire-and-forget and
// fail-open: a Redis error is counted and dropped, never propagated. The IP is
// canonicalised to match the form the inline consumer reads (v4 and v6).
func (s *Store) WriteJA4T(ctx context.Context, clientIP, ja4t string) {
	if ja4t == "" {
		JA4TWrittenTotal.WithLabelValues(fpSkippedUnknown).Inc()
		return
	}
	ip := canonicalIP(clientIP)
	if ip == "" {
		JA4TWrittenTotal.WithLabelValues(fpError).Inc()
		return
	}
	if s == nil || s.redis == nil {
		// No Redis backend (e.g. offline replay): count as skipped, not error.
		JA4TWrittenTotal.WithLabelValues(fpSkippedUnknown).Inc()
		return
	}
	if err := s.redis.Set(ctx, "fp:ja4t:ip:"+ip, ja4t, ja4tTTL); err != nil {
		JA4TWrittenTotal.WithLabelValues(fpError).Inc()
		return
	}
	JA4TWrittenTotal.WithLabelValues(fpWritten).Inc()
}

// canonicalIP returns the canonical string form of an IP, matching what the
// inline consumer (internal/security) computes: brackets and zone IDs stripped,
// lowercase, leading zeros removed. Returns "" for unparsable input.
func canonicalIP(ip string) string {
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
