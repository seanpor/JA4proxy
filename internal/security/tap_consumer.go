// Package security — Phase 203a TAP-consumed JA4T OS-mismatch signal.
//
// Architectural background (see docs/decisions/ADR-203a.md): the inline Go
// proxy cannot compute JA4T from an accept()'d socket because the kernel has
// already completed the TCP handshake by then. The Phase 20 TAP node, which
// sees raw SYN packets via AF_PACKET, is the correct producer of JA4T-
// derived OS classification. The TAP node writes `fp:os:ip:{ip}` strings to
// Redis; this consumer reads them on the hot path and emits a
// `tap_os_mismatch` RiskSignal when the OS class implied by the JA4 TLS
// fingerprint disagrees with the OS class observed in the client's TCP
// stack.
//
// All calls fail open: disabled config, missing Redis key, Redis error,
// Redis timeout — all return nil so legitimate traffic is never blocked
// on signal infrastructure failure.
package security

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/seanpor/ja4proxy/internal/cache"
	"github.com/seanpor/ja4proxy/internal/metrics"
	"github.com/sirupsen/logrus"
)

// canonicalIP returns the canonical string form of an IP address matching
// what the Phase-20 TAP node writes (via Python's socket.inet_ntop).
// Strips zone IDs, brackets, and leading zeros; lowercases hex octets.
// Returns "" for unparsable input (caller treats as fail-open).
func canonicalIP(ip string) string {
	// Strip IPv6 brackets if the caller accidentally left them on.
	if len(ip) >= 2 && ip[0] == '[' && ip[len(ip)-1] == ']' {
		ip = ip[1 : len(ip)-1]
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	// Drop zone IDs (e.g. "fe80::1%eth0") — TAP never sees them.
	if addr.Zone() != "" {
		addr = addr.WithZone("")
	}
	return addr.String()
}

// TapConsumerConfig configures the TAP-derived OS-mismatch signal consumer.
type TapConsumerConfig struct {
	Enabled      bool
	SignalScore  int
	RedisTimeout time.Duration
	CacheTTL     time.Duration
	// MaxAge is plumbed from config but not currently enforced: fp:os:ip:{ip}
	// is a Redis String with no embedded timestamp. Enforcing freshness would
	// require a second HGET against fp:conn:{id}.last_seen, out of scope for
	// phase 203. TAP writer sets a 24h TTL on the key, bounding worst-case
	// staleness. Fail-open preserved: stale lookups degrade to "missing signal"
	// rather than a wrong decision.
	MaxAge time.Duration
}

// redisGetter is the narrow Redis interface the TapConsumer depends on.
// Matches (*redis.Client).Get. Kept tiny so tests can stub easily.
type redisGetter interface {
	Get(ctx context.Context, key string) (string, error)
}

// TapConsumer reads Phase-20 TAP fingerprints from Redis and emits a signal
// when the observed OS disagrees with the one implied by the JA4 fingerprint.
type TapConsumer struct {
	cfg   *TapConsumerConfig
	redis redisGetter
	cache *cache.LRU
	log   *logrus.Logger
}

// NewTapConsumer constructs a TapConsumer. A nil log falls back to a default
// logger. A nil cfg yields a disabled consumer.
func NewTapConsumer(cfg *TapConsumerConfig, r redisGetter, log *logrus.Logger) *TapConsumer {
	if log == nil {
		log = logrus.New()
	}
	if cfg == nil {
		cfg = &TapConsumerConfig{}
	}
	return &TapConsumer{
		cfg:   cfg,
		redis: r,
		cache: cache.New(4096),
		log:   log,
	}
}

// ja4OSClass returns the OS class claimed by the JA4 fingerprint, or "" when
// the fingerprint does not map to a known OS. The starter table is
// intentionally small (see PHASE_203_review.md); gaps are fail-open.
//
// Keys are the JA4 prefix up to the first underscore (e.g. "t13d1516h2").
// Mappings derived from config/os_fingerprints.yml and the public
// FoxIO-LLC/ja4 dataset.
func ja4OSClass(ja4 string) string {
	if len(ja4) == 0 {
		return ""
	}
	underscore := strings.IndexByte(ja4, '_')
	if underscore <= 0 {
		return ""
	}
	prefix := ja4[:underscore]
	switch prefix {
	case "t13d1516h2":
		// Chrome/Edge on Windows (modern) — 10 extensions, 2 sigalgs.
		return "windows"
	case "t13d1517h2":
		// Chrome on macOS variant — widely documented in FoxIO JA4 corpus.
		return "macos"
	case "t13d1715h2":
		// Firefox on Linux — commonly reported JA4 shape.
		return "linux"
	case "t13d3112h2":
		// Safari on macOS.
		return "macos"
	case "t13d3113h2":
		// Safari on iOS.
		return "ios"
	case "t13d0310h2":
		// curl / command-line TLS clients (Linux default builds).
		return "linux"
	case "t13d1314h1":
		// Go http.Client default — Linux-shaped stack when run on Linux.
		return "linux"
	}
	return ""
}

// GetSignal returns a *RiskSignal when the JA4-claimed OS disagrees with the
// TAP-observed OS for this client IP. Returns nil on any fail-open condition
// (disabled, unknown JA4, Redis miss/error/timeout, observed==claimed).
// Never blocks longer than cfg.RedisTimeout on the hot path.
func (t *TapConsumer) GetSignal(ctx context.Context, clientIP, ja4 string) *RiskSignal {
	if t == nil || t.cfg == nil || !t.cfg.Enabled {
		return nil
	}
	if ja4 == "" || clientIP == "" {
		return nil
	}
	// Canonicalise IP to match what the Phase-20 TAP node stores.
	// Unparsable IP → fail open (no signal).
	canonIP := canonicalIP(clientIP)
	if canonIP == "" {
		return nil
	}
	claimed := ja4OSClass(ja4)
	if claimed == "" {
		return nil
	}

	observed, hit := t.cachedLookup(canonIP)
	if !hit {
		observed = t.redisLookup(ctx, canonIP)
		// Cache the outcome (even empty string) to short-circuit repeat calls.
		ttl := t.cfg.CacheTTL
		if ttl <= 0 {
			ttl = 60 * time.Second
		}
		t.cache.Set(cacheKey(canonIP), observed, ttl)
	}

	if observed == "" {
		// Miss already counted by redisLookup; nothing to emit.
		return nil
	}

	if observed == claimed {
		metrics.TapLookupsTotal.WithLabelValues("hit_match").Inc()
		return nil
	}

	metrics.TapLookupsTotal.WithLabelValues("hit_mismatch").Inc()
	metrics.TapSignalTotal.WithLabelValues("flag").Inc()
	return &RiskSignal{
		Name:   "tap_os_mismatch",
		Score:  t.cfg.SignalScore,
		Weight: 1.0,
		Reason: fmt.Sprintf("JA4 claims %s, TAP observed %s", claimed, observed),
	}
}

func (t *TapConsumer) cachedLookup(clientIP string) (string, bool) {
	if t.cache == nil {
		return "", false
	}
	v, ok := t.cache.Get(cacheKey(clientIP))
	if !ok {
		return "", false
	}
	s, _ := v.(string)
	return s, true
}

func (t *TapConsumer) redisLookup(parent context.Context, clientIP string) string {
	if t.redis == nil {
		metrics.TapLookupsTotal.WithLabelValues("error").Inc()
		return ""
	}
	timeout := t.cfg.RedisTimeout
	if timeout <= 0 {
		timeout = 50 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	val, err := t.redis.Get(ctx, "fp:os:ip:"+clientIP)
	if err != nil {
		metrics.TapLookupsTotal.WithLabelValues("error").Inc()
		t.log.WithError(err).WithField("client_ip", clientIP).Debug("tap_consumer: Redis GET failed; failing open")
		return ""
	}
	if val == "" {
		metrics.TapLookupsTotal.WithLabelValues("miss").Inc()
		return ""
	}
	return val
}

func cacheKey(clientIP string) string {
	return "tap_os:" + clientIP
}
