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
	"time"

	"github.com/seanpor/ja4proxy/internal/cache"
	"github.com/seanpor/ja4proxy/internal/fingerprint"
	"github.com/seanpor/ja4proxy/internal/metrics"
	"github.com/sirupsen/logrus"
)

// canonicalIP returns the canonical string form of an IP address matching
// what the TAP sensor writes. F-019: this used to duplicate
// internal/fingerprint.CanonicalIP's logic verbatim (identical to the writer
// side in internal/tap/store.go) — now delegates to the single shared
// implementation both packages already depend on for the OSClass vocabulary.
func canonicalIP(ip string) string {
	return fingerprint.CanonicalIP(ip)
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
	// NegativeCacheTTL bounds how long a Redis miss/error/timeout ("") is
	// cached before the next lookup retries Redis (D-002). Kept much shorter
	// than CacheTTL: a positive result is worth caching for a while, but a
	// miss racing the TAP sensor's own write (SYN observed a few ms before
	// the proxy's accept()) should not silently suppress the signal for the
	// full positive-result TTL once the sensor's write actually lands.
	NegativeCacheTTL time.Duration
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

// GetSignal returns a *RiskSignal when the JA4-claimed OS disagrees with the
// TAP-observed OS for this client IP. Returns nil on any fail-open condition
// (disabled, unknown JA4, Redis miss/error/timeout, observed==claimed, or an
// observed value that does not parse to a known OS class). The comparison fires
// only when BOTH classes are concrete, so an unknown on either side never
// produces a signal. Never blocks longer than cfg.RedisTimeout on the hot path.
func (t *TapConsumer) GetSignal(ctx context.Context, clientIP, ja4 string) *RiskSignal {
	if t == nil || t.cfg == nil || !t.cfg.Enabled {
		return nil
	}
	if ja4 == "" || clientIP == "" {
		return nil
	}
	// Canonicalise IP to match what the TAP sensor stores.
	// Unparsable IP → fail open (no signal).
	canonIP := canonicalIP(clientIP)
	if canonIP == "" {
		return nil
	}
	claimed := fingerprint.JA4OSClass(ja4)
	if !claimed.IsKnown() {
		return nil
	}

	observed, hit := t.cachedLookup(canonIP)
	if !hit {
		observed = t.redisLookup(ctx, canonIP)
		// Cache the outcome to short-circuit repeat calls, but a miss/error
		// gets a much shorter TTL than a positive result (D-002): a Redis GET
		// racing the TAP sensor's own write must not suppress the signal for
		// a full CacheTTL once the sensor's write actually lands.
		ttl := t.cfg.CacheTTL
		if ttl <= 0 {
			ttl = 60 * time.Second
		}
		if observed == "" {
			ttl = t.cfg.NegativeCacheTTL
			if ttl <= 0 {
				ttl = 5 * time.Second
			}
		}
		t.cache.Set(cacheKey(canonIP), observed, ttl)
	}

	observedClass := fingerprint.ParseOSClass(observed)
	if !observedClass.IsKnown() {
		// Miss, or a value that does not map to a known class; nothing to emit.
		return nil
	}

	if observedClass == claimed {
		metrics.TapLookupsTotal.WithLabelValues("hit_match").Inc()
		return nil
	}

	metrics.TapLookupsTotal.WithLabelValues("hit_mismatch").Inc()
	metrics.TapSignalTotal.WithLabelValues("flag").Inc()
	return &RiskSignal{
		Name:   "tap_os_mismatch",
		Score:  t.cfg.SignalScore,
		Weight: 1.0,
		Reason: fmt.Sprintf("JA4 claims %s, TAP observed %s", claimed, observedClass),
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

	val, err := t.redis.Get(ctx, fingerprint.KeyPrefixOSClass+clientIP)
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
