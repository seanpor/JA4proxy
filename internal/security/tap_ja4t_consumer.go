// Package security — Phase 316c TAP-consumed JA4T blocklist signal.
//
// Architectural background: like the OS-mismatch signal (ADR-203a), the inline
// proxy cannot compute JA4T from an accept()'d socket — the kernel completed the
// TCP handshake before the proxy sees the connection, so the SYN's window, MSS
// and option order are gone. The standalone TAP sensor (Phase 316a/c) sees the
// raw SYN, computes the canonical JA4T, and writes fp:ja4t:ip:{ip} to Redis.
//
// This consumer reads that key on the hot path and emits an advisory
// `tap_ja4t_blocklist` RiskSignal when the observed JA4T is on the
// operator-configured blocklist. The blocklist defaults to empty, so the signal
// is silent until an operator opts in — the conservative default that can never
// produce a false positive on its own (the core asymmetry). The signal is scored
// under the dial like any other; it never hard-blocks.
//
// All calls fail open: disabled config, empty blocklist, missing Redis key,
// Redis error or timeout — all return nil so legitimate traffic is never blocked
// on signal infrastructure failure.
package security

import (
	"context"
	"fmt"
	"time"

	"github.com/seanpor/ja4proxy/internal/cache"
	"github.com/seanpor/ja4proxy/internal/metrics"
	"github.com/sirupsen/logrus"
)

// JA4TConsumerConfig configures the TAP-derived JA4T blocklist signal consumer.
type JA4TConsumerConfig struct {
	Enabled      bool
	SignalScore  int
	RedisTimeout time.Duration
	CacheTTL     time.Duration
	// Blocklist is the set of JA4T strings that should raise the signal. Empty
	// (the default) means the consumer is effectively inert: it never emits.
	Blocklist map[string]bool
}

// JA4TConsumer reads passive JA4T fingerprints (fp:ja4t:ip:{ip}) from Redis and
// emits an advisory signal when the observed JA4T is blocklisted.
type JA4TConsumer struct {
	cfg   *JA4TConsumerConfig
	redis redisGetter
	cache *cache.LRU
	log   *logrus.Logger
}

// NewJA4TConsumer constructs a JA4TConsumer. A nil log falls back to a default
// logger; a nil cfg yields a disabled consumer.
func NewJA4TConsumer(cfg *JA4TConsumerConfig, r redisGetter, log *logrus.Logger) *JA4TConsumer {
	if log == nil {
		log = logrus.New()
	}
	if cfg == nil {
		cfg = &JA4TConsumerConfig{}
	}
	return &JA4TConsumer{
		cfg:   cfg,
		redis: r,
		cache: cache.New(4096),
		log:   log,
	}
}

// GetSignal returns a *RiskSignal when the passive JA4T observed for clientIP is
// on the configured blocklist. Returns nil on every fail-open condition
// (disabled, empty blocklist, unparsable IP, Redis miss/error/timeout, or an
// observed JA4T that is not blocklisted). Never blocks longer than
// cfg.RedisTimeout on the hot path.
func (c *JA4TConsumer) GetSignal(ctx context.Context, clientIP string) *RiskSignal {
	if c == nil || c.cfg == nil || !c.cfg.Enabled || len(c.cfg.Blocklist) == 0 {
		return nil
	}
	if clientIP == "" {
		return nil
	}
	canonIP := canonicalIP(clientIP)
	if canonIP == "" {
		return nil
	}

	observed, hit := c.cachedLookup(canonIP)
	if !hit {
		observed = c.redisLookup(ctx, canonIP)
		ttl := c.cfg.CacheTTL
		if ttl <= 0 {
			ttl = 60 * time.Second
		}
		c.cache.Set(ja4tCacheKey(canonIP), observed, ttl)
	}

	if observed == "" {
		// Miss/error already counted in redisLookup; nothing to emit.
		return nil
	}
	if !c.cfg.Blocklist[observed] {
		metrics.TapJA4TLookupsTotal.WithLabelValues("hit_clean").Inc()
		return nil
	}

	metrics.TapJA4TLookupsTotal.WithLabelValues("hit_blocklisted").Inc()
	metrics.TapJA4TSignalTotal.WithLabelValues("flag").Inc()
	return &RiskSignal{
		Name:   "tap_ja4t_blocklist",
		Score:  c.cfg.SignalScore,
		Weight: 1.0,
		Reason: fmt.Sprintf("TAP-observed JA4T %s on blocklist", observed),
	}
}

func (c *JA4TConsumer) cachedLookup(clientIP string) (string, bool) {
	if c.cache == nil {
		return "", false
	}
	v, ok := c.cache.Get(ja4tCacheKey(clientIP))
	if !ok {
		return "", false
	}
	s, _ := v.(string)
	return s, true
}

func (c *JA4TConsumer) redisLookup(parent context.Context, clientIP string) string {
	if c.redis == nil {
		metrics.TapJA4TLookupsTotal.WithLabelValues("error").Inc()
		return ""
	}
	timeout := c.cfg.RedisTimeout
	if timeout <= 0 {
		timeout = 50 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	val, err := c.redis.Get(ctx, "fp:ja4t:ip:"+clientIP)
	if err != nil {
		metrics.TapJA4TLookupsTotal.WithLabelValues("error").Inc()
		c.log.WithError(err).WithField("client_ip", clientIP).Debug("tap_ja4t_consumer: Redis GET failed; failing open")
		return ""
	}
	if val == "" {
		metrics.TapJA4TLookupsTotal.WithLabelValues("miss").Inc()
		return ""
	}
	return val
}

func ja4tCacheKey(clientIP string) string {
	return "tap_ja4t:" + clientIP
}
