package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"

	"github.com/sirupsen/logrus"
)

// sanitizeKey canonicalises clientIP via netip and caps ja4 length.
func sanitizeKey(clientIP, ja4 string) (canonIP, safeJA4 string, ok bool) {
	addr, err := netip.ParseAddr(clientIP)
	if err != nil || !addr.IsValid() {
		return "", "", false
	}
	if len(ja4) > 256 {
		ja4 = ja4[:256]
	}
	return addr.String(), ja4, true
}

// StrategyConfig holds rate limiting thresholds for a single strategy.
type StrategyConfig struct {
	Enabled    bool
	Suspicious int
	Block      int
	Ban        int
	Window     float64
	TTL        int
}

// RateLimiterConfig configures the multi-strategy rate limiter.
type RateLimiterConfig struct {
	Enabled bool
	ByIP    StrategyConfig
	ByJA4   StrategyConfig
	ByIPJA4 StrategyConfig
}

// RateLimiter implements a multi-strategy sliding window rate limiter.
// Port of MultiStrategyRateTracker from src/security/pipeline.py.
type RateLimiter struct {
	cfg   *RateLimiterConfig
	redis RedisReader
	log   *logrus.Logger
}

// NewRateLimiter creates a RateLimiter with the given configuration.
func NewRateLimiter(cfg *RateLimiterConfig, redis RedisReader, log *logrus.Logger) *RateLimiter {
	if log == nil {
		log = logrus.New()
	}
	if cfg == nil {
		cfg = &RateLimiterConfig{}
	}
	return &RateLimiter{cfg: cfg, redis: redis, log: log}
}

// Check records this connection and returns a risk signal if thresholds are exceeded.
// Returns nil slice if rate limiting is disabled or no threshold reached.
func (r *RateLimiter) Check(ctx context.Context, clientIP, ja4 string) []RiskSignal {
	if !r.cfg.Enabled {
		return nil
	}

	canonIP, safeJA4, ok := sanitizeKey(clientIP, ja4)
	if !ok {
		sum := sha256.Sum256([]byte(clientIP))
		hash := hex.EncodeToString(sum[:])[:16]
		r.log.WithField("ip_hash", hash).Warn("rate_limiter: rejected unparseable IP; skipping rate limit (fail-open)")
		return nil
	}
	clientIP, ja4 = canonIP, safeJA4

	type stratResult struct {
		count    int
		strategy StrategyConfig
	}

	var results []stratResult

	// by_ip strategy
	if r.cfg.ByIP.Enabled {
		key := fmt.Sprintf("ratelimit:ip:%s", clientIP)
		count := r.redis.SlidingWindowCount(ctx, key, r.cfg.ByIP.Window, r.cfg.ByIP.TTL)
		results = append(results, stratResult{count: count, strategy: r.cfg.ByIP})
	}

	// by_ja4 strategy (skip if ja4 is empty)
	if r.cfg.ByJA4.Enabled && ja4 != "" {
		key := fmt.Sprintf("ratelimit:ja4:%s", ja4)
		count := r.redis.SlidingWindowCount(ctx, key, r.cfg.ByJA4.Window, r.cfg.ByJA4.TTL)
		results = append(results, stratResult{count: count, strategy: r.cfg.ByJA4})
	}

	// by_ip_ja4 strategy (skip if ja4 is empty)
	if r.cfg.ByIPJA4.Enabled && ja4 != "" {
		key := fmt.Sprintf("ratelimit:ip_ja4:%s:%s", clientIP, ja4)
		count := r.redis.SlidingWindowCount(ctx, key, r.cfg.ByIPJA4.Window, r.cfg.ByIPJA4.TTL)
		results = append(results, stratResult{count: count, strategy: r.cfg.ByIPJA4})
	}

	if len(results) == 0 {
		return nil
	}

	// Count how many strategies hit each level
	banCount := 0
	blockCount := 0
	suspiciousCount := 0

	for _, res := range results {
		s := res.strategy
		if res.count >= s.Ban {
			banCount++
		} else if res.count >= s.Block {
			blockCount++
		} else if res.count >= s.Suspicious {
			suspiciousCount++
		}
	}

	// Any single strategy at ban → signal
	if banCount >= 1 {
		return []RiskSignal{{
			Name:   "rate_limit_ban",
			Score:  90,
			Reason: "rate limit ban threshold exceeded",
			Weight: 1.0,
		}}
	}

	// 2+ strategies at block → signal
	if blockCount >= 2 {
		return []RiskSignal{{
			Name:   "rate_limit_block",
			Score:  60,
			Reason: "rate limit block threshold exceeded (majority vote)",
			Weight: 1.0,
		}}
	}

	// 2+ strategies at suspicious → signal
	if suspiciousCount >= 2 {
		return []RiskSignal{{
			Name:   "rate_limit_suspicious",
			Score:  20,
			Reason: "rate limit suspicious threshold exceeded (majority vote)",
			Weight: 1.0,
		}}
	}

	return nil
}
