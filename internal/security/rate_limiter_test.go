package security

import (
	"context"
	"testing"
)

// mockRedisCounter implements RedisReader for rate limiter tests.
type mockRedisCounter struct {
	mockRedis
	counts map[string]int
}

func (m *mockRedisCounter) SlidingWindowCount(_ context.Context, key string, _ float64, _ int) int {
	return m.counts[key]
}

func defaultRateLimiterCfg() *RateLimiterConfig {
	return &RateLimiterConfig{
		Enabled: true,
		ByIP:    StrategyConfig{Enabled: true, Suspicious: 50, Block: 200, Ban: 500, Window: 1, TTL: 300},
		ByJA4:   StrategyConfig{Enabled: true, Suspicious: 20, Block: 100, Ban: 200, Window: 1, TTL: 300},
		ByIPJA4: StrategyConfig{Enabled: true, Suspicious: 20, Block: 50, Ban: 100, Window: 1, TTL: 300},
	}
}

func TestRateLimiter_Disabled_NoSignal(t *testing.T) {
	cfg := defaultRateLimiterCfg()
	cfg.Enabled = false
	rl := NewRateLimiter(cfg, &mockRedisCounter{counts: map[string]int{
		"ratelimit:ip:1.2.3.4": 1000,
	}}, nil)
	sigs := rl.Check(context.Background(), "1.2.3.4", "t13d1234")
	if len(sigs) != 0 {
		t.Errorf("disabled rate limiter: expected no signals, got %d", len(sigs))
	}
}

func TestRateLimiter_BelowThreshold_NoSignal(t *testing.T) {
	cfg := defaultRateLimiterCfg()
	rl := NewRateLimiter(cfg, &mockRedisCounter{counts: map[string]int{
		"ratelimit:ip:1.2.3.4":              10,
		"ratelimit:ja4:t13d1234":            5,
		"ratelimit:ip_ja4:1.2.3.4:t13d1234": 3,
	}}, nil)
	sigs := rl.Check(context.Background(), "1.2.3.4", "t13d1234")
	if len(sigs) != 0 {
		t.Errorf("below threshold: expected no signals, got %d", len(sigs))
	}
}

func TestRateLimiter_SingleStrategy_Suspicious_NoSignal(t *testing.T) {
	// Only 1 strategy hits suspicious — majority=2 required, so no signal.
	cfg := defaultRateLimiterCfg()
	rl := NewRateLimiter(cfg, &mockRedisCounter{counts: map[string]int{
		"ratelimit:ip:1.2.3.4":              60, // above Suspicious(50) for ByIP
		"ratelimit:ja4:t13d1234":            5,  // below Suspicious(20) for ByJA4
		"ratelimit:ip_ja4:1.2.3.4:t13d1234": 3,  // below Suspicious(20) for ByIPJA4
	}}, nil)
	sigs := rl.Check(context.Background(), "1.2.3.4", "t13d1234")
	if len(sigs) != 0 {
		t.Errorf("single strategy suspicious: expected no signal (majority=2 required), got %d signals", len(sigs))
	}
}

func TestRateLimiter_MajoritySuspicious_SignalFired(t *testing.T) {
	cfg := defaultRateLimiterCfg()
	rl := NewRateLimiter(cfg, &mockRedisCounter{counts: map[string]int{
		"ratelimit:ip:1.2.3.4":              60, // ByIP: suspicious (>50)
		"ratelimit:ja4:t13d1234":            25, // ByJA4: suspicious (>20)
		"ratelimit:ip_ja4:1.2.3.4:t13d1234": 3,  // ByIPJA4: below threshold
	}}, nil)
	sigs := rl.Check(context.Background(), "1.2.3.4", "t13d1234")
	if len(sigs) == 0 {
		t.Fatal("majority suspicious: expected signal, got none")
	}
	if sigs[0].Name != "rate_limit_suspicious" {
		t.Errorf("expected 'rate_limit_suspicious', got %q", sigs[0].Name)
	}
}

func TestRateLimiter_MajorityBlock_SignalFired(t *testing.T) {
	cfg := defaultRateLimiterCfg()
	rl := NewRateLimiter(cfg, &mockRedisCounter{counts: map[string]int{
		"ratelimit:ip:1.2.3.4":              250, // ByIP: block (>200)
		"ratelimit:ja4:t13d1234":            120, // ByJA4: block (>100)
		"ratelimit:ip_ja4:1.2.3.4:t13d1234": 3,   // ByIPJA4: below threshold
	}}, nil)
	sigs := rl.Check(context.Background(), "1.2.3.4", "t13d1234")
	if len(sigs) == 0 {
		t.Fatal("majority block: expected signal, got none")
	}
	if sigs[0].Name != "rate_limit_block" {
		t.Errorf("expected 'rate_limit_block', got %q", sigs[0].Name)
	}
}

func TestRateLimiter_AnyBan_SignalFired(t *testing.T) {
	// Single strategy at ban level → signal (no majority required).
	cfg := defaultRateLimiterCfg()
	rl := NewRateLimiter(cfg, &mockRedisCounter{counts: map[string]int{
		"ratelimit:ip:1.2.3.4":              600, // ByIP: ban (>500)
		"ratelimit:ja4:t13d1234":            5,   // ByJA4: below threshold
		"ratelimit:ip_ja4:1.2.3.4:t13d1234": 3,   // ByIPJA4: below threshold
	}}, nil)
	sigs := rl.Check(context.Background(), "1.2.3.4", "t13d1234")
	if len(sigs) == 0 {
		t.Fatal("any ban: expected signal, got none")
	}
	if sigs[0].Name != "rate_limit_ban" {
		t.Errorf("expected 'rate_limit_ban', got %q", sigs[0].Name)
	}
}

func TestRateLimiter_EmptyJA4_SkipsJA4Strategies(t *testing.T) {
	cfg := defaultRateLimiterCfg()
	// Only ByIP key will be checked; JA4 strategies skipped since ja4="".
	rl := NewRateLimiter(cfg, &mockRedisCounter{counts: map[string]int{
		"ratelimit:ip:1.2.3.4": 10,
	}}, nil)
	sigs := rl.Check(context.Background(), "1.2.3.4", "")
	// Only 1 strategy result available (ByIP) — can't reach majority for any level.
	if len(sigs) != 0 {
		t.Errorf("empty JA4: expected no signals, got %d", len(sigs))
	}
}

func TestRateLimiter_HighestLevelWins(t *testing.T) {
	// Both block and ban conditions are met — ban should win.
	cfg := defaultRateLimiterCfg()
	rl := NewRateLimiter(cfg, &mockRedisCounter{counts: map[string]int{
		"ratelimit:ip:1.2.3.4":              600, // ByIP: ban (>500)
		"ratelimit:ja4:t13d1234":            250, // ByJA4: block (>100)
		"ratelimit:ip_ja4:1.2.3.4:t13d1234": 60,  // ByIPJA4: block (>50)
	}}, nil)
	sigs := rl.Check(context.Background(), "1.2.3.4", "t13d1234")
	if len(sigs) == 0 {
		t.Fatal("highest level wins: expected signal, got none")
	}
	if sigs[0].Name != "rate_limit_ban" {
		t.Errorf("expected 'rate_limit_ban' (ban beats block), got %q", sigs[0].Name)
	}
}
