package security

import (
	"testing"
	"time"
)

// fixedClock returns a controllable time source for deterministic TTL tests.
func fixedClock(t *time.Time) func() time.Time {
	return func() time.Time { return *t }
}

// TestDecisionCache_AsymmetricTTL asserts ADR-003: an ALLOW is cached long, a
// BLOCK short. Reverting to a single (or no) TTL fails this test.
func TestDecisionCache_AsymmetricTTL(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	c := NewDecisionCache(100, 30*time.Minute, 30*time.Second)
	c.now = fixedClock(&now)

	c.Set("client-a|ja4", &PipelineResult{Action: "allow"})
	c.Set("client-b|ja4", &PipelineResult{Action: "block"})

	// 45s later: the block has expired, the allow has not.
	now = now.Add(45 * time.Second)
	if _, ok := c.Get("client-b|ja4"); ok {
		t.Error("block entry should have expired after 30s block TTL")
	}
	if _, ok := c.Get("client-a|ja4"); !ok {
		t.Error("allow entry should still be live 45s in (30m allow TTL)")
	}

	// Past the allow TTL: the allow expires too.
	now = now.Add(31 * time.Minute)
	if _, ok := c.Get("client-a|ja4"); ok {
		t.Error("allow entry should have expired after 30m allow TTL")
	}
}

// TestDecisionCache_NonAllowUsesBlockTTL: every non-allow action gets the short
// TTL, not just "block".
func TestDecisionCache_NonAllowUsesBlockTTL(t *testing.T) {
	for _, action := range []string{"block", "ban", "tarpit", "rate_limit", "flag"} {
		now := time.Unix(2_000_000, 0)
		c := NewDecisionCache(100, 30*time.Minute, 30*time.Second)
		c.now = fixedClock(&now)
		c.Set("k|ja4", &PipelineResult{Action: action})
		now = now.Add(31 * time.Second)
		if _, ok := c.Get("k|ja4"); ok {
			t.Errorf("action %q should use the short block TTL and be expired after 31s", action)
		}
	}
}

// TestDecisionCache_ExpiryOnReadRemovesEntry: an expired entry is a miss and is
// deleted from the map (not left to accumulate).
func TestDecisionCache_ExpiryOnReadRemovesEntry(t *testing.T) {
	now := time.Unix(3_000_000, 0)
	c := NewDecisionCache(100, time.Minute, time.Second)
	c.now = fixedClock(&now)
	c.Set("k|ja4", &PipelineResult{Action: "block"})
	now = now.Add(2 * time.Second)
	if _, ok := c.Get("k|ja4"); ok {
		t.Fatal("expected expired miss")
	}
	c.mu.RLock()
	_, present := c.data["k|ja4"]
	c.mu.RUnlock()
	if present {
		t.Error("expired entry should be removed from the map on read")
	}
}

// TestDecisionCache_EmptyKeyGuard: Set("") is a no-op and Get("") is a miss.
func TestDecisionCache_EmptyKeyGuard(t *testing.T) {
	c := NewDecisionCache(100, time.Minute, time.Second)
	c.Set("", &PipelineResult{Action: "block"})
	if _, ok := c.Get(""); ok {
		t.Error("empty key must never be a hit")
	}
	if len(c.data) != 0 {
		t.Error("Set with empty key must not store anything")
	}
}

// TestDecisionCache_NilResultGuard: Set with a nil result is a no-op.
func TestDecisionCache_NilResultGuard(t *testing.T) {
	c := NewDecisionCache(100, time.Minute, time.Second)
	c.Set("k|ja4", nil)
	if _, ok := c.Get("k|ja4"); ok {
		t.Error("nil result must not be cached")
	}
}

// TestDecisionCache_EvictionBounded: inserting well past the limit keeps the map
// bounded and prefers evicting already-expired entries.
func TestDecisionCache_EvictionBounded(t *testing.T) {
	now := time.Unix(4_000_000, 0)
	limit := 50
	c := NewDecisionCache(limit, 30*time.Minute, 30*time.Second)
	c.now = fixedClock(&now)
	for i := 0; i < limit*4; i++ {
		c.Set(itoa(int64(i))+"|ja4", &PipelineResult{Action: "allow"})
	}
	c.mu.RLock()
	n := len(c.data)
	c.mu.RUnlock()
	if n > limit {
		t.Errorf("cache grew past limit: %d > %d", n, limit)
	}
}

// TestDecisionCache_DefaultsOnNonPositive: non-positive limit/TTLs fall back to
// the ADR-003 defaults rather than disabling expiry or the map.
func TestDecisionCache_DefaultsOnNonPositive(t *testing.T) {
	c := NewDecisionCache(0, 0, 0)
	if c.limit != 10000 {
		t.Errorf("limit default: got %d, want 10000", c.limit)
	}
	if c.allowTTL != defaultAllowTTL {
		t.Errorf("allowTTL default: got %v, want %v", c.allowTTL, defaultAllowTTL)
	}
	if c.blockTTL != defaultBlockTTL {
		t.Errorf("blockTTL default: got %v, want %v", c.blockTTL, defaultBlockTTL)
	}
}

// TestDecisionCacheKey_IncludesClientIP: the composite key must vary by client
// IP so two clients sharing a JA4 never collide. This is the core of
// JA4PROXY-2026-0087.
func TestDecisionCacheKey_IncludesClientIP(t *testing.T) {
	same := decisionCacheKey("1.1.1.1", "ja4v")
	other := decisionCacheKey("2.2.2.2", "ja4v")
	if same == other {
		t.Fatalf("clients sharing a JA4 must not share a cache key: %q == %q", same, other)
	}
	if decisionCacheKey("1.1.1.1", "ja4v") != same {
		t.Error("key must be deterministic for the same (ip, ja4)")
	}
}
