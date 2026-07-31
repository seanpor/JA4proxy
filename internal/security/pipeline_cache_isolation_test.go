package security

import (
	"context"
	"net"
	"testing"
	"time"
)

// isoBanRedis reports a ban for exactly one IP; everything else inherits the
// zero-value mockRedis behaviour.
type isoBanRedis struct {
	mockRedis
	bannedKey string
}

func (b *isoBanRedis) GetString(_ context.Context, key string) string {
	if key == b.bannedKey {
		return "operator ban: abuse"
	}
	return ""
}

// waitForCache polls the decision cache until key is present or the deadline
// elapses. The production pipeline scores asynchronously, so the caching side
// effect is not visible synchronously after Process returns.
func waitForCache(c *DecisionCache, key string) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := c.Get(key); ok {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return false
}

// TestPipeline_CacheDoesNotLeakAcrossClients is the JA4PROXY-2026-0087
// regression. It drives the real async scoring path (Sync=false, the
// production default): one banned IP is scored to "block" and cached; a
// different IP that merely shares the same JA4 must NOT inherit that block.
//
// If the cache is reverted to keying on JA4 alone, the banned IP's block is
// cached under the bare JA4 and the second client gets a cache hit → "block",
// failing this test.
func TestPipeline_CacheDoesNotLeakAcrossClients(t *testing.T) {
	const sharedJA4 = "t13d1516h2_deadbeefcafe_0011223344ff"
	const bannedIP = "203.0.113.10"
	const innocentIP = "198.51.100.20"

	cfg := &PipelineConfig{
		JA4BlockingEnabled: true,
		// Long allow TTL, short block TTL — ADR-003 defaults are fine here.
		DecisionCacheAllowTTLSeconds: 1800,
		DecisionCacheBlockTTLSeconds: 30,
	}
	p := NewPipeline(cfg, &isoBanRedis{bannedKey: "ban:" + bannedIP}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.StartBackgroundWorkers(ctx)

	// 1. Banned client connects. Async returns allow immediately; the real
	//    decision (block, manual_ban) is scored in the background and cached
	//    under the banned client's composite key.
	p.Process(ctx, &ConnectionContext{
		ClientIP: bannedIP, ParsedIP: net.ParseIP(bannedIP), JA4: sharedJA4,
	})
	bannedKey := decisionCacheKey(bannedIP, sharedJA4)
	if !waitForCache(p.cache, bannedKey) {
		t.Fatal("banned client's decision was never cached")
	}
	if res, _ := p.cache.Get(bannedKey); res == nil || res.Action != "block" {
		t.Fatalf("banned client should be cached as block, got %+v", res)
	}

	// 2. An innocent client sharing the same JA4 must not be blocked by the
	//    banned client's cached decision.
	res := p.Process(ctx, &ConnectionContext{
		ClientIP: innocentIP, ParsedIP: net.ParseIP(innocentIP), JA4: sharedJA4,
	})
	if res.Action == "block" || res.Action == "ban" {
		t.Fatalf("innocent client sharing JA4 wrongly got %q from another client's cached decision", res.Action)
	}

	// And its own (allow) decision must cache under its own key, never colliding.
	innocentKey := decisionCacheKey(innocentIP, sharedJA4)
	if !waitForCache(p.cache, innocentKey) {
		t.Fatal("innocent client's own decision was never cached")
	}
	if r, _ := p.cache.Get(innocentKey); r == nil || r.Action == "block" || r.Action == "ban" {
		t.Fatalf("innocent client's cached decision should not be a block/ban: %+v", r)
	}
}
