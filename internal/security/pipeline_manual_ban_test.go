package security

import (
	"context"
	"net"
	"testing"
)

// banRedis is a RedisReader whose Exists() reports the configured banned keys
// (everything else inherits mockRedis, which returns false / zero).
type banRedis struct {
	mockRedis
	banned map[string]bool
}

func (b *banRedis) Exists(_ context.Context, key string) bool { return b.banned[key] }

// phase-231a: a manual ban (`ban:{ip}`) hard-blocks immediately, even in monitor
// mode (dial=0), because the check runs before the dial is fetched.
func TestPipeline_ManualBanBlocksAtDialZero(t *testing.T) {
	p := newTestPipeline(0) // monitor mode — nothing else would block here
	p.redis = &banRedis{banned: map[string]bool{"ban:9.9.9.9": true}}

	res := p.Process(context.Background(), &ConnectionContext{
		ParsedIP: net.ParseIP("9.9.9.9"), ClientIP: "9.9.9.9",
	})
	if res.Action != "block" {
		t.Fatalf("manual ban at dial=0: action = %q, want block", res.Action)
	}
	if res.BypassReason != "manual_ban" {
		t.Fatalf("manual ban: reason = %q, want manual_ban", res.BypassReason)
	}
}

// A non-banned IP is not treated as a manual ban (and Exists()==false is exactly
// the fail-open path: a Redis error returns false, so an outage never blocks).
func TestPipeline_NoManualBan(t *testing.T) {
	p := newTestPipeline(0)
	p.redis = &banRedis{banned: map[string]bool{"ban:9.9.9.9": true}}

	res := p.Process(context.Background(), &ConnectionContext{
		ParsedIP: net.ParseIP("5.6.7.8"), ClientIP: "5.6.7.8", // not banned
	})
	if res.BypassReason == "manual_ban" {
		t.Fatalf("unbanned IP wrongly flagged manual_ban: %+v", res)
	}
}
