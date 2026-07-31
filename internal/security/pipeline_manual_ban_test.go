package security

import (
	"context"
	"net"
	"testing"
)

// banRedis is a RedisReader whose GetString() reports the configured ban
// values (everything else inherits mockRedis, which returns "" / zero). D-001
// switched the pipeline's ban check from Exists() to GetString() so it can
// distinguish sensor-enforced from operator bans by value.
type banRedis struct {
	mockRedis
	banned map[string]string // key -> ban value; "manual ban reason text" for operator bans
}

func (b *banRedis) GetString(_ context.Context, key string) string { return b.banned[key] }

// phase-231a: a manual ban (`ban:{ip}`) hard-blocks immediately, even in monitor
// mode (dial=0), because the check runs before the dial is fetched.
func TestPipeline_ManualBanBlocksAtDialZero(t *testing.T) {
	p := newTestPipeline(0) // monitor mode — nothing else would block here
	p.redis = &banRedis{banned: map[string]string{"ban:9.9.9.9": "operator ban: abuse"}}

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

// A non-banned IP is not treated as a manual ban (and GetString()=="" is
// exactly the fail-open path: a Redis error returns "", so an outage never
// blocks).
func TestPipeline_NoManualBan(t *testing.T) {
	p := newTestPipeline(0)
	p.redis = &banRedis{banned: map[string]string{"ban:9.9.9.9": "operator ban: abuse"}}

	res := p.Process(context.Background(), &ConnectionContext{
		ParsedIP: net.ParseIP("5.6.7.8"), ClientIP: "5.6.7.8", // not banned
	})
	if res.BypassReason == "manual_ban" {
		t.Fatalf("unbanned IP wrongly flagged manual_ban: %+v", res)
	}
}

// TestPipeline_TapEnforcedBanReasonDistinguished guards D-001: a ban:{ip}
// value written by the TAP sensor's Enforcer ("tap_enforce:ja4t=...") must
// report BypassReason "tap_enforce_ban", not the operator-ban label
// "manual_ban" — the two previously looked identical because the old check
// only tested key existence, never the value.
func TestPipeline_TapEnforcedBanReasonDistinguished(t *testing.T) {
	p := newTestPipeline(0)
	p.redis = &banRedis{banned: map[string]string{"ban:9.9.9.9": "tap_enforce:ja4t=64240_2-1-3-1-1-4_1460_8"}}

	res := p.Process(context.Background(), &ConnectionContext{
		ParsedIP: net.ParseIP("9.9.9.9"), ClientIP: "9.9.9.9",
	})
	if res.Action != "block" {
		t.Fatalf("tap-enforced ban: action = %q, want block", res.Action)
	}
	if res.BypassReason != "tap_enforce_ban" {
		t.Fatalf("tap-enforced ban: reason = %q, want tap_enforce_ban", res.BypassReason)
	}
}
