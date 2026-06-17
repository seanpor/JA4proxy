package tap_test

// Closed-loop test for the out-of-band enforcement bridge (PHASE_316d): the TAP
// sensor computes a JA4T from a SYN and, when that JA4T is on the enforcement
// blocklist, records a ban intent. Armed, it writes the canonical ban:{ip} key
// that the inline proxy already hard-blocks on (internal/security/pipeline.go,
// phase-231a) — so the loop "sensor sees → next connection is blocked" is proven
// against a real Redis, not a mock. Unarmed, only the advisory watchlist appears.

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/seanpor/ja4proxy/internal/tap"
)

func TestRoundTrip_ArmedWritesEnforceableBan(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	br := redisBridge{c: goredis.NewClient(&goredis.Options{Addr: mr.Addr()})}
	ctx := context.Background()

	const ip = "198.51.100.40"
	ja4t := tap.ComputeJA4T(linuxStack())
	if ja4t == "" {
		t.Fatal("precondition: ComputeJA4T(linuxStack) returned empty")
	}

	enf := tap.NewEnforcer(tap.EnforcerConfig{
		Armed:         true,
		JA4TBlocklist: map[string]bool{ja4t: true},
		BanTTL:        90 * time.Second,
		IntentTTL:     30 * time.Minute,
	}, br)
	enf.Consider(ctx, ip, ja4t)

	// The inline proxy enforces via EXISTS ban:{ip} — assert that exact key.
	if !mr.Exists("ban:" + ip) {
		t.Fatal("armed enforcement must write ban:{ip} the inline proxy reads — loop broken")
	}
	if ttl := mr.TTL("ban:" + ip); ttl != 90*time.Second {
		t.Errorf("ban TTL = %v; want 90s", ttl)
	}
	if !mr.Exists("fp:ban_intent:ip:" + ip) {
		t.Error("armed path must also record the advisory watchlist for audit")
	}
}

func TestRoundTrip_UnarmedNeverWritesBan(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	br := redisBridge{c: goredis.NewClient(&goredis.Options{Addr: mr.Addr()})}
	ctx := context.Background()

	const ip = "198.51.100.41"
	ja4t := tap.ComputeJA4T(linuxStack())

	// Default posture (not armed) — the same blocklisted JA4T must NOT block.
	enf := tap.NewEnforcer(tap.EnforcerConfig{
		JA4TBlocklist: map[string]bool{ja4t: true},
	}, br)
	enf.Consider(ctx, ip, ja4t)

	if mr.Exists("ban:" + ip) {
		t.Fatal("unarmed sensor must NEVER write ban:{ip} — this would block on a passive guess")
	}
	if !mr.Exists("fp:ban_intent:ip:" + ip) {
		t.Error("unarmed match should still record the advisory watchlist")
	}
}
