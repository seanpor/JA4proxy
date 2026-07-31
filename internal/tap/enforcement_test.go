package tap

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// recordingSetter captures every Set call (the armed path issues two: the
// watchlist write then the ban write), unlike fakeSetter which keeps only the
// last. failOn, when non-empty, makes the matching key's write return an error.
type recordingSetter struct {
	calls  []setCall
	failOn string
}

type setCall struct {
	key, value string
	ttl        time.Duration
}

func (r *recordingSetter) Set(_ context.Context, key, value string, ttl time.Duration) error {
	if r.failOn != "" && key == r.failOn {
		return errors.New("redis down")
	}
	r.calls = append(r.calls, setCall{key, value, ttl})
	return nil
}

func enfCounter(result string) float64 {
	return testutil.ToFloat64(EnforcementActionsTotal.WithLabelValues(result))
}

const blocklistedJA4T = "64240_2-1-3-1-1-4_1460_8"

func armedCfg(rs *recordingSetter) (EnforcerConfig, *recordingSetter) {
	return EnforcerConfig{
		Armed:         true,
		JA4TBlocklist: map[string]bool{blocklistedJA4T: true},
		BanTTL:        90 * time.Second,
		IntentTTL:     30 * time.Minute,
	}, rs
}

func TestEnforcer_UnarmedWritesWatchlistOnly(t *testing.T) {
	before := enfCounter(enfWatchlist)
	rs := &recordingSetter{}
	cfg := EnforcerConfig{JA4TBlocklist: map[string]bool{blocklistedJA4T: true}}
	NewEnforcer(cfg, rs).Consider(context.Background(), "203.0.113.9", blocklistedJA4T)

	if len(rs.calls) != 1 {
		t.Fatalf("unarmed match should write exactly the watchlist; got %d writes", len(rs.calls))
	}
	c := rs.calls[0]
	if c.key != "fp:ban_intent:ip:203.0.113.9" {
		t.Errorf("watchlist key = %q; want fp:ban_intent:ip:203.0.113.9", c.key)
	}
	if c.value != "ja4t="+blocklistedJA4T {
		t.Errorf("watchlist value = %q; want provenance ja4t=...", c.value)
	}
	if c.ttl != defaultIntentTTL {
		t.Errorf("watchlist ttl = %v; want default %v", c.ttl, defaultIntentTTL)
	}
	if got := enfCounter(enfWatchlist); got != before+1 {
		t.Errorf("watchlist counter %v -> %v; want +1", before, got)
	}
}

func TestEnforcer_ArmedWritesIntentThenBan(t *testing.T) {
	before := enfCounter(enfBanned)
	cfg, rs := armedCfg(&recordingSetter{})
	NewEnforcer(cfg, rs).Consider(context.Background(), "203.0.113.9", blocklistedJA4T)

	if len(rs.calls) != 2 {
		t.Fatalf("armed match should write watchlist AND ban; got %d writes", len(rs.calls))
	}
	intent, ban := rs.calls[0], rs.calls[1]
	if intent.key != "fp:ban_intent:ip:203.0.113.9" {
		t.Errorf("first write must be the watchlist; got key %q", intent.key)
	}
	if ban.key != "ban:203.0.113.9" {
		t.Errorf("ban key = %q; want ban:203.0.113.9", ban.key)
	}
	if ban.value != "tap_enforce:ja4t="+blocklistedJA4T {
		t.Errorf("ban value = %q; want provenance tap_enforce:ja4t=...", ban.value)
	}
	if ban.ttl != 90*time.Second {
		t.Errorf("ban ttl = %v; want configured 90s", ban.ttl)
	}
	if got := enfCounter(enfBanned); got != before+1 {
		t.Errorf("banned counter %v -> %v; want +1", before, got)
	}
}

func TestEnforcer_NonMatchingJA4TDoesNothing(t *testing.T) {
	before := enfCounter(enfSkipped)
	cfg, rs := armedCfg(&recordingSetter{})
	NewEnforcer(cfg, rs).Consider(context.Background(), "203.0.113.9", "1024_2_536_0")
	if len(rs.calls) != 0 {
		t.Errorf("non-blocklisted JA4T must not write; got %d", len(rs.calls))
	}
	if got := enfCounter(enfSkipped); got != before+1 {
		t.Errorf("skipped counter %v -> %v; want +1", before, got)
	}
}

func TestEnforcer_EmptyBlocklistShortCircuits(t *testing.T) {
	before := enfCounter(enfSkipped)
	rs := &recordingSetter{}
	// Armed but empty blocklist: the default-safe state must never write a ban.
	NewEnforcer(EnforcerConfig{Armed: true}, rs).Consider(context.Background(), "203.0.113.9", blocklistedJA4T)
	if len(rs.calls) != 0 {
		t.Errorf("empty blocklist must short-circuit before any write; got %d", len(rs.calls))
	}
	if got := enfCounter(enfSkipped); got != before+1 {
		t.Errorf("skipped counter %v -> %v; want +1", before, got)
	}
}

func TestEnforcer_EmptyJA4TSkips(t *testing.T) {
	before := enfCounter(enfSkipped)
	cfg, rs := armedCfg(&recordingSetter{})
	NewEnforcer(cfg, rs).Consider(context.Background(), "203.0.113.9", "")
	if len(rs.calls) != 0 {
		t.Errorf("empty JA4T (no SYN) must not write; got %d", len(rs.calls))
	}
	if got := enfCounter(enfSkipped); got != before+1 {
		t.Errorf("skipped counter %v -> %v; want +1", before, got)
	}
}

func TestEnforcer_UnparsableIPCountsError(t *testing.T) {
	before := enfCounter(enfError)
	cfg, rs := armedCfg(&recordingSetter{})
	NewEnforcer(cfg, rs).Consider(context.Background(), "not-an-ip", blocklistedJA4T)
	if len(rs.calls) != 0 {
		t.Errorf("unparsable IP must not write; got %d", len(rs.calls))
	}
	if got := enfCounter(enfError); got != before+1 {
		t.Errorf("error counter %v -> %v; want +1", before, got)
	}
}

func TestEnforcer_NilBackendSkips(t *testing.T) {
	before := enfCounter(enfSkipped)
	cfg := EnforcerConfig{Armed: true, JA4TBlocklist: map[string]bool{blocklistedJA4T: true}}
	NewEnforcer(cfg, nil).Consider(context.Background(), "203.0.113.9", blocklistedJA4T)
	if got := enfCounter(enfSkipped); got != before+1 {
		t.Errorf("nil backend should count skipped; %v -> %v", before, got)
	}
}

func TestEnforcer_WatchlistErrorFailsOpenAndSkipsBan(t *testing.T) {
	before := enfCounter(enfError)
	cfg, _ := armedCfg(&recordingSetter{})
	rs := &recordingSetter{failOn: "fp:ban_intent:ip:203.0.113.9"}
	NewEnforcer(cfg, rs).Consider(context.Background(), "203.0.113.9", blocklistedJA4T)
	// Watchlist write failed → Redis unhealthy → must NOT attempt the ban.
	if len(rs.calls) != 0 {
		t.Errorf("a failed watchlist write must abort before the ban; got %d writes", len(rs.calls))
	}
	if got := enfCounter(enfError); got != before+1 {
		t.Errorf("error counter %v -> %v; want +1", before, got)
	}
}

func TestEnforcer_BanErrorFailsOpen(t *testing.T) {
	before := enfCounter(enfError)
	cfg, _ := armedCfg(&recordingSetter{})
	rs := &recordingSetter{failOn: "ban:203.0.113.9"}
	NewEnforcer(cfg, rs).Consider(context.Background(), "203.0.113.9", blocklistedJA4T)
	// Watchlist succeeds, ban fails — counted as error, never propagated.
	if len(rs.calls) != 1 || rs.calls[0].key != "fp:ban_intent:ip:203.0.113.9" {
		t.Errorf("watchlist should persist even if ban fails; calls=%v", rs.calls)
	}
	if got := enfCounter(enfError); got != before+1 {
		t.Errorf("error counter %v -> %v; want +1", before, got)
	}
}

func TestEnforcer_CanonicalisesIP(t *testing.T) {
	cases := []struct{ in, wantIntent string }{
		{"203.0.113.9", "fp:ban_intent:ip:203.0.113.9"},
		{"2001:DB8::1", "fp:ban_intent:ip:2001:db8::1"},
		{"[2001:db8::1]", "fp:ban_intent:ip:2001:db8::1"},
		{"fe80::1%eth0", "fp:ban_intent:ip:fe80::1"},
	}
	for _, c := range cases {
		cfg, rs := armedCfg(&recordingSetter{})
		NewEnforcer(cfg, rs).Consider(context.Background(), c.in, blocklistedJA4T)
		if len(rs.calls) == 0 || rs.calls[0].key != c.wantIntent {
			t.Errorf("Consider(%q) intent key = %v; want %q", c.in, rs.calls, c.wantIntent)
		}
	}
}

func TestNewEnforcer_PublishesArmedGauge(t *testing.T) {
	NewEnforcer(EnforcerConfig{Armed: true}, nil)
	if g := testutil.ToFloat64(EnforcementArmed); g != 1 {
		t.Errorf("armed gauge = %v; want 1", g)
	}
	NewEnforcer(EnforcerConfig{Armed: false}, nil)
	if g := testutil.ToFloat64(EnforcementArmed); g != 0 {
		t.Errorf("armed gauge = %v; want 0", g)
	}
}

func TestEnforcer_NilReceiverSafe(t *testing.T) {
	var e *Enforcer
	e.Consider(context.Background(), "203.0.113.9", blocklistedJA4T) // must not panic
}

func TestNewEnforcer_DefaultsZeroTTLs(t *testing.T) {
	cfg := EnforcerConfig{JA4TBlocklist: map[string]bool{blocklistedJA4T: true}}
	rs := &recordingSetter{}
	NewEnforcer(cfg, rs).Consider(context.Background(), "203.0.113.9", blocklistedJA4T)
	if rs.calls[0].ttl != defaultIntentTTL {
		t.Errorf("zero IntentTTL should default to %v; got %v", defaultIntentTTL, rs.calls[0].ttl)
	}
}

// TestEnforcer_ConcurrentBlocklistReloadIsRaceFree exercises F-016: a
// SetBlocklist call (simulating a config-reload handler) racing Consider's
// hot-path reads must never trigger Go's "concurrent map read and map write"
// panic. Run with -race to actually catch a regression.
func TestEnforcer_ConcurrentBlocklistReloadIsRaceFree(t *testing.T) {
	e := NewEnforcer(EnforcerConfig{Armed: false, JA4TBlocklist: map[string]bool{blocklistedJA4T: true}}, &recordingSetter{})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			e.SetBlocklist(map[string]bool{blocklistedJA4T: true})
		}
	}()

	for i := 0; i < 200; i++ {
		e.Consider(context.Background(), "203.0.113.9", blocklistedJA4T)
	}
	<-done
}
