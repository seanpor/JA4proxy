package tap_test

// Closed-loop test for the JA4T blocklist signal (PHASE_316c): the TAP sensor
// computes the JA4T from a SYN and writes fp:ja4t:ip via internal/tap; the inline
// proxy consumer reads it via internal/security and emits tap_ja4t_blocklist when
// the observed JA4T is blocklisted. Writer and reader share one Redis and the same
// canonical JA4T string, so the loop is proven end to end — the discipline the
// dormant 203a OS-mismatch signal originally lacked.

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/seanpor/ja4proxy/internal/security"
	"github.com/seanpor/ja4proxy/internal/tap"
)

func newJA4TConsumer(br redisBridge, blocklist ...string) *security.JA4TConsumer {
	set := make(map[string]bool, len(blocklist))
	for _, j := range blocklist {
		set[j] = true
	}
	return security.NewJA4TConsumer(&security.JA4TConsumerConfig{
		Enabled:      true,
		SignalScore:  30,
		RedisTimeout: 200 * time.Millisecond,
		CacheTTL:     time.Second,
		Blocklist:    set,
	}, br, nil)
}

func TestRoundTrip_JA4TBlocklistFires(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	br := redisBridge{c: goredis.NewClient(&goredis.Options{Addr: mr.Addr()})}
	ctx := context.Background()

	const ip = "198.51.100.20"
	// Sensor computes the JA4T from a Linux-style SYN and writes it.
	ja4t := tap.ComputeJA4T(linuxStack())
	if ja4t == "" {
		t.Fatal("precondition: ComputeJA4T(linuxStack) returned empty")
	}
	tap.NewStore(br).WriteJA4T(ctx, ip, ja4t)
	if got, _ := mr.Get("fp:ja4t:ip:" + ip); got != ja4t {
		t.Fatalf("fp:ja4t:ip not written verbatim; got %q want %q", got, ja4t)
	}

	// Operator blocklists exactly that JA4T → the consumer fires.
	sig := newJA4TConsumer(br, ja4t).GetSignal(ctx, ip)
	if sig == nil {
		t.Fatal("expected tap_ja4t_blocklist signal; got nil — the loop is broken")
	}
	if sig.Name != "tap_ja4t_blocklist" {
		t.Errorf("signal Name = %q; want tap_ja4t_blocklist", sig.Name)
	}
	if sig.Score != 30 {
		t.Errorf("signal Score = %d; want 30", sig.Score)
	}
}

func TestRoundTrip_JA4TNotBlocklistedSilent(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	br := redisBridge{c: goredis.NewClient(&goredis.Options{Addr: mr.Addr()})}
	ctx := context.Background()

	const ip = "198.51.100.21"
	ja4t := tap.ComputeJA4T(windowsStack())
	tap.NewStore(br).WriteJA4T(ctx, ip, ja4t)

	// Blocklist holds a different JA4T → no signal for this observed one.
	if sig := newJA4TConsumer(br, "0_0_0_0").GetSignal(ctx, ip); sig != nil {
		t.Errorf("a non-blocklisted JA4T must be silent; got %+v", sig)
	}
}

func TestRoundTrip_JA4TNoSYNWritesNothing(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	br := redisBridge{c: goredis.NewClient(&goredis.Options{Addr: mr.Addr()})}
	ctx := context.Background()

	const ip = "198.51.100.22"
	// Mid-stream capture: no SYN → empty JA4T → nothing written → nothing fires.
	noSYN := tap.StackFeatures{HasSYN: false}
	ja4t := tap.ComputeJA4T(noSYN)
	if ja4t != "" {
		t.Fatalf("precondition: no-SYN JA4T should be empty; got %q", ja4t)
	}
	tap.NewStore(br).WriteJA4T(ctx, ip, ja4t)
	if mr.Exists("fp:ja4t:ip:" + ip) {
		t.Error("empty JA4T must not write a key")
	}
	// Even with a blocklist that would match a real JA4T, a missing key is silent.
	if sig := newJA4TConsumer(br, tap.ComputeJA4T(linuxStack())).GetSignal(ctx, ip); sig != nil {
		t.Errorf("no observed JA4T must produce no signal; got %+v", sig)
	}
}
