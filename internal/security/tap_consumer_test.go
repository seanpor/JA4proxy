package security

// Phase 203a — TDD red: TAP-consumed JA4T-OS-mismatch signal.
//
// Contract (from docs/phases/PHASE_203.md sub-phase 203a):
//   type TapConsumer struct { ... }
//   type TapConsumerConfig struct {
//       Enabled        bool
//       SignalScore    int
//       RedisTimeout   time.Duration
//       CacheTTL       time.Duration
//       MaxAge         time.Duration
//   }
//   func NewTapConsumer(cfg *TapConsumerConfig, redis redisClient, log *logrus.Logger) *TapConsumer
//   func (t *TapConsumer) GetSignal(ctx, clientIP, ja4 string) *RiskSignal
//
// The TapConsumer reads fp:os:ip:{clientIP} (String) from Redis.
// It maps JA4 → claimed OS via ja4OSClass(ja4 string) string.
// When claimed != observed → *RiskSignal{Name:"tap_os_mismatch", Score: cfg.SignalScore, Weight:1.0}.
//
// All tests below expect types/functions the 203a implementer must introduce.
// Mock is a simple struct implementing a Get(ctx, key) (string, error) method —
// the exact shape of *redis.Client.Get in internal/redis/client.go.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeRedis is a minimal Get-only Redis fake. The TapConsumer implementer
// must define an interface narrow enough that this fake satisfies it
// (e.g. `type redisClient interface { Get(ctx context.Context, key string) (string, error) }`).
type fakeRedis struct {
	mu       sync.Mutex
	values   map[string]string
	err      error
	delay    time.Duration
	getCalls int64
}

func (f *fakeRedis) Get(ctx context.Context, key string) (string, error) {
	atomic.AddInt64(&f.getCalls, 1)
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if f.err != nil {
		return "", f.err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.values[key]
	if !ok {
		return "", nil
	}
	return v, nil
}

func (f *fakeRedis) calls() int64 { return atomic.LoadInt64(&f.getCalls) }

func newTapConfig() *TapConsumerConfig {
	return &TapConsumerConfig{
		Enabled:      true,
		SignalScore:  30,
		RedisTimeout: 50 * time.Millisecond,
		CacheTTL:     60 * time.Second,
		MaxAge:       300 * time.Second,
	}
}

// A JA4 fingerprint the ja4OSClass table is expected to recognise.
// 203a implementer defines the starter mapping; pick any of the well-known
// browser fingerprints. Using t13d1516h2 (Chrome-on-Windows shape).
const (
	chromeWindowsJA4 = "t13d1516h2_aabbccddeeff_aabbccddeeff"
	unmappedJA4      = "t13d0000zz_000000000000_000000000000" // deliberately fake; no OS mapping
)

func TestTapConsumer_Disabled_ReturnsNil(t *testing.T) {
	cfg := newTapConfig()
	cfg.Enabled = false
	rc := &fakeRedis{values: map[string]string{}}
	tc := NewTapConsumer(cfg, rc, nil)

	got := tc.GetSignal(context.Background(), "1.2.3.4", chromeWindowsJA4)
	if got != nil {
		t.Errorf("disabled consumer must return nil; got %+v", got)
	}
	if rc.calls() != 0 {
		t.Errorf("disabled consumer must not call Redis; got %d calls", rc.calls())
	}
}

func TestTapConsumer_UnknownJA4_ReturnsNil(t *testing.T) {
	rc := &fakeRedis{values: map[string]string{"fp:os:ip:1.2.3.4": "linux"}}
	tc := NewTapConsumer(newTapConfig(), rc, nil)

	got := tc.GetSignal(context.Background(), "1.2.3.4", unmappedJA4)
	if got != nil {
		t.Errorf("unknown-JA4 must return nil (no-signal); got %+v", got)
	}
	if rc.calls() != 0 {
		t.Errorf("unknown-JA4 must short-circuit before Redis; got %d calls", rc.calls())
	}
}

func TestTapConsumer_EmptyJA4_ReturnsNil(t *testing.T) {
	rc := &fakeRedis{values: map[string]string{}}
	tc := NewTapConsumer(newTapConfig(), rc, nil)
	if got := tc.GetSignal(context.Background(), "1.2.3.4", ""); got != nil {
		t.Errorf("empty JA4 must return nil; got %+v", got)
	}
}

func TestTapConsumer_RedisMiss_ReturnsNil(t *testing.T) {
	rc := &fakeRedis{values: map[string]string{}} // no key
	tc := NewTapConsumer(newTapConfig(), rc, nil)

	got := tc.GetSignal(context.Background(), "1.2.3.4", chromeWindowsJA4)
	if got != nil {
		t.Errorf("Redis miss must return nil (fail open); got %+v", got)
	}
	if rc.calls() != 1 {
		t.Errorf("expected exactly 1 Redis call on miss; got %d", rc.calls())
	}
}

func TestTapConsumer_HitMatch_ReturnsNil(t *testing.T) {
	// If ja4OSClass(chromeWindowsJA4) returns "windows" and Redis has "windows" → no signal.
	// The 203a implementer controls both sides; whatever the canonical string is, the
	// fake mirrors it via a claimedOS() helper the implementer exposes OR the test
	// captures the OS by calling the exported ja4OSClass helper directly.
	claimed := callJA4OSClass(t, chromeWindowsJA4)
	if claimed == "" {
		t.Skip("starter ja4OSClass table does not map chromeWindowsJA4; update chromeWindowsJA4 constant in this test to a mapped JA4")
	}

	rc := &fakeRedis{values: map[string]string{"fp:os:ip:1.2.3.4": claimed}}
	tc := NewTapConsumer(newTapConfig(), rc, nil)

	got := tc.GetSignal(context.Background(), "1.2.3.4", chromeWindowsJA4)
	if got != nil {
		t.Errorf("claimed==observed must return nil; got %+v", got)
	}
}

func TestTapConsumer_HitMismatch_ReturnsSignal(t *testing.T) {
	claimed := callJA4OSClass(t, chromeWindowsJA4)
	if claimed == "" {
		t.Skip("starter ja4OSClass table does not map chromeWindowsJA4")
	}
	observed := "linux"
	if claimed == observed {
		observed = "macos"
	}

	rc := &fakeRedis{values: map[string]string{"fp:os:ip:1.2.3.4": observed}}
	cfg := newTapConfig()
	tc := NewTapConsumer(cfg, rc, nil)

	sig := tc.GetSignal(context.Background(), "1.2.3.4", chromeWindowsJA4)
	if sig == nil {
		t.Fatalf("claimed(%q) != observed(%q) must emit a signal; got nil", claimed, observed)
	}
	if sig.Name != "tap_os_mismatch" {
		t.Errorf("signal Name = %q; want tap_os_mismatch", sig.Name)
	}
	if sig.Score != cfg.SignalScore {
		t.Errorf("signal Score = %d; want %d (cfg.SignalScore)", sig.Score, cfg.SignalScore)
	}
	if sig.Weight != 1.0 {
		t.Errorf("signal Weight = %v; want 1.0", sig.Weight)
	}
	if sig.Reason == "" {
		t.Error("signal Reason must be non-empty and describe the claimed vs observed OS")
	}
}

func TestTapConsumer_RedisTimeout_DoesNotBlockHotPath(t *testing.T) {
	// Fake sleeps 1s; consumer must bail within RedisTimeout (50ms) + headroom.
	rc := &fakeRedis{values: map[string]string{}, delay: 1 * time.Second}
	cfg := newTapConfig()
	cfg.RedisTimeout = 50 * time.Millisecond
	tc := NewTapConsumer(cfg, rc, nil)

	start := time.Now()
	got := tc.GetSignal(context.Background(), "1.2.3.4", chromeWindowsJA4)
	elapsed := time.Since(start)

	if got != nil {
		t.Errorf("timeout must fail open (nil); got %+v", got)
	}
	if elapsed > 250*time.Millisecond {
		t.Errorf("GetSignal blocked %v on hot path; must respect RedisTimeout (50ms)", elapsed)
	}
}

func TestTapConsumer_RedisError_ReturnsNil(t *testing.T) {
	rc := &fakeRedis{err: errors.New("simulated redis failure")}
	tc := NewTapConsumer(newTapConfig(), rc, nil)

	got := tc.GetSignal(context.Background(), "1.2.3.4", chromeWindowsJA4)
	if got != nil {
		t.Errorf("Redis error must fail open (nil); got %+v", got)
	}
}

func TestTapConsumer_LocalCache_ShortCircuitsSecondLookup(t *testing.T) {
	claimed := callJA4OSClass(t, chromeWindowsJA4)
	if claimed == "" {
		t.Skip("starter ja4OSClass table does not map chromeWindowsJA4")
	}
	rc := &fakeRedis{values: map[string]string{"fp:os:ip:9.9.9.9": claimed}}
	tc := NewTapConsumer(newTapConfig(), rc, nil)

	ctx := context.Background()
	_ = tc.GetSignal(ctx, "9.9.9.9", chromeWindowsJA4)
	_ = tc.GetSignal(ctx, "9.9.9.9", chromeWindowsJA4)

	if got := rc.calls(); got != 1 {
		t.Errorf("second GetSignal for same clientIP should hit the local cache; Redis calls = %d, want 1", got)
	}
}

func TestTapConsumer_Concurrent_RaceFree(t *testing.T) {
	// Run under `go test -race`. Many goroutines hit the same IP; no data races.
	claimed := callJA4OSClass(t, chromeWindowsJA4)
	if claimed == "" {
		t.Skip("starter ja4OSClass table does not map chromeWindowsJA4")
	}
	rc := &fakeRedis{values: map[string]string{}}
	// Seed 100 distinct IPs so we exercise cache writes concurrently.
	for i := 0; i < 100; i++ {
		rc.values[fmt.Sprintf("fp:os:ip:10.0.0.%d", i)] = "linux"
	}
	tc := NewTapConsumer(newTapConfig(), rc, nil)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				ip := fmt.Sprintf("10.0.0.%d", (g*7+j)%100)
				_ = tc.GetSignal(context.Background(), ip, chromeWindowsJA4)
			}
		}(i)
	}
	wg.Wait()
}

// callJA4OSClass returns the OS string for a JA4 via the package-level
// ja4OSClass helper the 203a implementer must add. If the symbol does not
// exist, this test file will not compile — which is the correct red-state
// failure before implementation.
func callJA4OSClass(t *testing.T, ja4 string) string {
	t.Helper()
	return ja4OSClass(ja4)
}
