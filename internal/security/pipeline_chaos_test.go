// Phase 62 — Pipeline chaos / fault-injection tests.
//
// These tests drive the production Pipeline against a Redis double that
// returns errors on a configurable cadence. They lock in the asymmetry
// doctrine from CLAUDE.md: when the network plane fails, the proxy must
// continue serving traffic ("fail open"). A blocked legitimate user is the
// most expensive failure this proxy can produce.
//
// Three independent scenarios:
//
//  1. Total Redis outage    — every signal lookup fails; pipeline must allow.
//  2. Partial Redis outage  — half the calls fail; ALPN bypass must still allow.
//  3. Dial flip mid-flight  — flipping dial 0→100 must take effect on the
//     next Process() call (no stale ALLOW).
package security

import (
	"context"
	"sync/atomic"
	"testing"
)

// faultyRedis is a RedisReader test double that returns zero values for
// every read but increments an internal counter so tests can assert how
// many calls were made. The "failEvery" field controls a synthetic outage
// pattern: when failEvery > 0, every Nth call returns the zero value (which
// is what the production code receives during a real Redis error).
//
// Note: the production RedisReader interface returns plain values rather
// than (value, error) tuples — Redis errors are already swallowed inside
// the RedisReader implementation and surfaced as zero/empty results. So a
// chaos test that wants to simulate "every call fails" simply has every
// call return the zero value, which is exactly what real fail-open Redis
// wrappers do on connection loss.
type faultyRedis struct {
	dial      int32 // atomic for the dial-flip test
	failEvery int
	calls     int64
}

func newFaultyRedis(failEvery int, dial int) *faultyRedis {
	return &faultyRedis{failEvery: failEvery, dial: int32(dial)}
}

func (f *faultyRedis) shouldFail() bool {
	c := atomic.AddInt64(&f.calls, 1)
	if f.failEvery <= 0 {
		return false
	}
	return c%int64(f.failEvery) == 0
}

func (f *faultyRedis) setDial(d int) {
	atomic.StoreInt32(&f.dial, int32(d))
}

func (f *faultyRedis) GetDial(_ context.Context) int {
	if f.shouldFail() {
		return 0 // production wrapper returns 0 on error
	}
	return int(atomic.LoadInt32(&f.dial))
}

func (f *faultyRedis) SIsMember(_ context.Context, _ string, _ interface{}) bool {
	f.shouldFail()
	return false
}

func (f *faultyRedis) SlidingWindowCount(_ context.Context, _ string, _ float64, _ int) int {
	f.shouldFail()
	return 0
}

func (f *faultyRedis) HGetAll(_ context.Context, _ string) map[string]string {
	f.shouldFail()
	return nil
}

func (f *faultyRedis) GetString(_ context.Context, _ string) string {
	f.shouldFail()
	return ""
}

func (f *faultyRedis) SetString(_ context.Context, _ string, _ string, _ int) {
	f.shouldFail()
}

func (f *faultyRedis) Exists(_ context.Context, _ string) bool {
	f.shouldFail()
	return false
}

func (f *faultyRedis) Ping(_ context.Context) error {
	if f.shouldFail() {
		return context.DeadlineExceeded
	}
	return nil
}

func (f *faultyRedis) ZAdd(_ context.Context, _ string, _ float64, _ string) { f.shouldFail() }
func (f *faultyRedis) ZRemRangeByScore(_ context.Context, _ string, _, _ float64) {
	f.shouldFail()
}
func (f *faultyRedis) ZRange(_ context.Context, _ string, _, _ int64) []string {
	f.shouldFail()
	return nil
}
func (f *faultyRedis) ZCard(_ context.Context, _ string) int64 { f.shouldFail(); return 0 }
func (f *faultyRedis) ZRangeScores(_ context.Context, _ string, _, _ int64) []float64 {
	f.shouldFail()
	return nil
}

// newChaosPipeline builds a pipeline wired to a fault-injecting Redis. It is
// the chaos-test counterpart to newTestPipeline in pipeline_test.go and is
// kept under a different name so the two helpers can coexist in the same
// package.
func newChaosPipeline(t *testing.T, redis *faultyRedis) *Pipeline {
	t.Helper()
	cfg := &PipelineConfig{
		ALPNBrowserBypass:  true,
		JA4WhitelistBypass: true,
		JA4BlockingEnabled: true,
		MTLSBypass:         true,
		Whitelist:          map[string]bool{},
		Blacklist:          map[string]bool{},
	}
	return NewPipeline(cfg, redis, nil)
}

func validClientHello() *ConnectionContext {
	// Plain connection, no JA4 listed, no special ALPN. Should score zero
	// in the absence of any signals and therefore allow even at dial=100.
	return &ConnectionContext{
		ClientIP: "203.0.113.7",
		JA4:      "t13d000000_000000000000_000000000000",
	}
}

func h2BrowserClientHello() *ConnectionContext {
	// h2 ALPN — must always allow via the bypass, regardless of any score.
	return &ConnectionContext{
		ClientIP: "198.51.100.42",
		JA4:      "t13d1516h2_8daaf6152771_02713d6af862",
		ALPN:     "h2",
	}
}

func maliciousClientHello() *ConnectionContext {
	// A connection that produces a non-zero score path. We do not assert a
	// specific score here — only that the dial flip changes the action.
	return &ConnectionContext{
		ClientIP: "192.0.2.99",
		JA4:      "t10d000000_aaaaaaaaaaaa_bbbbbbbbbbbb",
	}
}

// TestPipeline_RedisOutage_FailsOpen — total outage scenario. Every Redis
// call returns the zero value (the production wrapper's error indicator),
// so the dial reads as 0 (monitor mode) and every signal lookup is empty.
// The pipeline must produce ALLOW. This is the load-bearing core of the
// asymmetry doctrine.
func TestPipeline_RedisOutage_FailsOpen(t *testing.T) {
	redis := newFaultyRedis(1, 100) // failEvery=1 → every call "fails"
	p := newChaosPipeline(t, redis)
	res := p.Process(context.Background(), validClientHello())
	if res == nil {
		t.Fatal("pipeline returned nil during Redis outage")
	}
	if res.Action != "allow" {
		t.Fatalf("expected allow during total Redis outage, got %q (score=%d)", res.Action, res.Score)
	}
}

// TestPipeline_PartialOutage_AllowBypassesStillWork — every other Redis
// call fails. The h2 ALPN bypass must still produce ALLOW for every
// request, no matter which call cycle catches the failure.
func TestPipeline_PartialOutage_AllowBypassesStillWork(t *testing.T) {
	redis := newFaultyRedis(2, 100)
	p := newChaosPipeline(t, redis)
	for i := 0; i < 50; i++ {
		res := p.Process(context.Background(), h2BrowserClientHello())
		if res == nil {
			t.Fatalf("iteration %d: pipeline returned nil", i)
		}
		if res.Action != "allow" {
			t.Fatalf("iteration %d: h2 ALPN bypass failed under partial outage: action=%q", i, res.Action)
		}
		if !res.Bypassed {
			t.Fatalf("iteration %d: expected bypass under partial outage, got bypassed=false", i)
		}
	}
}

// TestPipeline_DialFlip_PropagatesAndChangesAction — flipping the dial from
// 0 to 100 mid-flight must:
//
//  1. Take effect on the very next Process() call (no stored-state bug)
//  2. Cause the propagated dial value to materially change the action
//     decision when fed to ActionDecider with a score that crosses a
//     threshold.
//
// We cannot inject a high score directly through the pipeline in a unit
// test (signal collection requires real subsystems), so part (2) is
// asserted by feeding a synthetic threshold-crossing score to
// ActionDecider.Decide together with the dial value the pipeline returned.
// This locks the contract end-to-end: dial flows from Redis → Pipeline →
// PipelineResult.Dial → ActionDecider → action change.
//
// Unit-level dial × score correctness is exhaustively covered by
// TestActionDecider_MonitorMode and TestActionDecider_FullBlocking in
// action_decider_test.go.
//
// Earlier name: TestPipeline_DialFlip_NoStaleDecisions — that name was
// renamed in the Phase 62 review-fix because the original assertion only
// verified dial propagation, not action change. (Phase 62 external review.)
func TestPipeline_DialFlip_PropagatesAndChangesAction(t *testing.T) {
	redis := newFaultyRedis(0, 0) // healthy redis, dial=0
	p := newChaosPipeline(t, redis)
	decider := NewActionDeciderDefault()

	// First call: dial=0 (monitor mode). Pipeline must report Dial=0.
	res0 := p.Process(context.Background(), maliciousClientHello())
	if res0 == nil {
		t.Fatal("dial=0: pipeline returned nil")
	}
	if res0.Dial != 0 {
		t.Fatalf("dial=0: expected res.Dial=0, got %d", res0.Dial)
	}
	if res0.Action != "allow" {
		t.Fatalf("dial=0: expected allow (monitor mode), got %q", res0.Action)
	}

	// Flip the dial to 100.
	redis.setDial(100)

	// Second call: pipeline must observe the new dial on its next call —
	// no stored state caching the old value.
	res1 := p.Process(context.Background(), maliciousClientHello())
	if res1 == nil {
		t.Fatal("dial=100: pipeline returned nil")
	}
	if res1.Dial != 100 {
		t.Fatalf("after dial flip: expected res.Dial=100, got %d", res1.Dial)
	}

	// End-to-end contract: feed a threshold-crossing synthetic score to
	// ActionDecider with each propagated dial value. The action MUST
	// differ — that is the whole point of the dial. If this assertion
	// ever fails, either the dial is not flowing through correctly or
	// ActionDecider is broken (and the unit tests should already have
	// caught the latter).
	const synthHighScore = 80 // > block threshold (70) at dial=100
	action0 := decider.Decide(synthHighScore, res0.Dial)
	action1 := decider.Decide(synthHighScore, res1.Dial)
	if action0 != "allow" {
		t.Fatalf("synth score=%d, propagated dial=%d: expected allow, got %q",
			synthHighScore, res0.Dial, action0)
	}
	if action1 == "allow" {
		t.Fatalf("synth score=%d, propagated dial=%d: expected non-allow "+
			"after dial flip, got %q — dial value is not affecting action",
			synthHighScore, res1.Dial, action1)
	}
}
