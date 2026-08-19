package security

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// Phase 828 — the async scoring path must publish its result.
//
// Pipeline.Process returns a stub {allow, 0, Deferred: true} on the async path
// and queues the real work. The caller emits its telemetry event from that
// stub, so everything that explains the decision — score, signals,
// counterfactuals — was computed afterwards on a worker goroutine and never
// left the process. The first connection from any (IP, JA4) pair was published
// as "score 0, no explanation"; only repeats, served from the decision cache,
// carried the truth.
//
// These tests pin the callback that closes that gap. Note the trap they exist
// to catch: a test that sets Sync = true passes without the callback ever being
// invoked, because the synchronous path returns the full result directly. That
// is exactly how the ASN provenance gap survived its own test suite in phase
// 827, so every test here runs with Sync = false.

// newAsyncTestPipeline builds a pipeline that actually scores.
//
// Distinct from pipeline_test.go's newTestPipeline, which sets Sync = true —
// useless here, since the whole gap being tested exists only on the async path.
// It also whitelists t13d1516h2_8daaf6152771_02713d6af862; a test using that
// fingerprint would bypass the scorer and never reach the worker at all.
func newAsyncTestPipeline(t *testing.T) *Pipeline {
	t.Helper()
	log := logrus.New()
	log.SetLevel(logrus.PanicLevel)
	p := NewPipeline(&PipelineConfig{Thresholds: map[string]int{}}, &mockRedis{dial: 75}, log)
	p.Sync = false
	return p
}

// scoredJA4 is deliberately absent from every list in the test configs, so a
// connection carrying it reaches the scorer instead of short-circuiting.
const scoredJA4 = "t13d9999h1_deadbeefcafe_0123456789ab"

func TestOnScoredFiresOnTheAsyncPath(t *testing.T) {
	p := newAsyncTestPipeline(t) // Sync = false: the whole point of this test

	var (
		mu     sync.Mutex
		gotID  string
		gotRes *PipelineResult
	)
	done := make(chan struct{})
	var once sync.Once
	p.OnScored = func(c *ConnectionContext, r *PipelineResult) {
		mu.Lock()
		gotID, gotRes = c.ConnectionID, r
		mu.Unlock()
		once.Do(func() { close(done) })
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.StartBackgroundWorkers(ctx)

	res := p.Process(ctx, &ConnectionContext{
		ClientIP:     "203.0.113.7",
		JA4:          scoredJA4,
		ConnectionID: "node-abc",
	})

	// The synchronous answer is a placeholder, and must say so.
	if !res.Deferred {
		t.Error("the async stub must be marked Deferred — otherwise its score 0 " +
			"is published as a verdict rather than as 'not yet evaluated'")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("OnScored never fired: the scored result would never be published")
	}

	mu.Lock()
	defer mu.Unlock()
	if gotID != "node-abc" {
		t.Errorf("callback got connection id %q, want %q", gotID, "node-abc")
	}
	if gotRes == nil {
		t.Fatal("callback received a nil result")
	}
	if gotRes.Deferred {
		t.Error("the scored result must NOT be marked Deferred — it is the final word")
	}
}

func TestOnScoredNilIsSafe(t *testing.T) {
	// The callback is optional. A deployment that does not want the second
	// event must not crash the scoring worker.
	p := newAsyncTestPipeline(t)
	p.OnScored = nil

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.StartBackgroundWorkers(ctx)

	for i := 0; i < 10; i++ {
		p.Process(ctx, &ConnectionContext{ClientIP: "198.51.100.1", JA4: scoredJA4})
	}
	time.Sleep(200 * time.Millisecond) // let the worker drain
}

func TestOnScoredPanicDoesNotKillTheScoringWorker(t *testing.T) {
	// The callback is caller-supplied and does I/O (it marshals and enqueues a
	// Redis event). A panic in it must not take down the goroutine that scores
	// every subsequent connection: telemetry must never be able to stop
	// enforcement.
	p := newAsyncTestPipeline(t)

	var calls int
	var mu sync.Mutex
	survived := make(chan struct{})
	var once sync.Once
	p.OnScored = func(c *ConnectionContext, r *PipelineResult) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			panic("telemetry exploded")
		}
		once.Do(func() { close(survived) })
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.StartBackgroundWorkers(ctx)

	// Distinct (IP, JA4) pairs: identical ones would be served from the
	// decision cache and never reach the worker a second time, so this test
	// would pass without the recover ever being exercised.
	for i := 0; i < 6; i++ {
		p.Process(ctx, &ConnectionContext{
			ClientIP: "192.0.2." + string(rune('1'+i)),
			JA4:      scoredJA4,
		})
	}

	select {
	case <-survived:
	case <-time.After(5 * time.Second):
		mu.Lock()
		n := calls
		mu.Unlock()
		t.Fatalf("the scoring worker did not survive a panicking callback (calls=%d)", n)
	}
}

func TestDeferredIsFalseWhenSynchronous(t *testing.T) {
	// A synchronous result is complete on return, so it must not be published
	// as provisional — that would leave a "final" event permanently missing.
	p := newAsyncTestPipeline(t)
	p.Sync = true

	ctx := context.Background()
	res := p.Process(ctx, &ConnectionContext{ClientIP: "203.0.113.9", JA4: scoredJA4})

	if res.Deferred {
		t.Error("a synchronously scored result must not be marked Deferred")
	}
}
