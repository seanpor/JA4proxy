package security

import (
	"context"
	"runtime"
	"testing"
	"time"
)

// TestPipeline_ConstructionStartsNoWorkers_JA4PROXY_2026_0090 asserts that
// NewPipeline does not spawn the beaconing/audit workers at construction.
// Before the fix, every NewPipeline launched two goroutines that blocked
// forever on never-closed channels, each pinning the whole Pipeline via closure
// — a goroutine + memory leak for every pipeline built and discarded (the ja4p
// CLI, every unit test). Building N pipelines must not add ~2N goroutines.
func TestPipeline_ConstructionStartsNoWorkers_JA4PROXY_2026_0090(t *testing.T) {
	settle()
	base := runtime.NumGoroutine()

	const n = 50
	pipelines := make([]*Pipeline, 0, n)
	for i := 0; i < n; i++ {
		pipelines = append(pipelines, NewPipeline(nil, &mockRedis{}, nil))
	}
	settle()

	grew := runtime.NumGoroutine() - base
	// With the fix, construction starts 0 workers → growth ~0. Reverted, it
	// would be ~2*n (100). A generous threshold cleanly separates the two.
	if grew > n {
		t.Fatalf("NewPipeline started background workers at construction: goroutines grew by %d after building %d pipelines (want < %d)", grew, n, n)
	}
	runtime.KeepAlive(pipelines)
}

// TestPipeline_WorkersExitOnCancel_JA4PROXY_2026_0090 asserts the workers
// started by StartBackgroundWorkers exit when their context is cancelled,
// rather than blocking forever.
func TestPipeline_WorkersExitOnCancel_JA4PROXY_2026_0090(t *testing.T) {
	settle()
	base := runtime.NumGoroutine()

	p := NewPipeline(nil, &mockRedis{}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	p.StartBackgroundWorkers(ctx)

	// Workers are now running; goroutine count is above baseline.
	if runtime.NumGoroutine() <= base {
		t.Fatal("StartBackgroundWorkers did not start any goroutines")
	}

	cancel()

	// After cancellation the workers must return; goroutines drop back toward
	// baseline. Poll with a timeout to avoid depending on scheduler timing.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		settle()
		if runtime.NumGoroutine() <= base+2 { // small slack for test-runtime noise
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("workers did not exit after ctx cancel: goroutines still %d above baseline", runtime.NumGoroutine()-base)
}

// settle nudges the scheduler/GC so goroutine counts stabilise before sampling.
func settle() {
	runtime.GC()
	for i := 0; i < 3; i++ {
		runtime.Gosched()
		time.Sleep(5 * time.Millisecond)
	}
}
