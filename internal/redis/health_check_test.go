package redis

// Phase 201c — Redis health-check + script reload contract tests.
//
// REQUIRES (Coder must add before these tests pass):
//   - (*Client).HealthCheck(ctx context.Context)
//        * Pings Redis with a ~2 s timeout.
//        * On ping failure: sets metrics.RedisHealth{status="error"}=1,
//          {status="ok"}=0, logs WARN with substring "ping".
//        * On ping success: if slidingWinSHA == "", calls loadScripts (under
//          mutex, deduped across concurrent callers). If reload succeeds,
//          increments metrics.RedisScriptReloadsTotal{result="ok"}. If it
//          fails, increments {result="error"}. Then sets
//          RedisHealth{status="ok"}=1, {status="error"}=0.
//        * MUST be safe to call concurrently (-race clean).
//   - metrics.RedisHealth (GaugeVec, label: status)
//   - metrics.RedisScriptReloadsTotal (CounterVec, label: result)
//   - (*Client).SlidingWinSHAForTest() string — a tiny test-only accessor
//     that returns slidingWinSHA under the scriptMu RLock. Used to observe
//     reload state deterministically.
//   - (*Client).ZeroSlidingWinSHAForTest() — test-only helper that sets
//     slidingWinSHA to "" under the scriptMu Lock. Lets tests force the
//     "script was flushed" path without racing loadScripts.
//   - newFromOptions(opts *goredis.Options, log *logrus.Logger) *Client —
//     package-private constructor that accepts pre-built options. Used by
//     both TLS tests and these tests so they can share a seam.
//
// If any of the symbols above are missing, this file will FAIL TO COMPILE.
// That is the correct TDD red-phase signal.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"

	"github.com/seanpor/ja4proxy/internal/metrics"
)

func resetHealthMetrics(t *testing.T) {
	t.Helper()
	metrics.RedisHealth.Reset()
	metrics.RedisScriptReloadsTotal.Reset()
}

func newHealthTestClient(t *testing.T, addr string) (*Client, *logrustest.Hook) {
	t.Helper()
	host, port := splitHostPort(t, addr)
	log, hook := logrustest.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)
	c := New(Config{Host: host, Port: port, Timeout: 2 * time.Second}, log)
	return c, hook
}

func TestHealthCheck_ReloadsScriptAfterRestart(t *testing.T) {
	resetHealthMetrics(t)

	addr, srv, _ := newPlainMiniredis(t)
	c, _ := newHealthTestClient(t, addr)

	if sha := c.SlidingWinSHAForTest(); sha == "" {
		t.Fatal("expected slidingWinSHA to be populated after New()")
	}

	// Force the "script flushed" path by zeroing the SHA under lock so the
	// subsequent HealthCheck reload path is deterministically exercised.
	// Also restart miniredis so the server-side script cache is really empty.
	c.ZeroSlidingWinSHAForTest()
	restartMiniredisOnAddr(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c.HealthCheck(ctx)

	if sha := c.SlidingWinSHAForTest(); sha == "" {
		t.Errorf("HealthCheck should have reloaded sliding_window.lua; SHA still empty")
	}

	got := testutil.ToFloat64(metrics.RedisScriptReloadsTotal.WithLabelValues("ok"))
	if got != 1 {
		t.Errorf("RedisScriptReloadsTotal{result=ok}: got %v, want 1", got)
	}
}

func TestHealthCheck_PingFailureSetsErrorGauge(t *testing.T) {
	resetHealthMetrics(t)

	addr, srv, _ := newPlainMiniredis(t)
	c, hook := newHealthTestClient(t, addr)

	srv.Close() // kill the server: ping must fail

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c.HealthCheck(ctx)

	if got := testutil.ToFloat64(metrics.RedisHealth.WithLabelValues("error")); got != 1 {
		t.Errorf("RedisHealth{status=error}: got %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.RedisHealth.WithLabelValues("ok")); got != 0 {
		t.Errorf("RedisHealth{status=ok}: got %v, want 0", got)
	}

	saw := false
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.WarnLevel && strings.Contains(strings.ToLower(e.Message), "ping") {
			saw = true
			break
		}
	}
	if !saw {
		t.Errorf("expected WARN log containing 'ping'; entries: %+v", hook.AllEntries())
	}
}

func TestHealthCheck_RecoversAfterRestart(t *testing.T) {
	resetHealthMetrics(t)

	addr, srv, _ := newPlainMiniredis(t)
	c, _ := newHealthTestClient(t, addr)

	srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c.HealthCheck(ctx)
	if got := testutil.ToFloat64(metrics.RedisHealth.WithLabelValues("error")); got != 1 {
		t.Fatalf("pre-restart RedisHealth{error}: got %v, want 1", got)
	}

	// Bring Redis back on the same address.
	if err := srv.Restart(); err != nil {
		t.Fatalf("miniredis.Restart: %v", err)
	}
	_ = addr // addr unchanged

	// Zero the SHA so HealthCheck re-loads it after recovery.
	c.ZeroSlidingWinSHAForTest()

	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	c.HealthCheck(ctx2)

	if got := testutil.ToFloat64(metrics.RedisHealth.WithLabelValues("ok")); got != 1 {
		t.Errorf("post-restart RedisHealth{ok}: got %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.RedisHealth.WithLabelValues("error")); got != 0 {
		t.Errorf("post-restart RedisHealth{error}: got %v, want 0", got)
	}
	if got := testutil.ToFloat64(metrics.RedisScriptReloadsTotal.WithLabelValues("ok")); got != 1 {
		t.Errorf("post-restart reloads{ok}: got %v, want 1", got)
	}
}

func TestHealthCheck_Concurrent_NoRace(t *testing.T) {
	resetHealthMetrics(t)

	addr, _, _ := newPlainMiniredis(t)
	c, _ := newHealthTestClient(t, addr)

	// Force exactly one reload path by zeroing the SHA. The dedup logic in
	// HealthCheck must ensure only one goroutine wins the reload.
	c.ZeroSlidingWinSHAForTest()

	const n = 50
	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	done.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer done.Done()
			start.Wait()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			c.HealthCheck(ctx)
		}()
	}
	start.Done()
	done.Wait()

	reloads := testutil.ToFloat64(metrics.RedisScriptReloadsTotal.WithLabelValues("ok"))
	if reloads != 1 {
		t.Errorf("concurrent reload dedup: got %v ok reloads, want exactly 1", reloads)
	}
}

func TestHealthCheck_GoroutineStopsOnContextCancel(t *testing.T) {
	resetHealthMetrics(t)

	addr, _, _ := newPlainMiniredis(t)
	c, _ := newHealthTestClient(t, addr)

	ctx, cancel := context.WithCancel(context.Background())

	stopped := make(chan struct{})
	go func() {
		// Mirror the cmd/proxy/main.go loop pattern. Tick fast so a slow loop
		// is visibly slow, but assertion is on ctx.Done() handling not cadence.
		t := time.NewTicker(50 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				close(stopped)
				return
			case <-t.C:
				c.HealthCheck(ctx)
			}
		}
	}()

	cancel()
	select {
	case <-stopped:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("health-check goroutine did not exit within 500 ms of context cancellation")
	}
}
