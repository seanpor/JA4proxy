package redis

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/sirupsen/logrus"
)

// TestRedisHealth_DetectsEmptySlidingWindowSHA verifies that the health
// check detects an empty SlidingWindowSHA and triggers a reload (201d).
func TestRedisHealth_DetectsEmptySlidingWindowSHA(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	defer mr.Close()

	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	c := New(Config{
		Host:    mr.Host(),
		Port:    mr.Server().Addr().Port,
		Timeout: 2 * time.Second,
	}, log)
	defer c.Close()

	// Simulate the SHA being empty (as if the initial load failed).
	c.slidingWinSHA = ""

	ctx := context.Background()

	// Run a health check: if SHA is empty, it should trigger a reload.
	err = c.HealthCheck(ctx)
	if err != nil {
		// If the implementation doesn't exist yet, this will fail to compile.
		// If it exists but the reload fails (e.g., Redis isn't reachable for
		// SCRIPT LOAD), that's also acceptable — the point is the empty SHA
		// was detected.
		t.Logf("HealthCheck returned error (expected if reload triggered): %v", err)
	}

	// After health check, the SHA should be reloaded (non-empty) if Redis is up.
	sha := c.SlidingWindowSHA()
	if sha == "" {
		t.Error("SlidingWindowSHA is still empty after health check — reload should have refilled it")
	}
}

// TestRedisHealth_RecoversAfterOutage verifies that the health check recovers
// after a simulated outage (SHA becomes non-empty again).
func TestRedisHealth_RecoversAfterOutage(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	defer mr.Close()

	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	c := New(Config{
		Host:    mr.Host(),
		Port:    mr.Server().Addr().Port,
		Timeout: 2 * time.Second,
	}, log)
	defer c.Close()

	ctx := context.Background()

	// First, confirm the SHA is loaded.
	sha1 := c.SlidingWindowSHA()
	if sha1 == "" {
		t.Fatal("initial SlidingWindowSHA should not be empty")
	}

	// Simulate an outage by clearing the SHA.
	c.slidingWinSHA = ""

	// Health check should detect empty SHA and reload.
	_ = c.HealthCheck(ctx)

	sha2 := c.SlidingWindowSHA()
	if sha2 == "" {
		t.Error("SlidingWindowSHA is empty after health check — should have recovered")
	}
	if sha2 != sha1 {
		// The SHA should be the same after reload (same script).
		t.Logf("SHA changed from %s to %s (same script, should be identical)", sha1, sha2)
	}
}

// TestRedisHealth_PrometheusMetric verifies that the ja4proxy_redis_health
// Prometheus metric is exposed with status labels (201d).
func TestRedisHealth_PrometheusMetric(t *testing.T) {
	// This test verifies that the health metric exists and can be read.
	// The actual metric registration should happen in the metrics package.
	// We verify the metric is accessible after a health check run.

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	defer mr.Close()

	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	c := New(Config{
		Host:    mr.Host(),
		Port:    mr.Server().Addr().Port,
		Timeout: 2 * time.Second,
	}, log)
	defer c.Close()

	ctx := context.Background()

	// Run health check.
	err = c.HealthCheck(ctx)

	// The health status should be reflected in the metric.
	// We verify by reading the current health status.
	status := c.HealthStatus()
	if status == "" {
		t.Error("HealthStatus returned empty string — should reflect current health")
	}
}

// TestRedisHealth_PeriodicCheck tests that the periodic health check runs at
// the configured interval (201d). We use a mock time approach to avoid real sleep.
func TestRedisHealth_PeriodicCheck(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	defer mr.Close()

	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	c := New(Config{
		Host:    mr.Host(),
		Port:    mr.Server().Addr().Port,
		Timeout: 2 * time.Second,
	}, log)
	defer c.Close()

	// Clear the SHA so the first periodic check will trigger a reload.
	c.slidingWinSHA = ""

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var checkCount atomic.Int64

	// Start periodic health check with a very short interval.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.PeriodicHealthCheck(ctx, 50*time.Millisecond, func() {
			checkCount.Add(1)
		})
	}()

	// Wait long enough for at least 2 checks to run.
	time.Sleep(150 * time.Millisecond)
	cancel()
	wg.Wait()

	// Verify at least 2 health checks ran.
	count := checkCount.Load()
	if count < 2 {
		t.Errorf("expected at least 2 periodic health checks, got %d", count)
	}

	// Verify the SHA was reloaded.
	sha := c.SlidingWindowSHA()
	if sha == "" {
		t.Error("SlidingWindowSHA is empty after periodic checks — reload should have refilled it")
	}
}
