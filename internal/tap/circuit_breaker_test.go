package tap

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/seanpor/ja4proxy/internal/fingerprint"
)

// countingSetter records every call and returns errs[i] for the i-th call
// (repeating the last entry once exhausted). Distinct from store_test.go's
// fakeSetter, which returns one fixed error for every call -- the breaker
// tests need per-call sequencing (N failures, then a success, etc.).
type countingSetter struct {
	errs  []error
	calls int
}

func (c *countingSetter) Set(context.Context, string, string, time.Duration) error {
	i := c.calls
	if i >= len(c.errs) {
		i = len(c.errs) - 1
	}
	c.calls++
	if i < 0 {
		return nil
	}
	return c.errs[i]
}

func TestRedisCircuitBreaker_PassesThroughOnSuccess(t *testing.T) {
	inner := &countingSetter{}
	cb := NewRedisCircuitBreaker(inner)

	for i := 0; i < 10; i++ {
		if err := cb.Set(context.Background(), "k", "v", time.Second); err != nil {
			t.Fatalf("call %d: unexpected error %v", i, err)
		}
	}
	if inner.calls != 10 {
		t.Errorf("expected inner to be called 10 times, got %d", inner.calls)
	}
}

func TestRedisCircuitBreaker_TripsOpenAfterThreshold(t *testing.T) {
	origThreshold := circuitBreakerFailureThreshold
	t.Cleanup(func() { circuitBreakerFailureThreshold = origThreshold })
	circuitBreakerFailureThreshold = 3

	wantErr := errors.New("simulated redis error")
	inner := &countingSetter{errs: []error{wantErr, wantErr, wantErr, wantErr, wantErr}}
	cb := NewRedisCircuitBreaker(inner)

	// First 3 calls: genuine attempts, genuine failures.
	for i := 0; i < 3; i++ {
		if err := cb.Set(context.Background(), "k", "v", time.Second); !errors.Is(err, wantErr) {
			t.Fatalf("call %d: expected the underlying error, got %v", i, err)
		}
	}
	if inner.calls != 3 {
		t.Fatalf("expected 3 real attempts before tripping, got %d", inner.calls)
	}

	// 4th call: breaker is now open -- must NOT reach inner.
	err := cb.Set(context.Background(), "k", "v", time.Second)
	if !errors.Is(err, ErrRedisCircuitOpen) {
		t.Fatalf("expected ErrRedisCircuitOpen once tripped, got %v", err)
	}
	if inner.calls != 3 {
		t.Fatalf("expected no additional inner call while open, got %d total calls", inner.calls)
	}
}

func TestRedisCircuitBreaker_ResetsOnSuccessBeforeThreshold(t *testing.T) {
	origThreshold := circuitBreakerFailureThreshold
	t.Cleanup(func() { circuitBreakerFailureThreshold = origThreshold })
	circuitBreakerFailureThreshold = 3

	wantErr := errors.New("simulated redis error")
	// 2 failures (below the threshold of 3), then a success, then 2 more
	// failures. If the counter correctly reset on the success, the breaker
	// must still be closed after this sequence (max consecutive run = 2).
	inner := &countingSetter{errs: []error{wantErr, wantErr, nil, wantErr, wantErr}}
	cb := NewRedisCircuitBreaker(inner)

	for i := 0; i < 5; i++ {
		_ = cb.Set(context.Background(), "k", "v", time.Second)
	}
	if inner.calls != 5 {
		t.Fatalf("expected all 5 calls to reach inner (breaker never trips), got %d", inner.calls)
	}
}

func TestRedisCircuitBreaker_ClosesAfterCooldown(t *testing.T) {
	origThreshold, origCooldown := circuitBreakerFailureThreshold, circuitBreakerCooldown
	t.Cleanup(func() {
		circuitBreakerFailureThreshold, circuitBreakerCooldown = origThreshold, origCooldown
	})
	circuitBreakerFailureThreshold = 1
	circuitBreakerCooldown = 20 * time.Millisecond

	wantErr := errors.New("simulated redis error")
	inner := &countingSetter{errs: []error{wantErr, nil}}
	cb := NewRedisCircuitBreaker(inner)

	// Trip open on the first failure.
	if err := cb.Set(context.Background(), "k", "v", time.Second); !errors.Is(err, wantErr) {
		t.Fatalf("expected the underlying error on the first call, got %v", err)
	}
	// Immediately after: open, skipped.
	if err := cb.Set(context.Background(), "k", "v", time.Second); !errors.Is(err, ErrRedisCircuitOpen) {
		t.Fatalf("expected ErrRedisCircuitOpen immediately after tripping, got %v", err)
	}
	if inner.calls != 1 {
		t.Fatalf("expected exactly 1 real attempt before the cooldown-probe call, got %d", inner.calls)
	}

	time.Sleep(circuitBreakerCooldown + 10*time.Millisecond)

	// Cooldown elapsed: the next call is a real half-open probe.
	if err := cb.Set(context.Background(), "k", "v", time.Second); err != nil {
		t.Fatalf("expected the half-open probe to succeed, got %v", err)
	}
	if inner.calls != 2 {
		t.Fatalf("expected the probe to reach inner, got %d total calls", inner.calls)
	}
}

// TestStoreCountsCircuitOpenAsSkippedNotError verifies the R-002 requirement
// end to end through Store: a circuit-breaker skip must be labelled
// fpSkippedUnknown, not fpError -- it is a deliberate non-attempt, not an
// observed Redis failure, and conflating the two would make the error metric
// spike on every outage exactly when it's least useful (already known: Redis
// is down).
func TestStoreCountsCircuitOpenAsSkippedNotError(t *testing.T) {
	origThreshold := circuitBreakerFailureThreshold
	t.Cleanup(func() { circuitBreakerFailureThreshold = origThreshold })
	circuitBreakerFailureThreshold = 1

	wantErr := errors.New("simulated redis error")
	inner := &countingSetter{errs: []error{wantErr, wantErr}}
	cb := NewRedisCircuitBreaker(inner)
	store := NewStore(cb)

	errBefore := counter(fpError)
	skippedBefore := counter(fpSkippedUnknown)

	// Trips the breaker.
	store.WriteOSClass(context.Background(), "203.0.113.7", fingerprint.OSLinux)
	// This one hits the open breaker -- must count as skipped, not error.
	store.WriteOSClass(context.Background(), "203.0.113.8", fingerprint.OSLinux)

	if got := counter(fpError); got != errBefore+1 {
		t.Errorf("fpError = %v; want exactly +1 (the genuine failure that tripped the breaker)", got-errBefore)
	}
	if got := counter(fpSkippedUnknown); got != skippedBefore+1 {
		t.Errorf("fpSkippedUnknown = %v; want +1 (the circuit-open skip)", got-skippedBefore)
	}
}
