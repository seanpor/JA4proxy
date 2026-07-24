package tap

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrRedisCircuitOpen is returned by RedisCircuitBreaker.Set while the
// breaker is open. Store and Enforcer check for it specifically so a
// deliberate skip is counted as fpSkippedUnknown/enfSkipped, not
// fpError/enfError (R-002) -- the breaker chose not to try; it did not
// observe a fresh failure.
var ErrRedisCircuitOpen = errors.New("tap: redis circuit breaker open, skipping write")

// Breaker tuning. Package-level vars, not consts, so tests can shrink the
// cooldown and exercise the half-open-probe path without a real 10s wait.
var (
	// circuitBreakerFailureThreshold is the number of consecutive Redis
	// errors that trip the breaker open.
	circuitBreakerFailureThreshold = 5
	// circuitBreakerCooldown is how long the breaker stays open before
	// letting a real write through again (a half-open probe).
	circuitBreakerCooldown = 10 * time.Second
)

// RedisCircuitBreaker wraps a redisSetter and trips open after
// circuitBreakerFailureThreshold consecutive errors, skipping real Redis
// calls for circuitBreakerCooldown instead of letting every write in a
// Redis outage pay out its own timeout sequentially (R-002).
//
// Before this existed, a stalled/unreachable Redis collapsed throughput
// from thousands of events/sec to ~10/sec for minutes: each of the three
// per-event writes (OS class, JA4T, enforcement) still attempted and still
// waited out its share of the deadline, so the event buffer filled and
// stale events piled up behind the backlog. Tripping open after a handful
// of failures and skipping writes entirely for a cooldown keeps drain fast
// (skips are ~free) until Redis is worth trying again.
//
// Shared by Store and Enforcer (construct one, pass it to both) so a single
// breaker reflects Redis's real health rather than tracking per-caller
// state that could disagree with itself.
type RedisCircuitBreaker struct {
	inner redisSetter

	mu                  sync.Mutex
	consecutiveFailures int
	openUntil           time.Time
}

// NewRedisCircuitBreaker wraps inner. inner must be non-nil -- callers with
// no Redis backend (offline replay) should pass nil directly to NewStore/
// NewEnforcer instead of wrapping a nil setter.
func NewRedisCircuitBreaker(inner redisSetter) *RedisCircuitBreaker {
	return &RedisCircuitBreaker{inner: inner}
}

// Set implements redisSetter. While the breaker is open it returns
// ErrRedisCircuitOpen without calling inner at all.
func (cb *RedisCircuitBreaker) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	cb.mu.Lock()
	if time.Now().Before(cb.openUntil) {
		cb.mu.Unlock()
		RedisCircuitBreakerSkipsTotal.Inc()
		return ErrRedisCircuitOpen
	}
	cb.mu.Unlock()

	err := cb.inner.Set(ctx, key, value, ttl)

	cb.mu.Lock()
	defer cb.mu.Unlock()
	if err != nil {
		cb.consecutiveFailures++
		if cb.consecutiveFailures >= circuitBreakerFailureThreshold {
			cb.openUntil = time.Now().Add(circuitBreakerCooldown)
			RedisCircuitBreakerOpenedTotal.Inc()
		}
	} else {
		cb.consecutiveFailures = 0
	}
	return err
}
