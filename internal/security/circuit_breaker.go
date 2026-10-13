package security

import (
	"sync"
	"time"
)

// CircuitBreakerState represents the current state of a circuit breaker.
type CircuitBreakerState int

const (
	StateClosed CircuitBreakerState = iota
	StateOpen
	StateHalfOpen
)

// CircuitBreaker implements a fast-failing latch to protect against
// latency spikes and goroutine exhaustion when auxiliary dependencies fail.
type CircuitBreaker struct {
	mu               sync.RWMutex
	state            CircuitBreakerState
	failureThreshold int
	cooldownDuration time.Duration
	consecutiveFails int
	lastStateChange  time.Time
}

// NewCircuitBreaker creates a circuit breaker with threshold and cooldown parameters.
func NewCircuitBreaker(failureThreshold int, cooldownSeconds int) *CircuitBreaker {
	if failureThreshold <= 0 {
		failureThreshold = 5
	}
	if cooldownSeconds <= 0 {
		cooldownSeconds = 10
	}
	return &CircuitBreaker{
		state:            StateClosed,
		failureThreshold: failureThreshold,
		cooldownDuration: time.Duration(cooldownSeconds) * time.Second,
		lastStateChange:  time.Now(),
	}
}

// AllowExecution checks whether an operation should proceed or fast-fail.
// In StateOpen, if cooldown has elapsed, it transitions to StateHalfOpen and allows a probe.
func (cb *CircuitBreaker) AllowExecution() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()
	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		if now.Sub(cb.lastStateChange) >= cb.cooldownDuration {
			cb.state = StateHalfOpen
			cb.lastStateChange = now
			return true
		}
		return false
	case StateHalfOpen:
		// In half-open, allow one probe through
		return true
	default:
		return true
	}
}

// RecordSuccess records a successful call, resetting failure counts and closing the breaker.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.consecutiveFails = 0
	if cb.state != StateClosed {
		cb.state = StateClosed
		cb.lastStateChange = time.Now()
	}
}

// RecordFailure records a failed call. If threshold is reached, transitions to StateOpen.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.consecutiveFails++
	if cb.state == StateHalfOpen || cb.consecutiveFails >= cb.failureThreshold {
		cb.state = StateOpen
		cb.lastStateChange = time.Now()
	}
}

// State returns the current circuit breaker state.
func (cb *CircuitBreaker) State() CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}
