package security

import (
	"context"
	"net"
	"testing"
)

func boolPtr(b bool) *bool {
	return &b
}

func TestPipeline_FailOpen_QueueSaturation(t *testing.T) {
	// 1. When FailOpen is true (default), saturation results in allow (fail-open)
	cfgOpen := &PipelineConfig{
		FailOpen: boolPtr(true),
	}
	pOpen := NewPipeline(cfgOpen, &mockRedis{dial: 0}, nil)
	pOpen.Sync = false
	fillWorkChan(pOpen)

	resOpen := pOpen.Process(context.Background(), &ConnectionContext{
		ClientIP: "1.1.1.1", ParsedIP: net.ParseIP("1.1.1.1"),
	})
	if resOpen.Action != "allow" {
		t.Fatalf("queue saturation under FailOpen=true: got %q, want allow", resOpen.Action)
	}

	// 2. When FailOpen is false, saturation results in block (fail-closed)
	cfgClosed := &PipelineConfig{
		FailOpen: boolPtr(false),
	}
	pClosed := NewPipeline(cfgClosed, &mockRedis{dial: 0}, nil)
	pClosed.Sync = false
	fillWorkChan(pClosed)

	resClosed := pClosed.Process(context.Background(), &ConnectionContext{
		ClientIP: "1.1.1.2", ParsedIP: net.ParseIP("1.1.1.2"),
	})
	if resClosed.Action != "block" {
		t.Fatalf("queue saturation under FailOpen=false: got %q, want block", resClosed.Action)
	}
	if resClosed.BypassReason != "queue_saturation_fail_closed" {
		t.Fatalf("queue saturation under FailOpen=false: got reason %q, want queue_saturation_fail_closed", resClosed.BypassReason)
	}

	// 3. Subsystem override: FailOpen=false globally, but queue_saturation=true
	cfgSubOpen := &PipelineConfig{
		FailOpen: boolPtr(false),
		SubsystemsFailOpen: map[string]bool{
			"queue_saturation": true,
		},
	}
	pSubOpen := NewPipeline(cfgSubOpen, &mockRedis{dial: 0}, nil)
	pSubOpen.Sync = false
	fillWorkChan(pSubOpen)

	resSubOpen := pSubOpen.Process(context.Background(), &ConnectionContext{
		ClientIP: "1.1.1.3", ParsedIP: net.ParseIP("1.1.1.3"),
	})
	if resSubOpen.Action != "allow" {
		t.Fatalf("queue saturation under subsystem override true: got %q, want allow", resSubOpen.Action)
	}
}

func TestPipeline_FailOpen_CircuitBreaker_RedisDown(t *testing.T) {
	// Mock Redis that always returns dial error
	failingRedis := &mockRedis{dial: 0}

	// Fail open mode (default)
	cfgOpen := &PipelineConfig{
		FailOpen:                    boolPtr(true),
		CircuitBreakerFailureThresh: 2,
		CircuitBreakerCooldownSec:   10,
	}
	pOpen := NewPipeline(cfgOpen, failingRedis, nil)
	pOpen.Sync = true

	conn := &ConnectionContext{
		ClientIP: "10.0.0.1",
		ParsedIP: net.ParseIP("10.0.0.1"),
		JA4:      "t13d1516h2_8daaf6152771_02713d6af862",
	}

	// Simulate failures directly on the circuit breaker
	cb := pOpen.CircuitBreaker()
	cb.RecordFailure()
	cb.RecordFailure()

	if cb.State() != StateOpen {
		t.Fatalf("circuit breaker expected to be StateOpen, got %v", cb.State())
	}

	// Under open circuit breaker with FailOpen=true (default): allow
	resOpen := pOpen.Process(context.Background(), conn)
	if resOpen.Action != "allow" {
		t.Fatalf("got action %q under open circuit breaker with FailOpen=true, want allow", resOpen.Action)
	}

	// FailClosed mode
	cfgClosed := &PipelineConfig{
		FailOpen:                    boolPtr(false),
		CircuitBreakerFailureThresh: 2,
		CircuitBreakerCooldownSec:   10,
	}
	pClosed := NewPipeline(cfgClosed, failingRedis, nil)
	pClosed.Sync = true

	cbClosed := pClosed.CircuitBreaker()
	cbClosed.RecordFailure()
	cbClosed.RecordFailure()

	// In fail closed mode with open circuit breaker: connection is blocked
	resClosed := pClosed.Process(context.Background(), conn)
	if resClosed.Action != "block" {
		t.Fatalf("fail closed under tripped circuit breaker: got action %q, want block", resClosed.Action)
	}
	if resClosed.BypassReason != "redis_failure_fail_closed" {
		t.Fatalf("fail closed under tripped circuit breaker: got reason %q, want redis_failure_fail_closed", resClosed.BypassReason)
	}
}
