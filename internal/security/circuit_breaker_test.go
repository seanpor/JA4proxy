package security

import (
	"testing"
	"time"
)

func TestCircuitBreaker_Transitions(t *testing.T) {
	cb := NewCircuitBreaker(3, 1) // 3 fails, 1s cooldown

	if !cb.AllowExecution() {
		t.Fatal("expected closed breaker to allow execution")
	}
	if cb.State() != StateClosed {
		t.Fatalf("expected StateClosed, got %v", cb.State())
	}

	cb.RecordFailure()
	cb.RecordFailure()
	if !cb.AllowExecution() {
		t.Fatal("expected execution allowed before threshold")
	}

	// 3rd failure trips breaker
	cb.RecordFailure()
	if cb.State() != StateOpen {
		t.Fatalf("expected StateOpen, got %v", cb.State())
	}
	if cb.AllowExecution() {
		t.Fatal("expected open breaker to reject execution")
	}

	// Wait for cooldown
	time.Sleep(1100 * time.Millisecond)

	// Half-open probe
	if !cb.AllowExecution() {
		t.Fatal("expected half-open breaker to allow probe execution")
	}
	if cb.State() != StateHalfOpen {
		t.Fatalf("expected StateHalfOpen, got %v", cb.State())
	}

	// Success closes breaker
	cb.RecordSuccess()
	if cb.State() != StateClosed {
		t.Fatalf("expected StateClosed after success, got %v", cb.State())
	}
	if !cb.AllowExecution() {
		t.Fatal("expected closed breaker to allow execution")
	}
}

func TestCircuitBreaker_HalfOpenFailureReopens(t *testing.T) {
	cb := NewCircuitBreaker(2, 1)
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != StateOpen {
		t.Fatalf("expected StateOpen, got %v", cb.State())
	}

	time.Sleep(1100 * time.Millisecond)
	if !cb.AllowExecution() {
		t.Fatal("expected probe allowed")
	}
	if cb.State() != StateHalfOpen {
		t.Fatalf("expected StateHalfOpen, got %v", cb.State())
	}

	// Failure in half-open reopens immediately
	cb.RecordFailure()
	if cb.State() != StateOpen {
		t.Fatalf("expected StateOpen after half-open failure, got %v", cb.State())
	}
	if cb.AllowExecution() {
		t.Fatal("expected execution rejected in StateOpen")
	}
}
