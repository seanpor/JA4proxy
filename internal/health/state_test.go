package health

// Phase 203e — TDD red: anti-flap state for /health/deep component checks.
//
// Contract (from docs/phases/PHASE_203.md sub-phase 203e step 2):
//   type Config struct { FailThreshold int }  // default 3
//   type State struct { ... }
//   func New(cfg Config) *State
//   func (s *State) RecordFailure(component string) (unhealthy bool)
//   func (s *State) RecordSuccess(component string)
//   func (s *State) IsUnhealthy(component string) bool
//
// Invariants:
//   - 1 failure does not flip to unhealthy
//   - 3 consecutive failures flip to unhealthy (with FailThreshold=3)
//   - any success resets the failure counter (and clears unhealthy)
//   - safe under concurrent access (run with -race)

import (
	"sync"
	"testing"
)

func TestState_New_DefaultThreshold_IsThree(t *testing.T) {
	// Passing Config{} (zero FailThreshold) should default to 3.
	s := New(Config{})
	// 2 failures → still healthy with default threshold 3
	_ = s.RecordFailure("redis")
	if s.RecordFailure("redis") {
		t.Error("2 failures with default threshold should NOT flip to unhealthy")
	}
	if s.IsUnhealthy("redis") {
		t.Error("2 failures must not mark component unhealthy (threshold=3)")
	}
	// 3rd failure → flips
	if !s.RecordFailure("redis") {
		t.Error("3rd failure must flip to unhealthy when threshold=3")
	}
	if !s.IsUnhealthy("redis") {
		t.Error("IsUnhealthy must be true after 3 failures")
	}
}

func TestState_SingleFailure_DoesNotFlip(t *testing.T) {
	s := New(Config{FailThreshold: 3})
	if s.RecordFailure("redis") {
		t.Error("single failure must not flip to unhealthy")
	}
	if s.IsUnhealthy("redis") {
		t.Error("single failure must not set IsUnhealthy")
	}
}

func TestState_ThreeFailures_Flip(t *testing.T) {
	s := New(Config{FailThreshold: 3})
	first := s.RecordFailure("redis")
	second := s.RecordFailure("redis")
	third := s.RecordFailure("redis")
	if first || second {
		t.Errorf("failures 1 and 2 must not flip: first=%v second=%v", first, second)
	}
	if !third {
		t.Error("3rd failure must return unhealthy=true")
	}
	if !s.IsUnhealthy("redis") {
		t.Error("IsUnhealthy must be true after threshold reached")
	}
}

func TestState_Success_ResetsCounter(t *testing.T) {
	s := New(Config{FailThreshold: 3})
	_ = s.RecordFailure("redis")
	_ = s.RecordFailure("redis")
	s.RecordSuccess("redis")
	// After reset, we need 3 fresh failures to flip
	if s.RecordFailure("redis") {
		t.Error("after success-reset, single failure must not flip")
	}
	if s.IsUnhealthy("redis") {
		t.Error("after success-reset, component must be healthy")
	}
}

func TestState_Success_ClearsUnhealthy(t *testing.T) {
	s := New(Config{FailThreshold: 3})
	_ = s.RecordFailure("redis")
	_ = s.RecordFailure("redis")
	_ = s.RecordFailure("redis")
	if !s.IsUnhealthy("redis") {
		t.Fatal("precondition: should be unhealthy after 3 failures")
	}
	s.RecordSuccess("redis")
	if s.IsUnhealthy("redis") {
		t.Error("RecordSuccess must clear the unhealthy state")
	}
}

func TestState_Components_AreIndependent(t *testing.T) {
	s := New(Config{FailThreshold: 3})
	_ = s.RecordFailure("redis")
	_ = s.RecordFailure("redis")
	_ = s.RecordFailure("redis")
	if s.IsUnhealthy("geoip") {
		t.Error("geoip must remain healthy when only redis failed")
	}
	if !s.IsUnhealthy("redis") {
		t.Error("redis must be unhealthy")
	}
}

func TestState_UnknownComponent_IsHealthy(t *testing.T) {
	s := New(Config{FailThreshold: 3})
	if s.IsUnhealthy("never-touched") {
		t.Error("unknown component must default to healthy")
	}
}

func TestState_Concurrent_RaceFree(t *testing.T) {
	t.Parallel()
	s := New(Config{FailThreshold: 5})
	var wg sync.WaitGroup
	const workers = 10
	const ops = 200
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < ops; j++ {
				switch (id + j) % 3 {
				case 0:
					_ = s.RecordFailure("redis")
				case 1:
					s.RecordSuccess("redis")
				case 2:
					_ = s.IsUnhealthy("redis")
				}
			}
		}(i)
	}
	wg.Wait()
}
