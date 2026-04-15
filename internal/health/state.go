// Package health provides anti-flap state tracking for component probes
// consumed by /health/deep. Phase 203e.
//
// A component reports as "unhealthy" only after FailThreshold consecutive
// failures; any success resets the counter and clears the unhealthy flag.
// This prevents a single transient blip (e.g. a Redis TCP reset) from
// tipping the endpoint to 503 and bouncing pods.
package health

import "sync"

// Config configures anti-flap behaviour.
type Config struct {
	// FailThreshold is the number of consecutive failures required to flip
	// a component to unhealthy. Zero or negative → default 3.
	FailThreshold int
}

// State tracks per-component failure counts and unhealthy flags. Safe for
// concurrent use.
//
// Anti-flap semantics: a component flips to unhealthy only after N
// consecutive failures (default N=3 via Config.FailThreshold). Any single
// success resets both the failure counter and the unhealthy flag. Time-
// to-detect a real failure on /health/deep is therefore N × probe_interval
// — callers should tune probe cadence with this in mind.
type State struct {
	mu        sync.RWMutex
	failures  map[string]int
	unhealthy map[string]bool
	cfg       Config
}

// New constructs a State with the given config. A zero FailThreshold
// resolves to the documented default (3).
func New(cfg Config) *State {
	if cfg.FailThreshold <= 0 {
		cfg.FailThreshold = 3
	}
	return &State{
		failures:  make(map[string]int),
		unhealthy: make(map[string]bool),
		cfg:       cfg,
	}
}

// RecordFailure increments the failure count for component and returns
// whether the component is now unhealthy (count ≥ FailThreshold).
func (s *State) RecordFailure(component string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures[component]++
	if s.failures[component] >= s.cfg.FailThreshold {
		s.unhealthy[component] = true
		return true
	}
	return false
}

// RecordSuccess resets both the failure counter and unhealthy flag for the
// component.
func (s *State) RecordSuccess(component string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.failures, component)
	delete(s.unhealthy, component)
}

// IsUnhealthy reports whether the component has flipped to unhealthy.
// Unknown components are reported healthy.
func (s *State) IsUnhealthy(component string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.unhealthy[component]
}
