# Security Scoring & Telemetry Conservation Invariants

## Goal
Implement property-based invariant test suites for JA4proxy's threat scoring engine and Prometheus observability metrics (`internal/security/`, `internal/metrics/`, and `src/security/`). Establish formal mathematical guarantees that risk scores are strictly bounded and monotonic (adverse signals never reduce risk), that scores decay predictably over time, and that the fundamental Telemetry Conservation Law holds across all connection processing pathways (every accepted connection terminates in an audited, counted outcome with zero silent drops).

---

## Scope
1. **Target Packages**:
   - `internal/security/` (Go risk scoring, policy evaluation, signal aggregation).
   - `internal/metrics/` (Prometheus counters, histograms, connection accounting).
   - `src/security/` (Python scoring logic parity).
2. **New Test Files**:
   - `internal/security/scorer_invariant_test.go`
   - `internal/metrics/conservation_test.go`
3. **Formal Invariants to Enforce**:
   - **Invariant 1 (Score Bounding & Co-domain)**:
     For any set of observed signals $\mathcal{S}$:
     $$0 \le \text{CalculateRiskScore}(\mathcal{S}) \le 100$$
     No combination of negative or positive signals may produce a score $<0$ or $>100$.
   - **Invariant 2 (Monotonic Risk Elevation)**:
     Let $\mathcal{S}$ be a set of signals and $s_{\text{adverse}}$ be any malicious indicator (e.g. Tor exit node, high-frequency rate violation, malformed TLS, known bot JA4):
     $$\text{Score}(\mathcal{S} \cup \{s_{\text{adverse}}\}) \ge \text{Score}(\mathcal{S})$$
     Adding an adverse signal can never decrease risk or lower an existing mitigation tier.
   - **Invariant 3 (Predictable Temporal Decay)**:
     In the absence of new adverse events, an elevated risk score must decay monotonically toward baseline 0 as time elapses:
     $$t_1 < t_2 \implies \text{Score}(t_1) \ge \text{Score}(t_2)$$
   - **Invariant 4 (Telemetry Conservation Law)**:
     At any time $T$, total client connections accepted by the proxy listener must exactly equal the sum of terminal connection outcomes:
     $$\Delta\text{ConnectionsAccepted} \equiv \Delta\text{Forwarded} + \Delta\text{Blocked} + \Delta\text{Tarpitted} + \Delta\text{Dropped}$$
     No connection can disappear into a silent fail-open or fail-closed branch without updating the telemetry matrix.

---

## Junior Developer Implementation Guide

### Step 1: Set up Risk Scorer Test Harness
In `internal/security/scorer_invariant_test.go`:
```go
package security_test

import (
	"testing"
	"testing/quick"
	"time"

	"github.com/seanpor/ja4proxy/internal/security"
)
```

### Step 2: Implement Invariant 1 & 2 Test (Score Bounding & Monotonicity)
```go
func TestInvariant_ScoreBoundingAndMonotonicity(t *testing.T) {
	scorer := security.NewScorer()

	// 1. Generate arbitrary combinations of signals
	property := func(signalIDs []uint8) bool {
		signals := convertToSignals(signalIDs)
		score := scorer.Calculate(signals)

		// Assert Bounding: 0 <= score <= 100
		if score < 0 || score > 100 {
			return false
		}

		// Assert Monotonicity: adding an adverse signal never lowers score
		for _, adverse := range security.AllAdverseSignals() {
			augmented := append(signals, adverse)
			newScore := scorer.Calculate(augmented)
			if newScore < score {
				return false // Monotonicity violated!
			}
		}
		return true
	}

	if err := quick.Check(property, &quick.Config{MaxCount: 1000}); err != nil {
		t.Fatalf("Score monotonicity or bounding violated: %v", err)
	}
}
```

### Step 3: Implement Invariant 3 Test (Monotonic Decay)
```go
func TestInvariant_TemporalDecayMonotonicity(t *testing.T) {
	scorer := security.NewScorer()
	initialScore := scorer.Calculate(highRiskSignals) // e.g. score = 85

	t0 := time.Now()
	prevScore := initialScore

	for step := 1; step <= 10; step++ {
		tCurrent := t0.Add(time.Duration(step) * 5 * time.Minute)
		decayedScore := scorer.CalculateAtTime(highRiskSignals, tCurrent)

		if decayedScore > prevScore {
			t.Fatalf("Score increased during decay period: step %d, got %d, prev %d", step, decayedScore, prevScore)
		}
		prevScore = decayedScore
	}

	if prevScore > 10 {
		t.Fatalf("Score failed to decay near baseline after 50 minutes: got %d", prevScore)
	}
}
```

### Step 4: Implement Invariant 4 Test (Telemetry Conservation Law)
In `internal/metrics/conservation_test.go`:
1. Read baseline values for Prometheus counters:
   - `ja4proxy_connections_accepted_total`
   - `ja4proxy_connections_forwarded_total`
   - `ja4proxy_connections_blocked_total`
   - `ja4proxy_connections_tarpitted_total`
   - `ja4proxy_connections_dropped_total`
2. Fire 1,000 mixed requests through proxy (300 valid TLS, 200 banned IPs, 200 rate-limited, 150 slowloris timeouts, 150 abrupt RSTs).
3. Read final counter values and assert:
   $$\Delta\text{Accepted} == \Delta\text{Forwarded} + \Delta\text{Blocked} + \Delta\text{Tarpitted} + \Delta\text{Dropped}$$
4. If the difference is non-zero, identify the exact uncounted code path and fail the test.

---

## Test Strategy
- Run security & metrics invariant tests:
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./internal/security ./internal/metrics -run Invariant`
- Run with race detector:
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -race -v ./internal/security ./internal/metrics`

---

## Acceptance Criteria
- [ ] `internal/security/scorer_invariant_test.go` implemented and passing.
- [ ] `internal/metrics/conservation_test.go` implemented and passing.
- [ ] Risk scores mathematically proven within $[0, 100]$ across 1,000 fuzz combinations.
- [ ] Monotonic risk elevation proven across all known adverse signals.
- [ ] Telemetry conservation equation verified: $\Delta\text{Accepted} \equiv \sum \text{Terminals}$ with 0 discrepancy across 1,000 mixed connections.
- [ ] `make test-unit` and `make preflight` pass 100% green.

---

## Out of Scope
- Management API RBAC authorization (covered in 606g).
- TCP reassembly logic (covered in 606e).
