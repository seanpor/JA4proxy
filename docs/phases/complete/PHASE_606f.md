# Intelligence, Risk Scoring & Temporal Decay Invariants

## Goal
Implement property-based invariant test suites for JA4proxy's risk scoring engine and threat intelligence evaluation (`internal/security`). Establish formal guarantees that total risk scores are strictly bounded within $[0, 100]$, that risk signal accumulation exhibits monotonic elevation under malicious signals and monotonic reduction under trust signals, that empty signal sets evaluate to zero score and allow action, and that individual extreme signal scores are sanitized and clamped prior to aggregation.

---

## Read These First
- `internal/security/risk_scorer.go` (composite score calculation and threshold mapping)
- `internal/security/models.go` (RiskSignal and RiskAssessment struct definitions)
- `internal/security/risk_scorer_test.go` (existing unit tests)

---

## Verified API Surface
- `NewRiskScorerDefault()` — `internal/security/risk_scorer.go`
- `(*RiskScorer).Score(signals)` — `internal/security/risk_scorer.go`

---

## Invariants

| ID | Plain-English Statement | Formal Statement | SecOps Rationale |
|---|---|---|---|
| `INV-SCORE-001` | Risk Score Bounding | $\forall \text{signals}, \quad 0 \le \text{TotalScore} \le 100$ | Guarantees composite risk scores never overflow or underflow mathematical limits. |
| `INV-SCORE-002` | Risk Score Monotonicity | $\mathcal{S}(x \cup \{s_+\}) \ge \mathcal{S}(x) \land \mathcal{S}(x \cup \{s_-\}) \le \mathcal{S}(x)$ | Ensures threat signal additions strictly elevate risk while trust signals strictly lower risk. |
| `INV-SCORE-003` | Empty Signal List Zero Evaluation | $\text{Signals} == \emptyset \implies \text{Score} == 0 \land \text{Action} == \text{"allow"}$ | Prevents default-deny un-triggered connections when zero risk signals are present. |
| `INV-SCORE-004` | Individual Signal Clamping Sanitization | $\forall s \in \text{signals}, \quad \text{Clamped}(s.\text{Score}) \in [-100, 100]$ | Sanitizes malformed or unbounded upstream feed scores before score aggregation. |

---

## Step-by-Step Implementation Guide

### Step 1: Create `internal/security/risk_scorer_invariant_test.go`
```go
package security_test

import (
	"testing"

	"github.com/seanpor/ja4proxy/internal/security"
	"pgregory.net/rapid"
)

func TestInvariant_Score_Bounding(t *testing.T) {
	scorer := security.NewRiskScorerDefault()

	rapid.Check(t, func(t *rapid.T) {
		numSignals := rapid.IntRange(0, 20).Draw(t, "numSignals")
		signals := make([]security.RiskSignal, numSignals)

		for i := 0; i < numSignals; i++ {
			signals[i] = security.RiskSignal{
				Name:   rapid.StringMatching("[a-z0-9_]{3,10}").Draw(t, "signalName"),
				Score:  rapid.IntRange(-500, 500).Draw(t, "signalScore"),
				Weight: rapid.Float64Range(0.0, 5.0).Draw(t, "signalWeight"),
			}
		}

		assessment := scorer.Score(signals)
		if assessment.TotalScore < 0 || assessment.TotalScore > 100 {
			t.Fatalf("Risk score out of bounds [0, 100]: got %d", assessment.TotalScore)
		}
	})
}
```

---

## Acceptance Criteria

- [x] `internal/security/risk_scorer_invariant_test.go` created and all 4 invariants passing.
- [x] Invariants registered in `docs/testing/invariants.yaml`.
- [x] Package `internal/security` coverage verified $\ge 90.6\%$.
- [x] News fragment created in `docs/fragments/phase-606f-risk-invariants.md`.
- [x] `make preflight` passes 100% green.

---

## Out of Scope
- Config reloading mechanisms (covered in Phase 606g).
- Management API routes (covered in Phase 606i).
