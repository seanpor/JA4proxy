// Phase 62 — Property-based tests for the security package using
// pgregory.net/rapid. These tests assert load-bearing invariants of the
// scoring and decision logic that are easy to break with a one-line change
// and hard to spot with example-based tests.
//
// Four properties:
//
//  1. PropertyScoreInRange     — Score(...) ∈ [0, 100] for any signal slice
//  2. PropertyScoreMonotonic   — adding a positive signal never decreases the score
//  3. PropertyDecisionIdempotent — Decide(score, dial) twice returns the same action
//  4. PropertyDialZeroNeverBlocks — dial=0 never returns a blocking action
//
// If any property test fails, do NOT silently weaken the property to make it
// pass. A failing property is a real bug — document it in PHASE_62_notes.md
// and surface it to the reviewer.
package security

import (
	"testing"

	"pgregory.net/rapid"
)

// genRiskSignal returns a generator for arbitrary RiskSignals with a score
// in [-100, 100] and a weight in [0, 2]. Names and reasons are short fixed
// strings — they are not load-bearing for any property under test.
func genRiskSignal() *rapid.Generator[RiskSignal] {
	return rapid.Custom(func(t *rapid.T) RiskSignal {
		return RiskSignal{
			Name:   rapid.SampledFrom([]string{"a", "b", "c", "d"}).Draw(t, "name"),
			Score:  rapid.IntRange(-100, 100).Draw(t, "score"),
			Reason: "synthetic",
			Weight: rapid.Float64Range(0, 2).Draw(t, "weight"),
		}
	})
}

// genPositiveRiskSignal returns a generator for signals with a strictly
// positive score and a non-zero weight. Used to test the monotonicity
// property: appending such a signal must never decrease the composite
// score (until the [0, 100] cap is hit).
func genPositiveRiskSignal() *rapid.Generator[RiskSignal] {
	return rapid.Custom(func(t *rapid.T) RiskSignal {
		return RiskSignal{
			Name:   "pos",
			Score:  rapid.IntRange(1, 100).Draw(t, "score"),
			Reason: "synthetic-positive",
			Weight: rapid.Float64Range(0.1, 2).Draw(t, "weight"),
		}
	})
}

// testThresholds returns a default-shaped threshold map for the action
// decider used in the property tests.
func testThresholds() map[string]int {
	return map[string]int{
		"flag":       20,
		"rate_limit": 35,
		"tarpit":     55,
		"block":      70,
		"ban":        85,
	}
}

// TestProperty_ScoreInRange — for any list of RiskSignals, the composite
// score is in [0, 100] inclusive. The scorer caps and floors; this test
// asserts the cap and floor cannot be bypassed by adversarial signal
// combinations.
func TestProperty_ScoreInRange(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		signals := rapid.SliceOf(genRiskSignal()).Draw(rt, "signals")
		assessment := NewRiskScorerDefault().Score(signals)
		if assessment.TotalScore < 0 || assessment.TotalScore > 100 {
			rt.Fatalf("score out of range: %d for %v", assessment.TotalScore, signals)
		}
	})
}

// TestProperty_ScoreMonotonic — adding a positive-weight signal never
// decreases the score. The check skips the assertion when the base score is
// already at the cap (100) since further additions are clipped.
func TestProperty_ScoreMonotonic(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		base := rapid.SliceOf(genRiskSignal()).Draw(rt, "base")
		extra := genPositiveRiskSignal().Draw(rt, "extra")
		scorer := NewRiskScorerDefault()
		before := scorer.Score(base).TotalScore
		after := scorer.Score(append(base, extra)).TotalScore
		if before < 100 && after < before {
			rt.Fatalf("adding positive signal decreased score: %d → %d (extra=%+v)", before, after, extra)
		}
	})
}

// TestProperty_DecisionIdempotent — calling Decide twice on the same input
// returns the same action. This guards against accidental state mutation
// in the decider.
func TestProperty_DecisionIdempotent(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		score := rapid.IntRange(0, 100).Draw(rt, "score")
		dial := rapid.IntRange(0, 100).Draw(rt, "dial")
		d := NewActionDecider(testThresholds())
		a := d.Decide(score, dial)
		b := d.Decide(score, dial)
		if a != b {
			rt.Fatalf("Decide not idempotent at score=%d dial=%d: %q vs %q", score, dial, a, b)
		}
	})
}

// TestProperty_DialZeroNeverBlocks — at dial=0 (monitor mode), no score,
// however high, results in a blocking action. This is the load-bearing
// invariant from CLAUDE.md: "Default dial is 0. The proxy never blocks on
// first deploy."
func TestProperty_DialZeroNeverBlocks(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		score := rapid.IntRange(0, 100).Draw(rt, "score")
		d := NewActionDecider(testThresholds())
		a := d.Decide(score, 0)
		switch a {
		case "block", "ban", "tarpit":
			rt.Fatalf("dial=0 produced blocking action %q at score=%d", a, score)
		}
	})
}
