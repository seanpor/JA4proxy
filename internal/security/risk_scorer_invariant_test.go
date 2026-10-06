package security_test

import (
	"testing"

	"github.com/seanpor/ja4proxy/internal/security"
	"pgregory.net/rapid"
)

// INV-SCORE-001: Risk Score Bounding
// forall signals, 0 <= TotalScore <= 100
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

// INV-SCORE-002: Risk Score Monotonicity
// S(x U {MaliciousSignal}) >= S(x), S(x U {TrustSignal}) <= S(x)
func TestInvariant_Score_Monotonicity(t *testing.T) {
	scorer := security.NewRiskScorerDefault()

	rapid.Check(t, func(t *rapid.T) {
		numSignals := rapid.IntRange(1, 10).Draw(t, "numSignals")
		baseSignals := make([]security.RiskSignal, numSignals)

		for i := 0; i < numSignals; i++ {
			baseSignals[i] = security.RiskSignal{
				Name:   rapid.StringMatching("[a-z0-9_]{3,10}").Draw(t, "signalName"),
				Score:  rapid.IntRange(-50, 50).Draw(t, "signalScore"),
				Weight: 1.0,
			}
		}

		baseAssessment := scorer.Score(baseSignals)

		// Malicious signal (positive score)
		maliciousScore := rapid.IntRange(1, 100).Draw(t, "maliciousScore")
		maliciousSignal := security.RiskSignal{Name: "malicious_sig", Score: maliciousScore, Weight: 1.0}
		withMalicious := append([]security.RiskSignal(nil), baseSignals...)
		withMalicious = append(withMalicious, maliciousSignal)
		maliciousAssessment := scorer.Score(withMalicious)

		if maliciousAssessment.TotalScore < baseAssessment.TotalScore {
			t.Fatalf("Monotonicity violation: adding malicious signal lowered score from %d to %d",
				baseAssessment.TotalScore, maliciousAssessment.TotalScore)
		}

		// Trust signal (negative score)
		trustScore := rapid.IntRange(-100, -1).Draw(t, "trustScore")
		trustSignal := security.RiskSignal{Name: "trust_sig", Score: trustScore, Weight: 1.0}
		withTrust := append([]security.RiskSignal(nil), baseSignals...)
		withTrust = append(withTrust, trustSignal)
		trustAssessment := scorer.Score(withTrust)

		if trustAssessment.TotalScore > baseAssessment.TotalScore {
			t.Fatalf("Monotonicity violation: adding trust signal raised score from %d to %d",
				baseAssessment.TotalScore, trustAssessment.TotalScore)
		}
	})
}

// INV-SCORE-003: Empty Signal List Zero Evaluation
// empty signals => score == 0, action == "allow"
func TestInvariant_Score_EmptySignalsZero(t *testing.T) {
	scorer := security.NewRiskScorerDefault()
	assessment := scorer.Score(nil)

	if assessment.TotalScore != 0 {
		t.Fatalf("Empty signals expected score 0, got %d", assessment.TotalScore)
	}
	if assessment.RecommendedAction != "allow" {
		t.Fatalf("Empty signals expected action 'allow', got %q", assessment.RecommendedAction)
	}
}

// INV-SCORE-004: Individual Signal Clamping Sanitization
// forall s in signals, Clamped(s.Score) in [-100, 100]
func TestInvariant_Score_ClampedSignalSanitization(t *testing.T) {
	scorer := security.NewRiskScorerDefault()

	rapid.Check(t, func(t *rapid.T) {
		extremeScore := rapid.IntRange(101, 10000).Draw(t, "extremeScore")
		sig := security.RiskSignal{Name: "extreme", Score: extremeScore, Weight: 1.0}

		assessment := scorer.Score([]security.RiskSignal{sig})
		if assessment.TotalScore > 100 {
			t.Fatalf("Extreme positive signal escaped clamping: total score %d", assessment.TotalScore)
		}

		extremeNegScore := rapid.IntRange(-10000, -101).Draw(t, "extremeNegScore")
		sigNeg := security.RiskSignal{Name: "extreme_neg", Score: extremeNegScore, Weight: 1.0}

		assessmentNeg := scorer.Score([]security.RiskSignal{sigNeg})
		if assessmentNeg.TotalScore < 0 {
			t.Fatalf("Extreme negative signal escaped clamping: total score %d", assessmentNeg.TotalScore)
		}
	})
}
