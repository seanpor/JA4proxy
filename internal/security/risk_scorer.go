package security

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// thresholdOrder defines the action resolution order (highest severity first).
var thresholdOrder = []string{"ban", "block", "tarpit", "rate_limit", "flag"}

// defaultThresholds matches the proxy.yml defaults and the Python RiskScorer.
var defaultThresholds = map[string]int{
	"flag":       20,
	"rate_limit": 35,
	"tarpit":     55,
	"block":      70,
	"ban":        85,
}

// RiskAssessment is the output of RiskScorer.Score.
type RiskAssessment struct {
	// TotalScore is the composite score 0–100 (never below 0, never above 100).
	TotalScore int
	// Signals contains all contributing signals as received by the scorer.
	Signals []RiskSignal
	// RecommendedAction is the action derived from thresholds alone, before dial.
	// Values: allow | flag | rate_limit | tarpit | block | ban
	RecommendedAction string
	// Explanation contains the top-3 signals formatted for log output.
	Explanation string
}

// RiskScorer aggregates RiskSignal objects into a RiskAssessment.
// It is thread-safe (no mutable state after construction).
type RiskScorer struct {
	thresholds map[string]int
}

// NewRiskScorer creates a RiskScorer with the given thresholds.
// Missing keys fall back to defaultThresholds.
func NewRiskScorer(thresholds map[string]int) *RiskScorer {
	t := make(map[string]int, len(defaultThresholds))
	for k, v := range defaultThresholds {
		t[k] = v
	}
	for k, v := range thresholds {
		t[k] = v
	}
	return &RiskScorer{thresholds: t}
}

// NewRiskScorerDefault creates a RiskScorer with default thresholds.
func NewRiskScorerDefault() *RiskScorer {
	return NewRiskScorer(nil)
}

// Score computes the composite score and recommended action.
// An empty signal list returns score=0, action=allow.
func (r *RiskScorer) Score(signals []RiskSignal) RiskAssessment {
	// Clamp individual signals to [-100, 100]
	validated := make([]RiskSignal, 0, len(signals))
	for _, sig := range signals {
		clamped := sig.Score
		if clamped > 100 {
			clamped = 100
		} else if clamped < -100 {
			clamped = -100
		}
		if clamped != sig.Score {
			sig = RiskSignal{
				Name:   sig.Name,
				Score:  clamped,
				Reason: sig.Reason,
				Weight: sig.Weight,
			}
		}
		validated = append(validated, sig)
	}

	// Sum weighted contributions
	raw := 0
	for _, s := range validated {
		w := s.Weight
		if w == 0 {
			w = 1.0
		}
		raw += int(math.Round(float64(s.Score) * w))
	}

	// Clamp composite to 0–100
	total := raw
	if total < 0 {
		total = 0
	} else if total > 100 {
		total = 100
	}

	action := deriveAction(total, r.thresholds)
	explanation := buildExplanation(validated)

	return RiskAssessment{
		TotalScore:        total,
		Signals:           validated,
		RecommendedAction: action,
		Explanation:       explanation,
	}
}

// deriveAction returns the highest-triggered action for the given score.
func deriveAction(score int, thresholds map[string]int) string {
	for _, action := range thresholdOrder {
		threshold, ok := thresholds[action]
		if !ok {
			threshold = defaultThresholds[action]
		}
		if score >= threshold {
			return action
		}
	}
	return "allow"
}

// buildExplanation formats the top-3 signals by absolute weighted contribution.
func buildExplanation(signals []RiskSignal) string {
	if len(signals) == 0 {
		return ""
	}
	sorted := make([]RiskSignal, len(signals))
	copy(sorted, signals)
	sort.Slice(sorted, func(i, j int) bool {
		wi := sorted[i].Weight
		if wi == 0 {
			wi = 1.0
		}
		wj := sorted[j].Weight
		if wj == 0 {
			wj = 1.0
		}
		ai := abs(int(float64(sorted[i].Score) * wi))
		aj := abs(int(float64(sorted[j].Score) * wj))
		return ai > aj
	})
	if len(sorted) > 3 {
		sorted = sorted[:3]
	}
	parts := make([]string, len(sorted))
	for i, s := range sorted {
		sign := "+"
		if s.Score < 0 {
			sign = ""
		}
		parts[i] = fmt.Sprintf("%s(%s%d)", s.Name, sign, s.Score)
	}
	return strings.Join(parts, ", ")
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
