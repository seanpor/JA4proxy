package security

import (
	"strings"
	"testing"
)

func TestRiskScorer_EmptySignals(t *testing.T) {
	s := NewRiskScorerDefault()
	result := s.Score(nil)
	if result.TotalScore != 0 {
		t.Errorf("empty signals: score=%d, want 0", result.TotalScore)
	}
	if result.RecommendedAction != "allow" {
		t.Errorf("empty signals: action=%q, want 'allow'", result.RecommendedAction)
	}
	if result.Explanation != "" {
		t.Errorf("empty signals: explanation=%q, want empty", result.Explanation)
	}
}

func TestRiskScorer_SingleSignal(t *testing.T) {
	s := NewRiskScorerDefault()
	signals := []RiskSignal{
		{Name: "test_signal", Score: 30, Reason: "test", Weight: 1.0},
	}
	result := s.Score(signals)
	if result.TotalScore != 30 {
		t.Errorf("score: got %d, want 30", result.TotalScore)
	}
	if result.RecommendedAction != "flag" { // flag threshold = 20
		t.Errorf("action: got %q, want 'flag'", result.RecommendedAction)
	}
}

func TestRiskScorer_ClampIndividualSignalHigh(t *testing.T) {
	s := NewRiskScorerDefault()
	signals := []RiskSignal{
		{Name: "big", Score: 200, Reason: "test", Weight: 1.0},
	}
	result := s.Score(signals)
	// Signal clamped to 100, total clamped to 100
	if result.TotalScore != 100 {
		t.Errorf("clamped high: got %d, want 100", result.TotalScore)
	}
}

func TestRiskScorer_ClampIndividualSignalLow(t *testing.T) {
	s := NewRiskScorerDefault()
	signals := []RiskSignal{
		{Name: "big_neg", Score: -200, Reason: "test", Weight: 1.0},
	}
	result := s.Score(signals)
	// Signal clamped to -100, total clamped to 0
	if result.TotalScore != 0 {
		t.Errorf("clamped low: got %d, want 0", result.TotalScore)
	}
}

func TestRiskScorer_ClampTotalHigh(t *testing.T) {
	s := NewRiskScorerDefault()
	signals := []RiskSignal{
		{Name: "a", Score: 70, Reason: "test", Weight: 1.0},
		{Name: "b", Score: 80, Reason: "test", Weight: 1.0},
	}
	result := s.Score(signals)
	if result.TotalScore != 100 {
		t.Errorf("total clamped to 100: got %d", result.TotalScore)
	}
}

func TestRiskScorer_ClampTotalLow(t *testing.T) {
	s := NewRiskScorerDefault()
	signals := []RiskSignal{
		{Name: "trusted", Score: -50, Reason: "test", Weight: 1.0},
		{Name: "mild", Score: 20, Reason: "test", Weight: 1.0},
	}
	result := s.Score(signals)
	// raw = -30, clamped to 0
	if result.TotalScore != 0 {
		t.Errorf("total clamped to 0: got %d", result.TotalScore)
	}
}

func TestRiskScorer_WeightedContribution(t *testing.T) {
	s := NewRiskScorerDefault()
	signals := []RiskSignal{
		{Name: "weighted", Score: 50, Reason: "test", Weight: 0.5},
	}
	result := s.Score(signals)
	// 50 * 0.5 = 25
	if result.TotalScore != 25 {
		t.Errorf("weighted: got %d, want 25", result.TotalScore)
	}
}

func TestRiskScorer_ActionThresholds(t *testing.T) {
	s := NewRiskScorerDefault()
	cases := []struct {
		score    int
		expected string
	}{
		{0, "allow"},
		{19, "allow"},
		{20, "flag"},
		{34, "flag"},
		{35, "rate_limit"},
		{54, "rate_limit"},
		{55, "tarpit"},
		{69, "tarpit"},
		{70, "block"},
		{84, "block"},
		{85, "ban"},
		{100, "ban"},
	}
	for _, tc := range cases {
		signals := []RiskSignal{{Name: "test", Score: tc.score, Reason: "t", Weight: 1.0}}
		result := s.Score(signals)
		if result.RecommendedAction != tc.expected {
			t.Errorf("score=%d: got action %q, want %q", tc.score, result.RecommendedAction, tc.expected)
		}
	}
}

func TestRiskScorer_CustomThresholds(t *testing.T) {
	s := NewRiskScorer(map[string]int{
		"flag":  10,
		"block": 50,
	})
	signals := []RiskSignal{{Name: "test", Score: 15, Reason: "t", Weight: 1.0}}
	result := s.Score(signals)
	// flag threshold now 10, so 15 should be "flag"
	if result.RecommendedAction != "flag" {
		t.Errorf("custom threshold: got %q, want 'flag'", result.RecommendedAction)
	}
}

func TestRiskScorer_Explanation(t *testing.T) {
	s := NewRiskScorerDefault()
	signals := []RiskSignal{
		{Name: "aaa", Score: 10, Reason: "r", Weight: 1.0},
		{Name: "bbb", Score: 50, Reason: "r", Weight: 1.0},
		{Name: "ccc", Score: 30, Reason: "r", Weight: 1.0},
		{Name: "ddd", Score: 5, Reason: "r", Weight: 1.0},
	}
	result := s.Score(signals)
	// Top 3 by abs: bbb(50), ccc(30), aaa(10)
	if !strings.Contains(result.Explanation, "bbb(+50)") {
		t.Errorf("explanation should contain bbb(+50): %q", result.Explanation)
	}
	if !strings.Contains(result.Explanation, "ccc(+30)") {
		t.Errorf("explanation should contain ccc(+30): %q", result.Explanation)
	}
	// ddd should NOT be in explanation (only top 3)
	if strings.Contains(result.Explanation, "ddd") {
		t.Errorf("explanation should not contain 4th signal ddd: %q", result.Explanation)
	}
}

func TestRiskScorer_NegativeSignalInExplanation(t *testing.T) {
	s := NewRiskScorerDefault()
	signals := []RiskSignal{
		{Name: "trusted", Score: -30, Reason: "r", Weight: 1.0},
	}
	result := s.Score(signals)
	if !strings.Contains(result.Explanation, "trusted(-30)") {
		t.Errorf("negative signal in explanation: %q", result.Explanation)
	}
}

func TestRiskScorer_DefaultWeightIsOne(t *testing.T) {
	s := NewRiskScorerDefault()
	// Weight = 0 should be treated as 1.0
	signals := []RiskSignal{{Name: "test", Score: 40, Reason: "r", Weight: 0}}
	result := s.Score(signals)
	if result.TotalScore != 40 {
		t.Errorf("zero weight treated as 1.0: got %d, want 40", result.TotalScore)
	}
}
