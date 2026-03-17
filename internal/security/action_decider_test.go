package security

import (
	"testing"
)

// TestEffectiveThreshold tests the interpolation formula from Python docs.
// Examples from action_decider.py docstring:
//
//	EffectiveThreshold(70, 0)   → 101
//	EffectiveThreshold(70, 100) → 70
//	EffectiveThreshold(70, 50)  → 86
//	EffectiveThreshold(20, 50)  → 60
func TestEffectiveThreshold(t *testing.T) {
	cases := []struct {
		configured int
		dial       int
		expected   int
	}{
		{70, 0, 101},   // monitor mode — unreachable
		{70, 100, 70},  // full blocking — exact configured
		{70, 50, 86},   // round(101 - 0.5 * 31) = round(85.5) = 86
		{20, 50, 60},   // round(101 - 0.5 * 81) = round(60.5) = 60
		{85, 0, 101},   // ban at monitor mode
		{85, 100, 85},  // ban at full blocking
		{55, 50, 74},   // round(101 - 0.5 * 46) = round(78) = 78? let me recalculate
		                // Actually: round(101 - 0.5 * (101-55)) = round(101 - 0.5*46) = round(101-23) = round(78) = 78
	}
	// Fix the 55,50 case
	cases[6].expected = 78

	for _, tc := range cases {
		got := EffectiveThreshold(tc.configured, tc.dial)
		if got != tc.expected {
			t.Errorf("EffectiveThreshold(%d, %d) = %d, want %d",
				tc.configured, tc.dial, got, tc.expected)
		}
	}
}

func TestEffectiveThreshold_Boundary(t *testing.T) {
	// At dial=0, always 101 regardless of configured
	for _, cfg := range []int{0, 20, 50, 70, 85, 100} {
		if got := EffectiveThreshold(cfg, 0); got != 101 {
			t.Errorf("EffectiveThreshold(%d, 0) = %d, want 101", cfg, got)
		}
	}
	// At dial=100, equals configured exactly
	for _, cfg := range []int{0, 20, 50, 70, 85, 100} {
		if got := EffectiveThreshold(cfg, 100); got != cfg {
			t.Errorf("EffectiveThreshold(%d, 100) = %d, want %d", cfg, got, cfg)
		}
	}
}

func TestActionDecider_MonitorMode(t *testing.T) {
	d := NewActionDeciderDefault()
	// dial=0 → always allow regardless of score
	for _, score := range []int{0, 20, 50, 70, 85, 100} {
		got := d.Decide(score, 0)
		if got != "allow" {
			t.Errorf("dial=0, score=%d: got %q, want 'allow'", score, got)
		}
	}
}

func TestActionDecider_FullBlocking(t *testing.T) {
	d := NewActionDeciderDefault()
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
		got := d.Decide(tc.score, 100)
		if got != tc.expected {
			t.Errorf("dial=100, score=%d: got %q, want %q", tc.score, got, tc.expected)
		}
	}
}

func TestActionDecider_IntermediateDial(t *testing.T) {
	d := NewActionDeciderDefault()
	// At dial=50, thresholds are pushed higher:
	// flag: EffectiveThreshold(20, 50) = 60
	// block: EffectiveThreshold(70, 50) = 86
	// So score=50 should be "allow" (below effective flag threshold of 60)
	got := d.Decide(50, 50)
	if got != "allow" {
		t.Errorf("dial=50, score=50: got %q, want 'allow' (flag threshold raised to 60)", got)
	}
	// score=60 should be "flag"
	got = d.Decide(60, 50)
	if got != "flag" {
		t.Errorf("dial=50, score=60: got %q, want 'flag'", got)
	}
}

func TestActionDecider_Counterfactuals(t *testing.T) {
	d := NewActionDeciderDefault()
	score := 75 // Would be "block" at dial=100
	cf := d.Counterfactuals(score, []int{0, 25, 50, 75, 100})

	if cf[0] != "allow" {
		t.Errorf("counterfactual dial=0: got %q, want 'allow'", cf[0])
	}
	if cf[100] != "block" {
		t.Errorf("counterfactual dial=100: got %q, want 'block'", cf[100])
	}
	// All dial values should have an entry
	for _, d := range []int{0, 25, 50, 75, 100} {
		if _, ok := cf[d]; !ok {
			t.Errorf("counterfactual missing dial value %d", d)
		}
	}
}

func TestActionDecider_CustomThresholds(t *testing.T) {
	d := NewActionDecider(map[string]int{
		"block": 50,
		"ban":   60,
	})
	// At dial=100, block threshold is now 50
	got := d.Decide(55, 100)
	if got != "block" {
		t.Errorf("custom block=50, score=55: got %q, want 'block'", got)
	}
	got = d.Decide(62, 100)
	if got != "ban" {
		t.Errorf("custom ban=60, score=62: got %q, want 'ban'", got)
	}
}

func TestActionDecider_ScoreZero_IsAllow(t *testing.T) {
	d := NewActionDeciderDefault()
	got := d.Decide(0, 100)
	if got != "allow" {
		t.Errorf("score=0, dial=100: got %q, want 'allow'", got)
	}
}

func TestActionDecider_ScoreAtThresholdBoundary(t *testing.T) {
	d := NewActionDeciderDefault()
	// At exactly the ban threshold (85), should be "ban"
	got := d.Decide(85, 100)
	if got != "ban" {
		t.Errorf("score=85, dial=100: got %q, want 'ban'", got)
	}
	// Just below (84) should be "block"
	got = d.Decide(84, 100)
	if got != "block" {
		t.Errorf("score=84, dial=100: got %q, want 'block'", got)
	}
}
