package security

import "math"

// EffectiveThreshold returns the effective minimum score to trigger an action
// at the given dial value.
//
// Formula: round(101 - (dial/100) × (101 - configured))
//
// Uses Python-compatible banker's rounding (round half to even) to produce
// byte-for-byte identical results to the Python effective_threshold() function.
//
// Examples:
//
//	EffectiveThreshold(70, 0)   → 101   // unreachable; monitor mode
//	EffectiveThreshold(70, 100) → 70    // exact configured threshold
//	EffectiveThreshold(70, 50)  → 86    // round(101 - 0.5 × 31) = round(85.5) = 86
//	EffectiveThreshold(20, 50)  → 60    // round(101 - 0.5 × 81) = round(60.5) = 60
func EffectiveThreshold(configured, dial int) int {
	if dial == 0 {
		return 101
	}
	raw := 101.0 - (float64(dial)/100.0)*(101.0-float64(configured))
	// Python uses banker's rounding (round half to even); replicate it here.
	floor := math.Floor(raw)
	frac := raw - floor
	if frac == 0.5 {
		// Round to nearest even integer
		if int(floor)%2 == 0 {
			return int(floor)
		}
		return int(floor) + 1
	}
	return int(math.Round(raw))
}

// ActionDecider maps (score, dial) → final action string.
// It is thread-safe (no mutable state after construction).
type ActionDecider struct {
	thresholds map[string]int
}

// NewActionDecider creates an ActionDecider with the given thresholds.
// Missing keys fall back to defaultThresholds.
func NewActionDecider(thresholds map[string]int) *ActionDecider {
	t := make(map[string]int, len(defaultThresholds))
	for k, v := range defaultThresholds {
		t[k] = v
	}
	for k, v := range thresholds {
		t[k] = v
	}
	return &ActionDecider{thresholds: t}
}

// NewActionDeciderDefault creates an ActionDecider with default thresholds.
func NewActionDeciderDefault() *ActionDecider {
	return NewActionDecider(nil)
}

// Decide returns the final action string for this connection.
//
// At dial=0, always returns "allow" (monitor mode).
// At dial=100, thresholds apply exactly as configured.
// Intermediate dial values interpolate thresholds upward.
func (a *ActionDecider) Decide(score, dial int) string {
	if dial == 0 {
		return "allow"
	}
	for _, action := range thresholdOrder {
		configured, ok := a.thresholds[action]
		if !ok {
			configured = defaultThresholds[action]
		}
		if score >= EffectiveThreshold(configured, dial) {
			return action
		}
	}
	return "allow"
}

// Counterfactuals returns {dial_value: action} for each dial in dialValues.
// Used for monitor-mode logging.
func (a *ActionDecider) Counterfactuals(score int, dialValues []int) map[int]string {
	result := make(map[int]string, len(dialValues))
	for _, d := range dialValues {
		result[d] = a.Decide(score, d)
	}
	return result
}
