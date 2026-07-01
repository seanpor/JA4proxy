package metrics

import (
	"testing"
)

func TestCardinalityGuard_GetLabel_KnownValue(t *testing.T) {
	g := NewCardinalityGuard(10)
	// First call adds the value.
	got := g.GetLabel("chrome")
	if got != "chrome" {
		t.Errorf("GetLabel(%q) = %q, want %q", "chrome", got, "chrome")
	}
	// Second call returns the same value (already in the set).
	got2 := g.GetLabel("chrome")
	if got2 != "chrome" {
		t.Errorf("GetLabel(%q) second call = %q, want %q", "chrome", got2, "chrome")
	}
}

func TestCardinalityGuard_GetLabel_ExceedsMax(t *testing.T) {
	g := NewCardinalityGuard(2)
	g.GetLabel("a")
	g.GetLabel("b")
	// Third unique value exceeds maxUnique → "other".
	got := g.GetLabel("c")
	if got != "other" {
		t.Errorf("GetLabel(c) with full guard = %q, want %q", got, "other")
	}
}

func TestCardinalityGuard_GetLabel_Empty(t *testing.T) {
	g := NewCardinalityGuard(5)
	got := g.GetLabel("")
	if got != "" {
		t.Errorf("GetLabel('') = %q, want empty string", got)
	}
}

func TestGlobalGuards_NotNil(t *testing.T) {
	if SNIGuard == nil {
		t.Error("SNIGuard should be initialised")
	}
	if JA4Guard == nil {
		t.Error("JA4Guard should be initialised")
	}
}
