package compliance_test

import (
	"sort"
	"testing"

	"github.com/seanpor/ja4proxy/internal/compliance"
	"pgregory.net/rapid"
)

// INV-COMPLIANCE-001: Signal Classifier Default Determinism
// DefaultSignalCategories mappings must be deterministically respected by NewSignalClassifier().
func TestInvariant_Compliance_DefaultDeterminism(t *testing.T) {
	clf := compliance.NewSignalClassifier()

	// 1. Single signal mapping verification
	for signal, expected := range compliance.DefaultSignalCategories {
		got := clf.Classify([]string{signal})
		if got != expected.Category {
			t.Fatalf("Default classification mismatch for signal %q: got %q, want %q", signal, got, expected.Category)
		}
	}

	// 2. Rapid property test: Random combinations of default signals follow highest weight / alphabetical rules
	rapid.Check(t, func(t *rapid.T) {
		signalKeys := make([]string, 0, len(compliance.DefaultSignalCategories))
		for k := range compliance.DefaultSignalCategories {
			signalKeys = append(signalKeys, k)
		}

		drawnCount := rapid.IntRange(1, len(signalKeys)).Draw(t, "drawnCount")
		drawnSignals := rapid.SliceOfNDistinct(rapid.SampledFrom(signalKeys), drawnCount, drawnCount, func(s string) string { return s }).Draw(t, "drawnSignals")

		gotCategory := clf.Classify(drawnSignals)

		// Calculate expected winner manually
		bestWeight := -1
		bestCategory := compliance.FallbackCategory
		for _, s := range drawnSignals {
			entry := compliance.DefaultSignalCategories[s]
			if entry.Weight > bestWeight || (entry.Weight == bestWeight && entry.Category < bestCategory) {
				bestWeight = entry.Weight
				bestCategory = entry.Category
			}
		}

		if gotCategory != bestCategory {
			t.Fatalf("Multi-signal classification mismatch for %v: got %q, want %q", drawnSignals, gotCategory, bestCategory)
		}
	})
}

// INV-COMPLIANCE-002: Signal Classifier Override Precedence
// Custom overrides in NewSignalClassifierWithOverrides merged over defaults and take precedence according to weight and alphabetical rules.
func TestInvariant_Compliance_OverridePrecedence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate random custom category entries as overrides
		numOverrides := rapid.IntRange(1, 10).Draw(t, "numOverrides")
		overrides := make(map[string]compliance.CategoryEntry, numOverrides)

		for i := 0; i < numOverrides; i++ {
			sig := rapid.StringMatching(`override_sig_[a-z]{3,8}`).Draw(t, "overrideSig")
			cat := rapid.StringMatching(`override_cat_[a-z]{3,8}`).Draw(t, "overrideCat")
			weight := rapid.IntRange(1, 200).Draw(t, "overrideWeight")
			overrides[sig] = compliance.CategoryEntry{
				Category: cat,
				Weight:   weight,
			}
		}

		clf := compliance.NewSignalClassifierWithOverrides(overrides)

		// Verify that all override signals exist in Categories()
		allCats := clf.Categories()
		for sig, entry := range overrides {
			gotEntry, ok := allCats[sig]
			if !ok {
				t.Fatalf("Override signal %q not present in Categories()", sig)
			}
			if gotEntry != entry {
				t.Fatalf("Override entry mismatch for %q: got %+v, want %+v", sig, gotEntry, entry)
			}
		}

		// Verify classification logic with overrides mixed with defaults
		mixedSignals := make([]string, 0)
		for k := range overrides {
			mixedSignals = append(mixedSignals, k)
		}
		for k := range compliance.DefaultSignalCategories {
			mixedSignals = append(mixedSignals, k)
		}
		sort.Strings(mixedSignals)

		drawnCount := rapid.IntRange(1, len(mixedSignals)).Draw(t, "drawnCount")
		drawnSignals := rapid.SliceOfNDistinct(rapid.SampledFrom(mixedSignals), drawnCount, drawnCount, func(s string) string { return s }).Draw(t, "drawnSignals")

		gotCategory := clf.Classify(drawnSignals)

		// Compute expected winner manually using merged map
		mergedMap := make(map[string]compliance.CategoryEntry)
		for k, v := range compliance.DefaultSignalCategories {
			mergedMap[k] = v
		}
		for k, v := range overrides {
			mergedMap[k] = v
		}

		bestWeight := -1
		bestCategory := compliance.FallbackCategory
		for _, s := range drawnSignals {
			entry := mergedMap[s]
			if entry.Weight > bestWeight || (entry.Weight == bestWeight && entry.Category < bestCategory) {
				bestWeight = entry.Weight
				bestCategory = entry.Category
			}
		}

		if gotCategory != bestCategory {
			t.Fatalf("Classification with overrides mismatch for %v: got %q, want %q", drawnSignals, gotCategory, bestCategory)
		}
	})
}
