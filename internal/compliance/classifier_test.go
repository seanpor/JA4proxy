package compliance_test

import (
	"testing"

	"github.com/seanpor/ja4proxy/internal/compliance"
)

// TestClassify_HighestWeightWins verifies that when multiple signals are fired,
// the one with the highest weight determines the category.
// Mirror of test_highest_weight_wins in management/tests/test_compliance_classifier.py.
func TestClassify_HighestWeightWins(t *testing.T) {
	clf := compliance.NewSignalClassifier()
	// spamhaus_drop weight=100 beats sni_missing weight=55
	got := clf.Classify([]string{"sni_missing", "spamhaus_drop"})
	const want = "known_malicious_network"
	if got != want {
		t.Errorf("Classify = %q; want %q", got, want)
	}
}

// TestClassify_TieBrokenAlphabetically verifies that equal-weight signals
// resolve to the alphabetically earlier category name.
// Mirror of test_tie_broken_alphabetically_by_category in classifier.py tests.
func TestClassify_TieBrokenAlphabetically(t *testing.T) {
	clf := compliance.NewSignalClassifierWithOverrides(map[string]compliance.CategoryEntry{
		"signal_z": {Category: "zzz_category", Weight: 80},
		"signal_a": {Category: "aaa_category", Weight: 80},
	})
	got := clf.Classify([]string{"signal_z", "signal_a"})
	const want = "aaa_category"
	if got != want {
		t.Errorf("tie-break: Classify = %q; want %q", got, want)
	}
}

// TestClassify_FallbackOnEmptySignals verifies the fallback category is returned
// when no signals are provided.
func TestClassify_FallbackOnEmptySignals(t *testing.T) {
	clf := compliance.NewSignalClassifier()
	got := clf.Classify([]string{})
	if got != compliance.FallbackCategory {
		t.Errorf("empty signals: Classify = %q; want %q", got, compliance.FallbackCategory)
	}
}

// TestClassify_FallbackOnAllUnknownSignals verifies the fallback category is returned
// when all signals are unrecognised.
func TestClassify_FallbackOnAllUnknownSignals(t *testing.T) {
	clf := compliance.NewSignalClassifier()
	got := clf.Classify([]string{"unknown_signal_xyz", "another_bogus"})
	if got != compliance.FallbackCategory {
		t.Errorf("unknown signals: Classify = %q; want %q", got, compliance.FallbackCategory)
	}
}

// TestClassify_NilSignals verifies nil slice behaves identically to empty slice.
func TestClassify_NilSignals(t *testing.T) {
	clf := compliance.NewSignalClassifier()
	got := clf.Classify(nil)
	if got != compliance.FallbackCategory {
		t.Errorf("nil signals: Classify = %q; want %q", got, compliance.FallbackCategory)
	}
}

// TestClassify_SingleSignal verifies a single known signal maps correctly.
func TestClassify_SingleSignal(t *testing.T) {
	clf := compliance.NewSignalClassifier()
	got := clf.Classify([]string{"tor_exit"})
	const want = "tor_exit_node"
	if got != want {
		t.Errorf("Classify(tor_exit) = %q; want %q", got, want)
	}
}

// TestClassify_OverrideBeatsDefault verifies that an override with higher weight
// beats the default entry for the same signal.
// Mirror of test_custom_weight_override_beats_default.
func TestClassify_OverrideBeatsDefault(t *testing.T) {
	// Default: sni_missing weight=55, spamhaus_drop weight=100
	// Override: sni_missing to weight=200 — should now win.
	clf := compliance.NewSignalClassifierWithOverrides(map[string]compliance.CategoryEntry{
		"sni_missing": {Category: "custom_category", Weight: 200},
	})
	got := clf.Classify([]string{"sni_missing", "spamhaus_drop"})
	const want = "custom_category"
	if got != want {
		t.Errorf("override: Classify = %q; want %q", got, want)
	}
}

// TestClassify_OverrideAddsNewSignal verifies that an unknown key added via overrides
// is accessible and can win.
func TestClassify_OverrideAddsNewSignal(t *testing.T) {
	clf := compliance.NewSignalClassifierWithOverrides(map[string]compliance.CategoryEntry{
		"brand_new_signal": {Category: "novel_category", Weight: 999},
	})
	got := clf.Classify([]string{"brand_new_signal", "spamhaus_drop"})
	const want = "novel_category"
	if got != want {
		t.Errorf("new override signal: Classify = %q; want %q", got, want)
	}
}

// TestClassify_OriginalDefaultsUnchangedAfterOverride verifies that constructing
// an overridden classifier does not mutate DefaultSignalCategories.
func TestClassify_OriginalDefaultsUnchangedAfterOverride(t *testing.T) {
	_ = compliance.NewSignalClassifierWithOverrides(map[string]compliance.CategoryEntry{
		"spamhaus_drop": {Category: "mutated", Weight: 1},
	})
	// DefaultSignalCategories must be unchanged.
	entry, ok := compliance.DefaultSignalCategories["spamhaus_drop"]
	if !ok {
		t.Fatal("spamhaus_drop missing from DefaultSignalCategories")
	}
	if entry.Category != "known_malicious_network" {
		t.Errorf("DefaultSignalCategories mutated: category = %q; want known_malicious_network", entry.Category)
	}
	if entry.Weight != 100 {
		t.Errorf("DefaultSignalCategories mutated: weight = %d; want 100", entry.Weight)
	}
}

// TestClassifyEvent_AddsCategoryField verifies ClassifyEvent returns a map with
// a "category" field and does not modify the original event.
func TestClassifyEvent_AddsCategoryField(t *testing.T) {
	clf := compliance.NewSignalClassifier()
	original := map[string]interface{}{
		"ip":      "1.2.3.4",
		"signals": []string{"tor_exit"},
	}
	result := clf.ClassifyEvent(original)

	// Category must be present and correct.
	cat, ok := result["category"]
	if !ok {
		t.Fatal("ClassifyEvent: 'category' field missing from result")
	}
	if cat != "tor_exit_node" {
		t.Errorf("ClassifyEvent category = %q; want tor_exit_node", cat)
	}

	// Original must be unchanged (non-mutating contract).
	if _, found := original["category"]; found {
		t.Error("ClassifyEvent mutated the original event map")
	}
}

// TestClassifyEvent_InterfaceSignals verifies ClassifyEvent handles []interface{}
// signal values (as returned by JSON unmarshalling into interface{}).
func TestClassifyEvent_InterfaceSignals(t *testing.T) {
	clf := compliance.NewSignalClassifier()
	event := map[string]interface{}{
		"ip":      "1.2.3.4",
		"signals": []interface{}{"spamhaus_drop", "tor_exit"},
	}
	result := clf.ClassifyEvent(event)
	if result["category"] != "known_malicious_network" {
		t.Errorf("ClassifyEvent ([]interface{}) = %q; want known_malicious_network", result["category"])
	}
}

// TestClassifyEvent_MissingSignalsField verifies ClassifyEvent returns fallback
// when no "signals" field is present.
func TestClassifyEvent_MissingSignalsField(t *testing.T) {
	clf := compliance.NewSignalClassifier()
	event := map[string]interface{}{"ip": "1.2.3.4"}
	result := clf.ClassifyEvent(event)
	if result["category"] != compliance.FallbackCategory {
		t.Errorf("missing signals field: category = %q; want %q", result["category"], compliance.FallbackCategory)
	}
}

// TestClassifyBatch_Length verifies ClassifyBatch returns the same number of events
// as were passed in.
func TestClassifyBatch_Length(t *testing.T) {
	clf := compliance.NewSignalClassifier()
	events := []map[string]interface{}{
		{"ip": "1.1.1.1", "signals": []string{"tor_exit"}},
		{"ip": "2.2.2.2", "signals": []string{"spamhaus_drop"}},
		{"ip": "3.3.3.3", "signals": []string{}},
	}
	got := clf.ClassifyBatch(events)
	if len(got) != len(events) {
		t.Errorf("ClassifyBatch len = %d; want %d", len(got), len(events))
	}
}

// TestClassifyBatch_DoesNotMutateInput verifies that ClassifyBatch leaves
// the original event slice and event maps unmodified.
func TestClassifyBatch_DoesNotMutateInput(t *testing.T) {
	clf := compliance.NewSignalClassifier()
	events := []map[string]interface{}{
		{"ip": "1.1.1.1", "signals": []string{"tor_exit"}},
	}
	_ = clf.ClassifyBatch(events)
	if _, found := events[0]["category"]; found {
		t.Error("ClassifyBatch mutated input event map")
	}
}

// TestAllCategories_ReturnsSorted verifies AllCategories returns a sorted,
// deduplicated slice matching the set in DefaultSignalCategories.
func TestAllCategories_ReturnsSorted(t *testing.T) {
	clf := compliance.NewSignalClassifier()
	cats := clf.AllCategories()
	if len(cats) == 0 {
		t.Fatal("AllCategories returned empty slice")
	}
	for i := 1; i < len(cats); i++ {
		if cats[i] <= cats[i-1] {
			t.Errorf("AllCategories not sorted at index %d: %q <= %q", i, cats[i], cats[i-1])
		}
	}
}

// TestCategories_ReturnsCopy verifies that mutating the map returned by
// Categories() does not affect the classifier's internal state.
func TestCategories_ReturnsCopy(t *testing.T) {
	clf := compliance.NewSignalClassifier()
	copy1 := clf.Categories()
	copy1["spamhaus_drop"] = compliance.CategoryEntry{Category: "mutated", Weight: 1}
	// The classifier should still return the original entry.
	copy2 := clf.Categories()
	if copy2["spamhaus_drop"].Category != "known_malicious_network" {
		t.Error("Categories() returned a reference, not a copy")
	}
}

// TestCrossLanguageParity_Vectors tests the exact same input/output vectors as
// management/tests/test_compliance_classifier.py to guarantee cross-language parity.
// Any divergence here means the two implementations disagree.
func TestCrossLanguageParity_Vectors(t *testing.T) {
	clf := compliance.NewSignalClassifier()
	cases := []struct {
		signals []string
		want    string
	}{
		// Single high-priority signal
		{[]string{"spamhaus_drop"}, "known_malicious_network"},
		{[]string{"spamhaus_edrop"}, "known_malicious_network"},
		{[]string{"tor_exit"}, "tor_exit_node"},
		{[]string{"beaconing_detected"}, "c2_beaconing"},
		{[]string{"ja4_blacklist"}, "malicious_tls_fingerprint"},
		{[]string{"abuseipdb_score_high"}, "reported_abuse"},
		{[]string{"tls_version_old"}, "obsolete_tls"},
		{[]string{"sni_missing"}, "automation_tool"},
		{[]string{"sni_ip_literal"}, "automation_tool"},
		{[]string{"datacenter"}, "datacenter_scanner"},
		{[]string{"asn_datacenter"}, "datacenter_scanner"},
		{[]string{"country_blacklist"}, "geo_blocked"},
		// Empty/unknown → fallback
		{[]string{}, compliance.FallbackCategory},
		{[]string{"not_a_real_signal"}, compliance.FallbackCategory},
		// Multi-signal — highest weight wins
		{[]string{"sni_missing", "spamhaus_drop"}, "known_malicious_network"},
		{[]string{"country_blacklist", "tor_exit"}, "tor_exit_node"},
		// Tie: datacenter vs asn_datacenter — both "datacenter_scanner" weight 50
		// Both same category, so either way result is "datacenter_scanner"
		{[]string{"datacenter", "asn_datacenter"}, "datacenter_scanner"},
		// Tie: sni_missing vs sni_ip_literal — both "automation_tool" weight 55
		{[]string{"sni_missing", "sni_ip_literal"}, "automation_tool"},
	}
	for _, tc := range cases {
		got := clf.Classify(tc.signals)
		if got != tc.want {
			t.Errorf("Classify(%v) = %q; want %q", tc.signals, got, tc.want)
		}
	}
}
