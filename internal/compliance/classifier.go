// Package compliance provides cross-language compliance helpers for Phase 84.
// The SignalClassifier maps fired RiskSignal names to human-readable attack
// categories and is the Go counterpart of management/compliance/classifier.py.
// Both implementations must produce identical output for the same input — see
// the cross-language parity test in Makefile target test-phase-84-classifier-parity.
package compliance

import (
	"sort"
)

// CategoryEntry maps one signal name to its category and weight.
type CategoryEntry struct {
	Category string
	Weight   int
}

// DefaultSignalCategories mirrors DEFAULT_SIGNAL_CATEGORIES in classifier.py.
// Any change here MUST be mirrored in the Python file and vice versa.
var DefaultSignalCategories = map[string]CategoryEntry{
	"spamhaus_drop":        {Category: "known_malicious_network",   Weight: 100},
	"spamhaus_edrop":       {Category: "known_malicious_network",   Weight: 100},
	"tor_exit":             {Category: "tor_exit_node",             Weight: 95},
	"beaconing_detected":   {Category: "c2_beaconing",              Weight: 90},
	"ja4_blacklist":        {Category: "malicious_tls_fingerprint", Weight: 85},
	"abuseipdb_score_high": {Category: "reported_abuse",            Weight: 70},
	"tls_version_old":      {Category: "obsolete_tls",              Weight: 60},
	"sni_missing":          {Category: "automation_tool",           Weight: 55},
	"sni_ip_literal":       {Category: "automation_tool",           Weight: 55},
	"datacenter":           {Category: "datacenter_scanner",        Weight: 50},
	"asn_datacenter":       {Category: "datacenter_scanner",        Weight: 50},
	"country_blacklist":    {Category: "geo_blocked",               Weight: 40},
}

// FallbackCategory is returned when no signals match.
const FallbackCategory = "high_risk_score"

// SignalClassifier maps sets of fired RiskSignal names to attack categories.
type SignalClassifier struct {
	categories map[string]CategoryEntry
}

// NewSignalClassifier creates a classifier with the default signal categories.
func NewSignalClassifier() *SignalClassifier {
	cats := make(map[string]CategoryEntry, len(DefaultSignalCategories))
	for k, v := range DefaultSignalCategories {
		cats[k] = v
	}
	return &SignalClassifier{categories: cats}
}

// NewSignalClassifierWithOverrides creates a classifier where entries in
// overrides are merged over the defaults.  Unknown keys in overrides are
// added; known keys in overrides replace the default entry.
func NewSignalClassifierWithOverrides(overrides map[string]CategoryEntry) *SignalClassifier {
	clf := NewSignalClassifier()
	for k, v := range overrides {
		clf.categories[k] = v
	}
	return clf
}

// Categories returns a copy of the active signal→CategoryEntry mapping.
func (c *SignalClassifier) Categories() map[string]CategoryEntry {
	out := make(map[string]CategoryEntry, len(c.categories))
	for k, v := range c.categories {
		out[k] = v
	}
	return out
}

// Classify returns the attack category for the given set of fired signal names.
//
// Resolution rules:
//   - The entry with the highest weight wins.
//   - Ties are broken by alphabetical order of the category name (ascending).
//   - Unknown signal names are silently ignored.
//   - Empty or all-unknown signals return FallbackCategory.
func (c *SignalClassifier) Classify(signals []string) string {
	bestWeight := -1
	bestCategory := FallbackCategory

	for _, signal := range signals {
		entry, ok := c.categories[signal]
		if !ok {
			continue
		}
		if entry.Weight > bestWeight ||
			(entry.Weight == bestWeight && entry.Category < bestCategory) {
			bestWeight = entry.Weight
			bestCategory = entry.Category
		}
	}
	return bestCategory
}

// ClassifyEvent adds a "category" field to a copy of the event map.
// The original map is not modified.
func (c *SignalClassifier) ClassifyEvent(event map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(event)+1)
	for k, v := range event {
		out[k] = v
	}
	var signals []string
	if raw, ok := event["signals"]; ok {
		switch s := raw.(type) {
		case []string:
			signals = s
		case []interface{}:
			for _, item := range s {
				if str, ok := item.(string); ok {
					signals = append(signals, str)
				}
			}
		}
	}
	out["category"] = c.Classify(signals)
	return out
}

// ClassifyBatch returns a new slice of event maps with a "category" field added.
func (c *SignalClassifier) ClassifyBatch(events []map[string]interface{}) []map[string]interface{} {
	out := make([]map[string]interface{}, len(events))
	for i, e := range events {
		out[i] = c.ClassifyEvent(e)
	}
	return out
}

// AllCategories returns a sorted slice of distinct category names in the mapping.
func (c *SignalClassifier) AllCategories() []string {
	seen := make(map[string]struct{})
	for _, entry := range c.categories {
		seen[entry.Category] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for cat := range seen {
		result = append(result, cat)
	}
	sort.Strings(result)
	return result
}
