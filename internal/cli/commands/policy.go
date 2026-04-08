package commands

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/anomalyco/ja4proxy/internal/cli/client"
)

// PolicySyntaxError is returned when the YAML cannot be parsed.
type PolicySyntaxError struct{ Msg string }

// PolicySchemaError is returned for structural violations (unknown fields,
// bad CIDR/JA4 formats, out-of-range dial settings).
type PolicySchemaError struct{ Msg string }

// PolicyTTLError is returned when an expires field is in the past.
type PolicyTTLError struct{ Msg string }

// PolicyDuplicateError is returned when duplicate JA4 fingerprints exist in
// the same list.
type PolicyDuplicateError struct{ Msg string }

// PolicyValidationError is returned when the dial increases by more than 20
// points without shadow_mode_approved: true.
type PolicyValidationError struct{ Msg string }

func (e *PolicySyntaxError) Error() string    { return e.Msg }
func (e *PolicySchemaError) Error() string    { return e.Msg }
func (e *PolicyTTLError) Error() string       { return e.Msg }
func (e *PolicyDuplicateError) Error() string { return e.Msg }
func (e *PolicyValidationError) Error() string { return e.Msg }

// ja4Pattern matches valid JA4 fingerprints: 10 lowercase alphanumeric chars,
// underscore, 12 hex chars, underscore, 12 hex chars.
var ja4Pattern = regexp.MustCompile(`^[a-z0-9]{10}_[a-f0-9]{12}_[a-f0-9]{12}$`)

// allowedTopLevelKeys is the set of permitted top-level keys in a policy YAML.
var allowedTopLevelKeys = map[string]bool{
	"meta":           true,
	"dial":           true,
	"allowlist":      true,
	"blocklist":      true,
	"watchlist":      true,
	"bypass_toggles": true,
}

// allowedBypassKeys is the set of permitted keys within bypass_toggles.
var allowedBypassKeys = map[string]bool{
	"alpn_browser_bypass":  true,
	"ja4_whitelist_bypass": true,
	"mtls_bypass":          true,
	"spamhaus_bypass":      true,
	"tls_version_bypass":   true,
}

// ValidatePolicy parses and validates a policy YAML document offline.
// currentDial is the current production dial setting used for increase validation.
// Returns the parsed policy map on success.
//
// Nine validation rules are applied in order:
//  1. YAML parse — PolicySyntaxError on failure.
//  2. Top-level keys — only meta/dial/allowlist/blocklist/watchlist/bypass_toggles
//     are allowed → PolicySchemaError.
//  3. bypass_toggles keys — only alpn_browser_bypass/ja4_whitelist_bypass/
//     mtls_bypass/spamhaus_bypass/tls_version_bypass are allowed → PolicySchemaError.
//  4. dial.setting must be 0–100 → PolicySchemaError.
//  5. expires fields must be future ISO 8601 timestamps → PolicyTTLError.
//  6. Dial increase > 20 without shadow_mode_approved: true → PolicyValidationError.
//  7. CIDR fields validated with net/netip.ParsePrefix → PolicySchemaError.
//  8. JA4 regex validation → PolicySchemaError.
//  9. No duplicate JA4 fingerprints in the same list → PolicyDuplicateError.
func ValidatePolicy(yamlText string, currentDial int) (map[string]interface{}, error) {
	// ── 1. YAML parse ────────────────────────────────────────────────────────
	var policy map[string]interface{}
	if err := yaml.Unmarshal([]byte(yamlText), &policy); err != nil {
		return nil, &PolicySyntaxError{Msg: fmt.Sprintf("YAML parse error: %v", err)}
	}
	if policy == nil {
		policy = map[string]interface{}{}
	}

	// ── 2. Top-level key validation ──────────────────────────────────────────
	for k := range policy {
		if !allowedTopLevelKeys[k] {
			return nil, &PolicySchemaError{
				Msg: fmt.Sprintf("unknown top-level key %q — allowed keys: meta, dial, allowlist, blocklist, watchlist, bypass_toggles", k),
			}
		}
	}

	// ── 3. bypass_toggles key validation ────────────────────────────────────
	if btRaw, ok := policy["bypass_toggles"]; ok && btRaw != nil {
		btMap, ok := btRaw.(map[string]interface{})
		if !ok {
			return nil, &PolicySchemaError{Msg: "bypass_toggles must be a mapping"}
		}
		for k := range btMap {
			if !allowedBypassKeys[k] {
				return nil, &PolicySchemaError{
					Msg: fmt.Sprintf("unknown bypass_toggles key %q — allowed keys: alpn_browser_bypass, ja4_whitelist_bypass, mtls_bypass, spamhaus_bypass, tls_version_bypass", k),
				}
			}
		}
	}

	// ── 4. dial.setting range ────────────────────────────────────────────────
	var newDialSetting *int
	if dialRaw, ok := policy["dial"]; ok && dialRaw != nil {
		dialMap, ok := dialRaw.(map[string]interface{})
		if !ok {
			return nil, &PolicySchemaError{Msg: "dial must be a mapping"}
		}
		if settingRaw, exists := dialMap["setting"]; exists {
			setting, ok := toInt(settingRaw)
			if !ok {
				return nil, &PolicySchemaError{
					Msg: fmt.Sprintf("dial.setting must be an integer 0–100, got %v", settingRaw),
				}
			}
			if setting < 0 || setting > 100 {
				return nil, &PolicySchemaError{
					Msg: fmt.Sprintf("dial.setting must be 0–100, got %d", setting),
				}
			}
			newDialSetting = &setting
		}
	}

	// ── 5 & 6. expires fields and dial increase check ───────────────────────
	if err := checkExpiresInLists(policy); err != nil {
		return nil, err
	}

	if newDialSetting != nil {
		increase := *newDialSetting - currentDial
		shadowApproved := false
		if dialMap, ok := policy["dial"].(map[string]interface{}); ok {
			if v, ok := dialMap["shadow_mode_approved"]; ok {
				shadowApproved, _ = v.(bool)
			}
		}
		if increase > 20 && !shadowApproved {
			return nil, &PolicyValidationError{
				Msg: fmt.Sprintf(
					"dial increase of %d points (from %d to %d) requires shadow_mode_approved: true in the dial section",
					increase, currentDial, *newDialSetting,
				),
			}
		}
	}

	// ── 7. CIDR validation ───────────────────────────────────────────────────
	if err := checkCIDRs(policy); err != nil {
		return nil, err
	}

	// ── 8. JA4 regex validation ──────────────────────────────────────────────
	if err := checkJA4s(policy); err != nil {
		return nil, err
	}

	// ── 9. Duplicate JA4 fingerprints ───────────────────────────────────────
	if err := checkDuplicateJA4s(policy); err != nil {
		return nil, err
	}

	return policy, nil
}

// ── helpers ────────────────────────────────────────────────────────────────────

// toInt converts a YAML-decoded numeric value to an int.
func toInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	}
	return 0, false
}

// checkExpiresInLists validates all expires fields in allowlist, blocklist,
// and watchlist sections.
func checkExpiresInLists(policy map[string]interface{}) error {
	for _, section := range []string{"allowlist", "blocklist", "watchlist"} {
		sRaw, ok := policy[section]
		if !ok || sRaw == nil {
			continue
		}
		sMap, ok := sRaw.(map[string]interface{})
		if !ok {
			continue
		}
		for _, listKey := range []string{"fingerprints", "ips"} {
			listRaw, ok := sMap[listKey]
			if !ok || listRaw == nil {
				continue
			}
			items, ok := listRaw.([]interface{})
			if !ok {
				continue
			}
			for _, itemRaw := range items {
				itemMap, ok := itemRaw.(map[string]interface{})
				if !ok {
					continue
				}
				if expiresRaw, ok := itemMap["expires"]; ok && expiresRaw != nil {
					expiresStr, _ := expiresRaw.(string)
					if expiresStr == "" {
						continue
					}
					dt, err := parseISO8601(expiresStr)
					if err != nil {
						return &PolicySchemaError{
							Msg: fmt.Sprintf("cannot parse expires %q in %s.%s: %v", expiresStr, section, listKey, err),
						}
					}
					if dt.Before(time.Now().UTC()) {
						return &PolicyTTLError{
							Msg: fmt.Sprintf("expires %q in %s.%s is in the past", expiresStr, section, listKey),
						}
					}
				}
			}
		}
	}
	return nil
}

// parseISO8601 parses an ISO 8601 timestamp string into a UTC time.Time.
func parseISO8601(s string) (time.Time, error) {
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02",
	}
	// Normalise trailing Z.
	normalized := s
	if len(s) > 0 && s[len(s)-1] == 'Z' {
		normalized = s[:len(s)-1] + "+00:00"
	}
	for _, format := range formats {
		if t, err := time.Parse(format, normalized); err == nil {
			return t.UTC(), nil
		}
	}
	// Last attempt with RFC3339.
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("unrecognised timestamp format: %q", s)
}

// checkCIDRs validates all CIDR fields in allowlist.ips, blocklist.ips, and
// watchlist.ips.
func checkCIDRs(policy map[string]interface{}) error {
	type cidrField struct {
		section  string
		listKey  string
		fieldKey string
	}
	fields := []cidrField{
		{"allowlist", "ips", "cidr"},
		{"blocklist", "ips", "cidr"},
		{"watchlist", "ips", "ip"},
	}
	for _, cf := range fields {
		sRaw, ok := policy[cf.section]
		if !ok || sRaw == nil {
			continue
		}
		sMap, ok := sRaw.(map[string]interface{})
		if !ok {
			continue
		}
		listRaw, ok := sMap[cf.listKey]
		if !ok || listRaw == nil {
			continue
		}
		items, ok := listRaw.([]interface{})
		if !ok {
			continue
		}
		for _, itemRaw := range items {
			itemMap, ok := itemRaw.(map[string]interface{})
			if !ok {
				continue
			}
			cidrRaw, ok := itemMap[cf.fieldKey]
			if !ok || cidrRaw == nil {
				continue
			}
			cidrStr, _ := cidrRaw.(string)
			if cidrStr == "" {
				continue
			}
			// Try as a prefix first, then as a plain address (add /32 or /128).
			_, err := netip.ParsePrefix(cidrStr)
			if err != nil {
				// Try as plain address.
				_, addrErr := netip.ParseAddr(cidrStr)
				if addrErr != nil {
					return &PolicySchemaError{
						Msg: fmt.Sprintf("invalid CIDR in %s.%s: %q — %v", cf.section, cf.listKey, cidrStr, err),
					}
				}
			}
		}
	}
	return nil
}

// checkJA4s validates all JA4 fingerprint fields against the expected regex.
func checkJA4s(policy map[string]interface{}) error {
	for _, section := range []string{"allowlist", "blocklist"} {
		sRaw, ok := policy[section]
		if !ok || sRaw == nil {
			continue
		}
		sMap, ok := sRaw.(map[string]interface{})
		if !ok {
			continue
		}
		fpsRaw, ok := sMap["fingerprints"]
		if !ok || fpsRaw == nil {
			continue
		}
		fps, ok := fpsRaw.([]interface{})
		if !ok {
			continue
		}
		for _, fpRaw := range fps {
			fpMap, ok := fpRaw.(map[string]interface{})
			if !ok {
				continue
			}
			ja4Raw, ok := fpMap["ja4"]
			if !ok || ja4Raw == nil {
				continue
			}
			ja4, _ := ja4Raw.(string)
			if !ja4Pattern.MatchString(ja4) {
				return &PolicySchemaError{
					Msg: fmt.Sprintf("invalid JA4 fingerprint in %s.fingerprints: %q — must match ^[a-z0-9]{10}_[a-f0-9]{12}_[a-f0-9]{12}$", section, ja4),
				}
			}
		}
	}
	return nil
}

// checkDuplicateJA4s detects duplicate JA4 fingerprints within the same list.
func checkDuplicateJA4s(policy map[string]interface{}) error {
	for _, section := range []string{"allowlist", "blocklist"} {
		sRaw, ok := policy[section]
		if !ok || sRaw == nil {
			continue
		}
		sMap, ok := sRaw.(map[string]interface{})
		if !ok {
			continue
		}
		fpsRaw, ok := sMap["fingerprints"]
		if !ok || fpsRaw == nil {
			continue
		}
		fps, ok := fpsRaw.([]interface{})
		if !ok {
			continue
		}
		seen := map[string]bool{}
		for _, fpRaw := range fps {
			fpMap, ok := fpRaw.(map[string]interface{})
			if !ok {
				continue
			}
			ja4Raw, ok := fpMap["ja4"]
			if !ok {
				continue
			}
			ja4, _ := ja4Raw.(string)
			if seen[ja4] {
				return &PolicyDuplicateError{
					Msg: fmt.Sprintf("duplicate JA4 fingerprint %q in %s.fingerprints", ja4, section),
				}
			}
			seen[ja4] = true
		}
	}
	return nil
}

// ── Public command functions ────────────────────────────────────────────────────

// RunPolicyValidate validates a policy YAML file offline and returns an error
// describing the first validation failure, or nil on success.
func RunPolicyValidate(yamlText string, currentDial int) error {
	_, err := ValidatePolicy(yamlText, currentDial)
	return err
}

// applyResult holds summary counts from a policy apply operation.
type applyResult struct {
	Added     int
	Removed   int
	Unchanged int
}

// RunPolicyApply applies a validated policy dict to the Management API using the
// same logic as scripts/ja4proxy-policy.py.  policyDict must be the output of
// ValidatePolicy.
func RunPolicyApply(ctx context.Context, c *client.Client, policyDict map[string]interface{}) error {
	result := &applyResult{}

	// Apply allowlist fingerprints.
	if err := applyFingerprints(ctx, c, policyDict, "allowlist", result); err != nil {
		return err
	}
	// Apply blocklist fingerprints.
	if err := applyFingerprints(ctx, c, policyDict, "blocklist", result); err != nil {
		return err
	}
	// Apply IPs.
	if err := applyIPs(ctx, c, policyDict, "allowlist", result); err != nil {
		return err
	}
	if err := applyIPs(ctx, c, policyDict, "blocklist", result); err != nil {
		return err
	}
	if err := applyWatchlistIPs(ctx, c, policyDict, result); err != nil {
		return err
	}

	// Apply dial if present.
	if dialRaw, ok := policyDict["dial"]; ok && dialRaw != nil {
		dialMap, ok := dialRaw.(map[string]interface{})
		if ok {
			if settingRaw, ok := dialMap["setting"]; ok {
				setting, ok := toInt(settingRaw)
				if ok {
					notes, _ := dialMap["notes"].(string)
					ticket, _ := dialMap["ticket"].(string)
					if err := RunDialSet(ctx, c, setting, ticket, notes); err != nil {
						return fmt.Errorf("applying dial setting: %w", err)
					}
				}
			}
		}
	}

	fmt.Printf("%d added, %d removed, %d unchanged\n", result.Added, result.Removed, result.Unchanged)
	return nil
}

// RunPolicyDiff compares a validated policy dict against the live API state and
// returns a list of drift entries (resources present in the API that are not
// managed by policy).  An empty slice means no drift.
func RunPolicyDiff(ctx context.Context, c *client.Client, policyDict map[string]interface{}) ([]interface{}, error) {
	var drift []interface{}

	// Check allowlist fingerprints.
	if d, err := diffFingerprints(ctx, c, policyDict, "allowlist"); err != nil {
		return nil, err
	} else {
		drift = append(drift, d...)
	}

	// Check blocklist fingerprints.
	if d, err := diffFingerprints(ctx, c, policyDict, "blocklist"); err != nil {
		return nil, err
	} else {
		drift = append(drift, d...)
	}

	return drift, nil
}

// ── apply helpers ──────────────────────────────────────────────────────────────

// applyFingerprints syncs fingerprints for the given section (allowlist/blocklist).
func applyFingerprints(ctx context.Context, c *client.Client, policy map[string]interface{}, section string, result *applyResult) error {
	entries := fingerprintsFromPolicy(policy, section)

	var liveItems []ListEntry
	if err := c.Get(ctx, "/api/v1/"+section, &liveItems); err != nil {
		return fmt.Errorf("fetching %s: %w", section, err)
	}

	liveByEntry := map[string]ListEntry{}
	for _, item := range liveItems {
		liveByEntry[item.Entry] = item
	}

	policyEntries := map[string]bool{}
	for _, entry := range entries {
		ja4, _ := entry["ja4"].(string)
		policyEntries[ja4] = true
		live, exists := liveByEntry[ja4]
		if exists && live.ManagedBy == "policy" {
			result.Unchanged++
			continue
		}
		payload := map[string]interface{}{
			"entry":      ja4,
			"managed_by": "policy",
		}
		if r, ok := entry["reason"].(string); ok {
			payload["reason"] = r
		}
		if t, ok := entry["ticket"].(string); ok {
			payload["ticket"] = t
		}
		var respBody map[string]interface{}
		if err := c.Post(ctx, "/api/v1/"+section, payload, &respBody); err != nil {
			return fmt.Errorf("adding %s to %s: %w", ja4, section, err)
		}
		if status, ok := respBody["status"].(string); ok && status == "pending_approval" {
			decisionID, _ := respBody["decision_id"].(string)
			return &PendingApprovalError{DecisionID: decisionID}
		}
		result.Added++
	}

	// Remove policy-managed entries not in policy.
	for entry, live := range liveByEntry {
		if live.ManagedBy == "policy" && !policyEntries[entry] {
			if err := c.Delete(ctx, "/api/v1/"+section+"/"+live.ID); err != nil {
				return fmt.Errorf("removing stale %s entry %s: %w", section, entry, err)
			}
			result.Removed++
		}
	}
	return nil
}

// applyIPs syncs IP/CIDR entries for allowlist or blocklist.
func applyIPs(ctx context.Context, c *client.Client, policy map[string]interface{}, section string, result *applyResult) error {
	entries := ipsFromPolicy(policy, section)

	var liveItems []ListEntry
	if err := c.Get(ctx, "/api/v1/"+section+"/ips", &liveItems); err != nil {
		// 404 means no ips endpoint — treat as empty.
		return nil
	}

	liveByEntry := map[string]ListEntry{}
	for _, item := range liveItems {
		liveByEntry[item.Entry] = item
	}

	policyEntries := map[string]bool{}
	for _, entry := range entries {
		cidr, _ := entry["cidr"].(string)
		if cidr == "" {
			cidr, _ = entry["ip"].(string)
		}
		policyEntries[cidr] = true
		live, exists := liveByEntry[cidr]
		if exists && live.ManagedBy == "policy" {
			result.Unchanged++
			continue
		}
		payload := map[string]interface{}{
			"entry":      cidr,
			"managed_by": "policy",
		}
		if r, ok := entry["reason"].(string); ok {
			payload["reason"] = r
		}
		var respBody map[string]interface{}
		if err := c.Post(ctx, "/api/v1/"+section+"/ips", payload, &respBody); err != nil {
			return fmt.Errorf("adding %s to %s/ips: %w", cidr, section, err)
		}
		result.Added++
	}

	for entry, live := range liveByEntry {
		if live.ManagedBy == "policy" && !policyEntries[entry] {
			if err := c.Delete(ctx, "/api/v1/"+section+"/ips/"+live.ID); err != nil {
				return fmt.Errorf("removing stale %s/ips entry %s: %w", section, entry, err)
			}
			result.Removed++
		}
	}
	return nil
}

// applyWatchlistIPs syncs watchlist IP entries.
func applyWatchlistIPs(ctx context.Context, c *client.Client, policy map[string]interface{}, result *applyResult) error {
	entries := ipsFromPolicySection(policy, "watchlist", "ip")
	if len(entries) == 0 {
		return nil
	}
	for _, entry := range entries {
		ip, _ := entry["ip"].(string)
		ttl := 0
		reason, _ := entry["reason"].(string)
		if err := RunWatchlistAdd(ctx, c, ip, ttl, reason); err != nil {
			return err
		}
		result.Added++
	}
	return nil
}

// diffFingerprints returns drift entries for the given section.
// Drift = live entries not managed by policy that are absent from the policy file.
func diffFingerprints(ctx context.Context, c *client.Client, policy map[string]interface{}, section string) ([]interface{}, error) {
	policyFPs := map[string]bool{}
	for _, entry := range fingerprintsFromPolicy(policy, section) {
		ja4, _ := entry["ja4"].(string)
		policyFPs[ja4] = true
	}

	var liveItems []ListEntry
	if err := c.Get(ctx, "/api/v1/"+section, &liveItems); err != nil {
		return nil, fmt.Errorf("fetching %s: %w", section, err)
	}

	var drift []interface{}
	for _, item := range liveItems {
		if item.ManagedBy != "policy" && !policyFPs[item.Entry] {
			drift = append(drift, map[string]interface{}{
				"resource_type": section + "_fingerprint",
				"identifier":    item.Entry,
				"managed_by":    item.ManagedBy,
			})
		}
	}
	return drift, nil
}

// ── data extraction helpers ────────────────────────────────────────────────────

// fingerprintsFromPolicy extracts the fingerprints list from a policy section.
func fingerprintsFromPolicy(policy map[string]interface{}, section string) []map[string]interface{} {
	sRaw, ok := policy[section]
	if !ok || sRaw == nil {
		return nil
	}
	sMap, ok := sRaw.(map[string]interface{})
	if !ok {
		return nil
	}
	fpsRaw, ok := sMap["fingerprints"]
	if !ok || fpsRaw == nil {
		return nil
	}
	fps, ok := fpsRaw.([]interface{})
	if !ok {
		return nil
	}
	result := make([]map[string]interface{}, 0, len(fps))
	for _, f := range fps {
		if m, ok := f.(map[string]interface{}); ok {
			result = append(result, m)
		}
	}
	return result
}

// ipsFromPolicy extracts IP/CIDR entries from section.ips.
func ipsFromPolicy(policy map[string]interface{}, section string) []map[string]interface{} {
	return ipsFromPolicySection(policy, section, "cidr")
}

// ipsFromPolicySection extracts IP entries from policy[section]["ips"].
func ipsFromPolicySection(policy map[string]interface{}, section, fieldKey string) []map[string]interface{} {
	sRaw, ok := policy[section]
	if !ok || sRaw == nil {
		return nil
	}
	sMap, ok := sRaw.(map[string]interface{})
	if !ok {
		return nil
	}
	listKey := "ips"
	ipsRaw, ok := sMap[listKey]
	if !ok || ipsRaw == nil {
		return nil
	}
	ips, ok := ipsRaw.([]interface{})
	if !ok {
		return nil
	}
	result := make([]map[string]interface{}, 0, len(ips))
	for _, ip := range ips {
		if m, ok := ip.(map[string]interface{}); ok {
			result = append(result, m)
		}
	}
	_ = fieldKey // consumed by callers
	return result
}
