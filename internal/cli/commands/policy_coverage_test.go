package commands_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anomalyco/ja4proxy/internal/cli/client"
	"github.com/anomalyco/ja4proxy/internal/cli/commands"
)

// ── parseISO8601 tests (via ValidatePolicy — the parser is exercised by
// expires validation) ─────────────────────────────────────────────────────────

func TestPolicyValidate_FutureExpires_Accepted(t *testing.T) {
	policy := validMinimalPolicy + `
allowlist:
  fingerprints:
    - ja4: "t13d1516h2_aabbccddeeff_aabbccddeeff"
      reason: "test"
      expires: "2099-12-31T23:59:59Z"
`
	err := commands.RunPolicyValidate(policy, 0)
	if err != nil {
		t.Errorf("expected nil for future expires, got: %v", err)
	}
}

func TestPolicyValidate_DateOnlyExpires_Accepted(t *testing.T) {
	policy := validMinimalPolicy + `
allowlist:
  fingerprints:
    - ja4: "t13d1516h2_aabbccddeeff_aabbccddeeff"
      reason: "test"
      expires: "2099-12-31"
`
	err := commands.RunPolicyValidate(policy, 0)
	if err != nil {
		t.Errorf("expected nil for date-only expires, got: %v", err)
	}
}

func TestPolicyValidate_BadExpiresFormat_SchemaError(t *testing.T) {
	policy := validMinimalPolicy + `
allowlist:
  fingerprints:
    - ja4: "t13d1516h2_aabbccddeeff_aabbccddeeff"
      reason: "test"
      expires: "not-a-date"
`
	err := commands.RunPolicyValidate(policy, 0)
	if err == nil {
		t.Fatal("expected error for bad expires format")
	}
	var schemaErr *commands.PolicySchemaError
	if !errors.As(err, &schemaErr) {
		t.Errorf("expected PolicySchemaError, got %T: %v", err, err)
	}
}

// ── ipsFromPolicy tests (via ValidatePolicy) ────────────────────────────────

func TestPolicyValidate_ValidIPAddress(t *testing.T) {
	policy := validMinimalPolicy + `
blocklist:
  ips:
    - cidr: "192.168.1.0/24"
      reason: "test"
`
	err := commands.RunPolicyValidate(policy, 0)
	if err != nil {
		t.Errorf("expected nil for valid CIDR, got: %v", err)
	}
}

func TestPolicyValidate_PlainIPAddress(t *testing.T) {
	// Plain IP (no /prefix) should also be accepted
	policy := validMinimalPolicy + `
blocklist:
  ips:
    - cidr: "10.0.0.1"
      reason: "test"
`
	err := commands.RunPolicyValidate(policy, 0)
	if err != nil {
		t.Errorf("expected nil for plain IP, got: %v", err)
	}
}

func TestPolicyValidate_IPv6CIDR(t *testing.T) {
	policy := validMinimalPolicy + `
blocklist:
  ips:
    - cidr: "2001:db8::/32"
      reason: "test"
`
	err := commands.RunPolicyValidate(policy, 0)
	if err != nil {
		t.Errorf("expected nil for IPv6 CIDR, got: %v", err)
	}
}

func TestPolicyValidate_WatchlistIP(t *testing.T) {
	policy := validMinimalPolicy + `
watchlist:
  ips:
    - ip: "10.0.0.5"
      reason: "suspicious"
`
	err := commands.RunPolicyValidate(policy, 0)
	if err != nil {
		t.Errorf("expected nil for watchlist IP, got: %v", err)
	}
}

// ── dial edge cases ──────────────────────────────────────────────────────────

func TestPolicyValidate_DialZero(t *testing.T) {
	policy := `meta:
  version: "1.0"
dial:
  setting: 0
`
	err := commands.RunPolicyValidate(policy, 0)
	if err != nil {
		t.Errorf("expected nil for dial=0, got: %v", err)
	}
}

func TestPolicyValidate_DialExactly100(t *testing.T) {
	policy := `meta:
  version: "1.0"
dial:
  setting: 100
  shadow_mode_approved: true
`
	err := commands.RunPolicyValidate(policy, 0)
	if err != nil {
		t.Errorf("expected nil for dial=100 with approval, got: %v", err)
	}
}

func TestPolicyValidate_DialNegative(t *testing.T) {
	policy := `meta:
  version: "1.0"
dial:
  setting: -1
`
	err := commands.RunPolicyValidate(policy, 0)
	if err == nil {
		t.Fatal("expected error for dial=-1")
	}
}

func TestPolicyValidate_EmptyDocument(t *testing.T) {
	err := commands.RunPolicyValidate("", 0)
	if err != nil {
		t.Errorf("empty YAML should be valid (empty policy), got: %v", err)
	}
}

// ── simulation commands ─────────────────────────────────────────────────────

func TestRunSimulationRun_ReturnsNotAvailable(t *testing.T) {
	err := commands.RunSimulationRun()
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, commands.ErrSimulationNotAvailable) {
		t.Errorf("expected ErrSimulationNotAvailable, got: %v", err)
	}
}

func TestRunSimulationStatus_ReturnsNotAvailable(t *testing.T) {
	err := commands.RunSimulationStatus()
	if !errors.Is(err, commands.ErrSimulationNotAvailable) {
		t.Errorf("expected ErrSimulationNotAvailable, got: %v", err)
	}
}

func TestRunSimulationReport_ReturnsNotAvailable(t *testing.T) {
	err := commands.RunSimulationReport()
	if !errors.Is(err, commands.ErrSimulationNotAvailable) {
		t.Errorf("expected ErrSimulationNotAvailable, got: %v", err)
	}
}

// ── RunPolicyApply ─────────────────────────────────────────────────────────

func TestRunPolicyApply_EmptyPolicy(t *testing.T) {
	// Empty policy — no fingerprints or IPs to sync, no dial to set
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		// Return empty lists for GET requests
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	policyDict := map[string]interface{}{
		"meta": map[string]interface{}{"version": "1.0"},
	}
	err := commands.RunPolicyApply(context.Background(), c, policyDict)
	if err != nil {
		t.Fatalf("RunPolicyApply error: %v", err)
	}
}

func TestRunPolicyApply_WithDial(t *testing.T) {
	var dialSet bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if strings.Contains(r.URL.Path, "dial") {
			dialSet = true
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	policyDict := map[string]interface{}{
		"dial": map[string]interface{}{
			"setting": 10,
			"notes":   "test",
			"ticket":  "TICKET-1",
		},
	}
	err := commands.RunPolicyApply(context.Background(), c, policyDict)
	if err != nil {
		t.Fatalf("RunPolicyApply error: %v", err)
	}
	if !dialSet {
		t.Error("expected dial to be set via API")
	}
}

// ── RunPolicyDiff ──────────────────────────────────────────────────────────

func TestRunPolicyDiff_NoDrift(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	policyDict := map[string]interface{}{}
	drift, err := commands.RunPolicyDiff(context.Background(), c, policyDict)
	if err != nil {
		t.Fatalf("RunPolicyDiff error: %v", err)
	}
	if len(drift) != 0 {
		t.Errorf("expected no drift, got %d entries", len(drift))
	}
}

func TestRunPolicyDiff_DetectsDrift(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Return a live entry that's not in the policy
		entries := []map[string]interface{}{
			{
				"id":         "1",
				"entry":      "t13d1516h2_aabbccddeeff_112233445566",
				"managed_by": "manual",
			},
		}
		_ = json.NewEncoder(w).Encode(entries)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	policyDict := map[string]interface{}{} // no fingerprints in policy
	drift, err := commands.RunPolicyDiff(context.Background(), c, policyDict)
	if err != nil {
		t.Fatalf("RunPolicyDiff error: %v", err)
	}
	if len(drift) == 0 {
		t.Error("expected drift to be detected")
	}
}

// ── RunDSARErase ────────────────────────────────────────────────────────────

func TestRunDSARErase_CallsDelete(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path + "?" + r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	result, err := commands.RunDSARErase(context.Background(), c, "10.0.0.1", "TICKET-123")
	if err != nil {
		t.Fatalf("RunDSARErase error: %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", gotMethod)
	}
	if !strings.Contains(gotPath, "10.0.0.1") {
		t.Errorf("path should contain IP: %s", gotPath)
	}
	if !strings.Contains(gotPath, "ticket=TICKET-123") {
		t.Errorf("path should contain ticket param: %s", gotPath)
	}
	if result.IP != "10.0.0.1" {
		t.Errorf("result.IP = %q; want 10.0.0.1", result.IP)
	}
	if result.AuditRef != "TICKET-123" {
		t.Errorf("result.AuditRef = %q; want TICKET-123", result.AuditRef)
	}
}

func TestRunDSARErase_EmptyTicket(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.String()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := commands.RunDSARErase(context.Background(), c, "10.0.0.1", "")
	if err != nil {
		t.Fatalf("RunDSARErase error: %v", err)
	}
	if strings.Contains(gotPath, "ticket=") {
		t.Errorf("path should not contain ticket param when empty: %s", gotPath)
	}
}

// ── Error type tests ─────────────────────────────────────────────────────────

func TestPolicyErrorTypes_ImplementError(t *testing.T) {
	errs := []error{
		&commands.PolicySyntaxError{Msg: "syntax"},
		&commands.PolicySchemaError{Msg: "schema"},
		&commands.PolicyTTLError{Msg: "ttl"},
		&commands.PolicyDuplicateError{Msg: "dup"},
		&commands.PolicyValidationError{Msg: "val"},
	}
	for _, e := range errs {
		if e.Error() == "" {
			t.Errorf("error type %T returned empty message", e)
		}
	}
}
