package commands_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/anomalyco/ja4proxy/internal/cli/client"
	"github.com/anomalyco/ja4proxy/internal/cli/commands"
)

// ── RunConfigReload ─────────────────────────────────────────────────────────

func TestRunConfigReload_SingleNode(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	err := commands.RunConfigReload(context.Background(), c, "node1")
	if err != nil {
		t.Fatalf("RunConfigReload error: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q; want POST", gotMethod)
	}
	if gotPath != "/api/v1/nodes/node1/reload" {
		t.Errorf("path = %q; want /api/v1/nodes/node1/reload", gotPath)
	}
}

func TestRunConfigReload_AllNodes(t *testing.T) {
	var reloadedNodes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/nodes" && r.Method == http.MethodGet {
			resp := map[string]interface{}{
				"nodes": []map[string]string{
					{"host": "proxy-1"},
					{"host": "proxy-2"},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		if r.Method == http.MethodPost {
			reloadedNodes = append(reloadedNodes, r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	err := commands.RunConfigReload(context.Background(), c, "")
	if err != nil {
		t.Fatalf("RunConfigReload error: %v", err)
	}
	if len(reloadedNodes) != 2 {
		t.Errorf("expected 2 reload calls, got %d", len(reloadedNodes))
	}
}

func TestRunConfigReload_EmptyNodesList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nodes":[]}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	err := commands.RunConfigReload(context.Background(), c, "")
	if err == nil {
		t.Fatal("expected error for empty nodes list")
	}
}

func TestRunConfigReload_FetchNodesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	err := commands.RunConfigReload(context.Background(), c, "")
	if err == nil {
		t.Fatal("expected error from node list fetch failure")
	}
}

func TestRunConfigReload_SingleNodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	err := commands.RunConfigReload(context.Background(), c, "bad-node")
	if err == nil {
		t.Fatal("expected error from reload failure")
	}
}

func TestRunConfigReload_SecondNodeReloadError(t *testing.T) {
	callNum := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callNum++
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/nodes" {
			resp := map[string]interface{}{
				"nodes": []map[string]string{
					{"host": "proxy-1"},
					{"host": "proxy-2"},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		// First reload OK, second fails
		if callNum > 2 {
			http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	err := commands.RunConfigReload(context.Background(), c, "")
	if err == nil {
		t.Fatal("expected error from second node reload failure")
	}
}

// ── RunIPRelease error path ─────────────────────────────────────────────────

func TestRunIPRelease_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	err := commands.RunIPRelease(context.Background(), c, "10.0.0.1")
	if err == nil {
		t.Fatal("expected error from release failure")
	}
}

// ── RunWatchlistAdd error path ──────────────────────────────────────────────

func TestRunWatchlistAdd_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	err := commands.RunWatchlistAdd(context.Background(), c, "10.0.0.1", 0, "test")
	if err == nil {
		t.Fatal("expected error from watchlist add failure")
	}
}

// ── RunWatchlistRemove error paths ──────────────────────────────────────────

func TestRunWatchlistRemove_FetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	err := commands.RunWatchlistRemove(context.Background(), c, "10.0.0.1")
	if err == nil {
		t.Fatal("expected error from watchlist fetch failure")
	}
}

func TestRunWatchlistRemove_DeleteError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			entries := []map[string]string{{"id": "w-1", "entry": "10.0.0.1"}}
			_ = json.NewEncoder(w).Encode(entries)
			return
		}
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	err := commands.RunWatchlistRemove(context.Background(), c, "10.0.0.1")
	if err == nil {
		t.Fatal("expected error from watchlist delete failure")
	}
}

// ── RunIPBan error path ─────────────────────────────────────────────────────

func TestRunIPBan_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := commands.RunIPBan(context.Background(), c, "10.0.0.1", 3600, "bad")
	if err == nil {
		t.Fatal("expected error from ban failure")
	}
}

// ── RunIPLookup connections error ───────────────────────────────────────────

func TestRunIPLookup_ConnectionsFetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := commands.RunIPLookup(context.Background(), c, "10.0.0.1")
	if err == nil {
		t.Fatal("expected error from connections fetch failure")
	}
}

// ── RunAllowlistAdd error path ──────────────────────────────────────────────

func TestRunAllowlistAdd_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := commands.RunAllowlistAdd(context.Background(), c, "t13abc", "reason", "", "")
	if err == nil {
		t.Fatal("expected error from allowlist add failure")
	}
}

// ── RunAllowlistRemove error paths ──────────────────────────────────────────

func TestRunAllowlistRemove_FetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	err := commands.RunAllowlistRemove(context.Background(), c, "t13abc")
	if err == nil {
		t.Fatal("expected error from allowlist fetch failure")
	}
}

func TestRunAllowlistRemove_DeleteError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			entries := []map[string]string{{"id": "a-1", "entry": "t13abc"}}
			_ = json.NewEncoder(w).Encode(entries)
			return
		}
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	err := commands.RunAllowlistRemove(context.Background(), c, "t13abc")
	if err == nil {
		t.Fatal("expected error from allowlist delete failure")
	}
}

// ── RunAllowlistList error path ─────────────────────────────────────────────

func TestRunAllowlistList_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := commands.RunAllowlistList(context.Background(), c)
	if err == nil {
		t.Fatal("expected error from allowlist list failure")
	}
}

// ── RunBlocklistAdd error path ──────────────────────────────────────────────

func TestRunBlocklistAdd_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := commands.RunBlocklistAdd(context.Background(), c, "t13abc", "reason", "")
	if err == nil {
		t.Fatal("expected error from blocklist add failure")
	}
}

// ── RunBlocklistRemove error paths ──────────────────────────────────────────

func TestRunBlocklistRemove_FetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	err := commands.RunBlocklistRemove(context.Background(), c, "t13abc")
	if err == nil {
		t.Fatal("expected error from blocklist fetch failure")
	}
}

func TestRunBlocklistRemove_DeleteError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			entries := []map[string]string{{"id": "b-1", "entry": "t13abc"}}
			_ = json.NewEncoder(w).Encode(entries)
			return
		}
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	err := commands.RunBlocklistRemove(context.Background(), c, "t13abc")
	if err == nil {
		t.Fatal("expected error from blocklist delete failure")
	}
}

// ── RunBlocklistList error path ─────────────────────────────────────────────

func TestRunBlocklistList_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := commands.RunBlocklistList(context.Background(), c)
	if err == nil {
		t.Fatal("expected error from blocklist list failure")
	}
}

// ── RunSignalCategories error path ──────────────────────────────────────────

func TestRunSignalCategories_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := commands.RunSignalCategories(context.Background(), c)
	if err == nil {
		t.Fatal("expected error from signal categories failure")
	}
}

// ── RunDSARErase error path ─────────────────────────────────────────────────

func TestRunDSARErase_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := commands.RunDSARErase(context.Background(), c, "10.0.0.1", "TICKET-1")
	if err == nil {
		t.Fatal("expected error from DSAR erase failure")
	}
}

// ── RunPCIDSSPack error paths ───────────────────────────────────────────────

func TestRunPCIDSSPack_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := commands.RunPCIDSSPack(context.Background(), c, "2026-01-01", "2026-04-01", "out.zip")
	if err == nil {
		t.Fatal("expected error from PCI-DSS pack API failure")
	}
}

func TestRunPCIDSSPack_JSONErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":"something went wrong"}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := commands.RunPCIDSSPack(context.Background(), c, "2026-01-01", "2026-04-01", "out.zip")
	if err == nil {
		t.Fatal("expected error for JSON error response")
	}
}

func TestRunPCIDSSPack_CreatesSubdirectory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write([]byte("PK\x03\x04fake"))
	}))
	defer srv.Close()

	outPath := filepath.Join(t.TempDir(), "sub", "dir", "pack.zip")
	c := client.New(srv.URL, "token")
	gotPath, err := commands.RunPCIDSSPack(context.Background(), c, "2026-01-01", "2026-04-01", outPath)
	if err != nil {
		t.Fatalf("RunPCIDSSPack error: %v", err)
	}
	if gotPath != outPath {
		t.Errorf("path = %q; want %q", gotPath, outPath)
	}
	if _, statErr := os.Stat(outPath); statErr != nil {
		t.Errorf("file not created: %v", statErr)
	}
}

// ── RunReportGenerate error path ────────────────────────────────────────────

func TestRunReportGenerate_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	var buf bytes.Buffer
	err := commands.RunReportGenerate(context.Background(), c, "2026-01-01", "2026-04-01", commands.ReportFormatHTML, &buf)
	if err == nil {
		t.Fatal("expected error from report generate failure")
	}
}

// ── RunConnectionsExport error and edge cases ───────────────────────────────

func TestRunConnectionsExport_GeneratesFilenameIfEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"connections":     []interface{}{},
			"count":           0,
			"has_more":        false,
			"next_page_token": nil,
			"total_in_window": 0,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	orig, _ := os.Getwd()
	tmp := t.TempDir()
	_ = os.Chdir(tmp)
	defer func() { _ = os.Chdir(orig) }()

	c := client.New(srv.URL, "token")
	result, err := commands.RunConnectionsExport(context.Background(), c, "2026-01-01", "2026-04-01", "")
	if err != nil {
		t.Fatalf("RunConnectionsExport error: %v", err)
	}
	if result.TotalEvents != 0 {
		t.Errorf("TotalEvents = %d; want 0", result.TotalEvents)
	}
	if result.OutputPath == "" {
		t.Error("expected generated output path, got empty")
	}
}

func TestRunConnectionsExport_Pagination(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		if callCount == 1 {
			token := "page2token"
			resp := map[string]interface{}{
				"connections": []map[string]string{
					{"ip": "10.0.0.1", "ja4": "t13abc", "risk_score": "50", "action_taken": "allowed", "timestamp": "2026-01-01T00:00:00Z"},
				},
				"count":           1,
				"has_more":        true,
				"next_page_token": token,
				"total_in_window": 2,
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		resp := map[string]interface{}{
			"connections": []map[string]string{
				{"ip": "10.0.0.2", "ja4": "t13def", "risk_score": "30", "action_taken": "allowed", "timestamp": "2026-01-01T00:01:00Z"},
			},
			"count":           1,
			"has_more":        false,
			"next_page_token": nil,
			"total_in_window": 2,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	outPath := filepath.Join(t.TempDir(), "export.jsonl")
	c := client.New(srv.URL, "token")
	result, err := commands.RunConnectionsExport(context.Background(), c, "2026-01-01", "2026-04-01", outPath)
	if err != nil {
		t.Fatalf("RunConnectionsExport error: %v", err)
	}
	if result.TotalEvents != 2 {
		t.Errorf("TotalEvents = %d; want 2", result.TotalEvents)
	}
	if callCount != 2 {
		t.Errorf("expected 2 API calls (pagination), got %d", callCount)
	}
}

func TestRunConnectionsExport_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	outPath := filepath.Join(t.TempDir(), "export.jsonl")
	c := client.New(srv.URL, "token")
	_, err := commands.RunConnectionsExport(context.Background(), c, "2026-01-01", "2026-04-01", outPath)
	if err == nil {
		t.Fatal("expected error from API failure")
	}
}

// ── RunHealth error paths ───────────────────────────────────────────────────

func TestRunHealth_DeepHealthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := commands.RunHealth(context.Background(), c, false)
	if err == nil {
		t.Fatal("expected error from deep health failure")
	}
}

func TestRunHealth_AllNodesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := commands.RunHealth(context.Background(), c, true)
	if err == nil {
		t.Fatal("expected error from nodes fetch failure")
	}
}

// ── ValidatePolicy toInt edge cases ─────────────────────────────────────────

func TestPolicyValidate_DialSettingFloat(t *testing.T) {
	// YAML may decode numeric values as float64
	policy := `meta:
  version: "1.0"
dial:
  setting: 50.0
`
	err := commands.RunPolicyValidate(policy, 0)
	// This should fail because 50.0→50 increase > 20 without shadow_mode_approved
	if err == nil {
		t.Fatal("expected error for dial increase > 20")
	}
}

func TestPolicyValidate_DialSettingString(t *testing.T) {
	policy := `meta:
  version: "1.0"
dial:
  setting: "fifty"
`
	err := commands.RunPolicyValidate(policy, 0)
	if err == nil {
		t.Fatal("expected error for non-numeric dial setting")
	}
}

func TestPolicyValidate_DialNotMapping(t *testing.T) {
	policy := `meta:
  version: "1.0"
dial: 50
`
	err := commands.RunPolicyValidate(policy, 0)
	if err == nil {
		t.Fatal("expected error for dial as scalar")
	}
}

func TestPolicyValidate_BypassTogglesNotMapping(t *testing.T) {
	policy := `meta:
  version: "1.0"
bypass_toggles: true
`
	err := commands.RunPolicyValidate(policy, 0)
	if err == nil {
		t.Fatal("expected error for bypass_toggles as scalar")
	}
}

// ── checkCIDRs edge case: empty CIDR string ────────────────────────────────

func TestPolicyValidate_EmptyCIDRField(t *testing.T) {
	policy := validMinimalPolicy + `
blocklist:
  ips:
    - cidr: ""
      reason: "empty cidr"
`
	// Empty CIDR should be silently skipped (not an error)
	err := commands.RunPolicyValidate(policy, 0)
	if err != nil {
		t.Errorf("empty CIDR should be skipped, got: %v", err)
	}
}

// ── checkExpiresInLists edge case: non-string expires ──────────────────────

func TestPolicyValidate_NonStringExpiresIgnored(t *testing.T) {
	policy := validMinimalPolicy + `
blocklist:
  fingerprints:
    - ja4: "t13d1516h2_aabbccddeeff_aabbccddeeff"
      expires: 12345
`
	// Numeric expires should be silently skipped (expiresStr will be "")
	err := commands.RunPolicyValidate(policy, 0)
	if err != nil {
		t.Errorf("non-string expires should be skipped, got: %v", err)
	}
}

// ── checkExpiresInLists: expires on blocklist ips ──────────────────────────

func TestPolicyValidate_BlocklistIPExpiredEntry(t *testing.T) {
	policy := validMinimalPolicy + `
blocklist:
  ips:
    - cidr: "10.0.0.0/24"
      expires: "2020-01-01T00:00:00Z"
`
	err := commands.RunPolicyValidate(policy, 0)
	if err == nil {
		t.Fatal("expected error for expired blocklist IP entry")
	}
}

// ── checkExpiresInLists: watchlist expires ──────────────────────────────────

func TestPolicyValidate_WatchlistExpiredEntry(t *testing.T) {
	policy := validMinimalPolicy + `
watchlist:
  ips:
    - ip: "10.0.0.5"
      expires: "2020-06-15T00:00:00Z"
`
	err := commands.RunPolicyValidate(policy, 0)
	if err == nil {
		t.Fatal("expected error for expired watchlist entry")
	}
}

// ── checkJA4s: blocklist ja4 validation ────────────────────────────────────

func TestPolicyValidate_BlocklistInvalidJA4(t *testing.T) {
	policy := validMinimalPolicy + `
blocklist:
  fingerprints:
    - ja4: "INVALID"
      reason: "test"
`
	err := commands.RunPolicyValidate(policy, 0)
	if err == nil {
		t.Fatal("expected error for invalid JA4 in blocklist")
	}
}

// ── checkDuplicateJA4s: blocklist duplicates ───────────────────────────────

func TestPolicyValidate_BlocklistDuplicateJA4(t *testing.T) {
	policy := validMinimalPolicy + `
blocklist:
  fingerprints:
    - ja4: "t13d1516h2_aabbccddeeff_aabbccddeeff"
      reason: "first"
    - ja4: "t13d1516h2_aabbccddeeff_aabbccddeeff"
      reason: "dup"
`
	err := commands.RunPolicyValidate(policy, 0)
	if err == nil {
		t.Fatal("expected error for duplicate JA4 in blocklist")
	}
}

// ── checkCIDRs: allowlist CIDRs ────────────────────────────────────────────

func TestPolicyValidate_AllowlistInvalidCIDR(t *testing.T) {
	policy := validMinimalPolicy + `
allowlist:
  ips:
    - cidr: "not-valid"
      reason: "test"
`
	err := commands.RunPolicyValidate(policy, 0)
	if err == nil {
		t.Fatal("expected error for invalid CIDR in allowlist")
	}
}

func TestPolicyValidate_WatchlistInvalidIP(t *testing.T) {
	policy := validMinimalPolicy + `
watchlist:
  ips:
    - ip: "definitely.not.an.ip"
      reason: "test"
`
	err := commands.RunPolicyValidate(policy, 0)
	if err == nil {
		t.Fatal("expected error for invalid IP in watchlist")
	}
}
