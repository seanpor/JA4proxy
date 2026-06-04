package commands_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/seanpor/ja4proxy/internal/cli/client"
	"github.com/seanpor/ja4proxy/internal/cli/commands"
)

// ── applyFingerprints coverage ─────────────────────────────────────────────

func TestRunPolicyApply_AddsNewFingerprint(t *testing.T) {
	var posted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/allowlist") {
			// No existing entries
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/allowlist") {
			posted = true
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["managed_by"] != "policy" {
				t.Errorf("managed_by = %q; want policy", body["managed_by"])
			}
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	policy := map[string]interface{}{
		"allowlist": map[string]interface{}{
			"fingerprints": []interface{}{
				map[string]interface{}{
					"ja4":    "t13d1516h2_aabbccddeeff_aabbccddeeff",
					"reason": "test entry",
					"ticket": "CHG-100",
				},
			},
		},
	}
	err := commands.RunPolicyApply(context.Background(), c, policy)
	if err != nil {
		t.Fatalf("RunPolicyApply error: %v", err)
	}
	if !posted {
		t.Error("expected POST to add new fingerprint")
	}
}

func TestRunPolicyApply_SkipsUnchangedFingerprint(t *testing.T) {
	var postCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/allowlist") && !strings.Contains(r.URL.Path, "/ips") {
			entries := []map[string]interface{}{
				{
					"id":         "1",
					"entry":      "t13d1516h2_aabbccddeeff_aabbccddeeff",
					"managed_by": "policy",
				},
			}
			_ = json.NewEncoder(w).Encode(entries)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if r.Method == http.MethodPost {
			postCount++
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	policy := map[string]interface{}{
		"allowlist": map[string]interface{}{
			"fingerprints": []interface{}{
				map[string]interface{}{
					"ja4": "t13d1516h2_aabbccddeeff_aabbccddeeff",
				},
			},
		},
	}
	err := commands.RunPolicyApply(context.Background(), c, policy)
	if err != nil {
		t.Fatalf("RunPolicyApply error: %v", err)
	}
	if postCount != 0 {
		t.Errorf("expected 0 POSTs for unchanged fingerprint, got %d", postCount)
	}
}

func TestRunPolicyApply_RemovesStalePolicyManagedEntry(t *testing.T) {
	var deleted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blocklist") && !strings.Contains(r.URL.Path, "/ips") {
			entries := []map[string]interface{}{
				{
					"id":         "stale-1",
					"entry":      "t13d1516h2_112233445566_112233445566",
					"managed_by": "policy",
				},
			}
			_ = json.NewEncoder(w).Encode(entries)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if r.Method == http.MethodDelete {
			deleted = true
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	// Policy has no blocklist fingerprints — stale entry should be removed
	policy := map[string]interface{}{}
	err := commands.RunPolicyApply(context.Background(), c, policy)
	if err != nil {
		t.Fatalf("RunPolicyApply error: %v", err)
	}
	if !deleted {
		t.Error("expected DELETE for stale policy-managed entry")
	}
}

func TestRunPolicyApply_PendingApprovalFromFingerprint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/allowlist") {
			_, _ = w.Write([]byte(`{"status":"pending_approval","decision_id":"dec-999"}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	policy := map[string]interface{}{
		"allowlist": map[string]interface{}{
			"fingerprints": []interface{}{
				map[string]interface{}{
					"ja4": "t13d1516h2_aabbccddeeff_aabbccddeeff",
				},
			},
		},
	}
	err := commands.RunPolicyApply(context.Background(), c, policy)
	if err == nil {
		t.Fatal("expected PendingApprovalError, got nil")
	}
	var pending *commands.PendingApprovalError
	if !errors.As(err, &pending) {
		t.Fatalf("expected *PendingApprovalError, got %T: %v", err, err)
	}
	if pending.DecisionID != "dec-999" {
		t.Errorf("DecisionID = %q; want dec-999", pending.DecisionID)
	}
}

func TestRunPolicyApply_FetchAllowlistError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"server error"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	policy := map[string]interface{}{}
	err := commands.RunPolicyApply(context.Background(), c, policy)
	if err == nil {
		t.Fatal("expected error from failing allowlist fetch")
	}
}

// ── applyIPs coverage ──────────────────────────────────────────────────────

func TestRunPolicyApply_AddsNewIP(t *testing.T) {
	var ipPosted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/blocklist/ips") {
			ipPosted = true
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["entry"] != "10.0.0.0/24" {
				t.Errorf("entry = %q; want 10.0.0.0/24", body["entry"])
			}
			_, _ = w.Write([]byte(`{}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	policy := map[string]interface{}{
		"blocklist": map[string]interface{}{
			"ips": []interface{}{
				map[string]interface{}{
					"cidr":   "10.0.0.0/24",
					"reason": "test block",
				},
			},
		},
	}
	err := commands.RunPolicyApply(context.Background(), c, policy)
	if err != nil {
		t.Fatalf("RunPolicyApply error: %v", err)
	}
	if !ipPosted {
		t.Error("expected POST to add new IP")
	}
}

func TestRunPolicyApply_SkipsUnchangedIP(t *testing.T) {
	var postCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/allowlist/ips") {
			entries := []map[string]interface{}{
				{"id": "ip-1", "entry": "192.168.1.0/24", "managed_by": "policy"},
			}
			_ = json.NewEncoder(w).Encode(entries)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if r.Method == http.MethodPost {
			postCount++
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	policy := map[string]interface{}{
		"allowlist": map[string]interface{}{
			"ips": []interface{}{
				map[string]interface{}{"cidr": "192.168.1.0/24"},
			},
		},
	}
	err := commands.RunPolicyApply(context.Background(), c, policy)
	if err != nil {
		t.Fatalf("RunPolicyApply error: %v", err)
	}
	if postCount != 0 {
		t.Errorf("expected 0 POSTs for unchanged IP, got %d", postCount)
	}
}

func TestRunPolicyApply_RemovesStaleIP(t *testing.T) {
	var deleted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blocklist/ips") {
			entries := []map[string]interface{}{
				{"id": "stale-ip-1", "entry": "172.16.0.0/12", "managed_by": "policy"},
			}
			_ = json.NewEncoder(w).Encode(entries)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/blocklist/ips/stale-ip-1") {
			deleted = true
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	policy := map[string]interface{}{}
	err := commands.RunPolicyApply(context.Background(), c, policy)
	if err != nil {
		t.Fatalf("RunPolicyApply error: %v", err)
	}
	if !deleted {
		t.Error("expected DELETE for stale policy-managed IP")
	}
}

// ── applyWatchlistIPs coverage ─────────────────────────────────────────────

func TestRunPolicyApply_AddsWatchlistIPs(t *testing.T) {
	var watchlistAdded int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/watchlist") {
			watchlistAdded++
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	policy := map[string]interface{}{
		"watchlist": map[string]interface{}{
			"ips": []interface{}{
				map[string]interface{}{"ip": "10.0.0.5", "reason": "suspicious"},
				map[string]interface{}{"ip": "10.0.0.6", "reason": "flagged"},
			},
		},
	}
	err := commands.RunPolicyApply(context.Background(), c, policy)
	if err != nil {
		t.Fatalf("RunPolicyApply error: %v", err)
	}
	if watchlistAdded != 2 {
		t.Errorf("expected 2 watchlist adds, got %d", watchlistAdded)
	}
}

// ── RunPolicyDiff error paths ──────────────────────────────────────────────

func TestRunPolicyDiff_AllowlistFetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := commands.RunPolicyDiff(context.Background(), c, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error from failing allowlist fetch")
	}
}

func TestRunPolicyDiff_PolicyManagedNotDrift(t *testing.T) {
	// Entries managed by "policy" that ARE in policy should not be drift;
	// entries managed by "policy" that are NOT in policy are also not drift
	// (diff only reports non-policy-managed entries)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		entries := []map[string]interface{}{
			{
				"id":         "1",
				"entry":      "t13d1516h2_aabbccddeeff_aabbccddeeff",
				"managed_by": "policy",
			},
		}
		_ = json.NewEncoder(w).Encode(entries)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	drift, err := commands.RunPolicyDiff(context.Background(), c, map[string]interface{}{})
	if err != nil {
		t.Fatalf("RunPolicyDiff error: %v", err)
	}
	if len(drift) != 0 {
		t.Errorf("policy-managed entries should not be drift, got %d", len(drift))
	}
}

// ── fingerprintsFromPolicy / ipsFromPolicySection edge cases ───────────────

func TestRunPolicyApply_NonMapSectionIgnored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	// allowlist is a string instead of a map — should be handled gracefully
	policy := map[string]interface{}{
		"allowlist": "not-a-map",
	}
	err := commands.RunPolicyApply(context.Background(), c, policy)
	if err != nil {
		t.Fatalf("RunPolicyApply should handle non-map section: %v", err)
	}
}

func TestRunPolicyApply_NonSliceFingerprintsIgnored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	// fingerprints is a string instead of a slice — should be handled gracefully
	policy := map[string]interface{}{
		"allowlist": map[string]interface{}{
			"fingerprints": "not-a-slice",
		},
	}
	err := commands.RunPolicyApply(context.Background(), c, policy)
	if err != nil {
		t.Fatalf("RunPolicyApply should handle non-slice fingerprints: %v", err)
	}
}

func TestRunPolicyApply_NonMapFingerprintItemIgnored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	// fingerprints contains a string item instead of a map
	policy := map[string]interface{}{
		"allowlist": map[string]interface{}{
			"fingerprints": []interface{}{"not-a-map"},
		},
	}
	err := commands.RunPolicyApply(context.Background(), c, policy)
	if err != nil {
		t.Fatalf("RunPolicyApply should handle non-map items: %v", err)
	}
}

// ── applyIPs with "ip" key (watchlist uses "ip" not "cidr") ────────────────

func TestRunPolicyApply_IPKeyFallback(t *testing.T) {
	var postedEntry string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/allowlist/ips") {
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			postedEntry, _ = body["entry"].(string)
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	// Use "ip" key instead of "cidr" — applyIPs should fall back to "ip" key
	policy := map[string]interface{}{
		"allowlist": map[string]interface{}{
			"ips": []interface{}{
				map[string]interface{}{"ip": "10.0.0.1", "reason": "test"},
			},
		},
	}
	err := commands.RunPolicyApply(context.Background(), c, policy)
	if err != nil {
		t.Fatalf("RunPolicyApply error: %v", err)
	}
	if postedEntry != "10.0.0.1" {
		t.Errorf("expected entry=10.0.0.1, got %q", postedEntry)
	}
}

// ── applyFingerprints POST error ───────────────────────────────────────────

func TestRunPolicyApply_PostFingerprintError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	policy := map[string]interface{}{
		"allowlist": map[string]interface{}{
			"fingerprints": []interface{}{
				map[string]interface{}{"ja4": "t13d1516h2_aabbccddeeff_aabbccddeeff"},
			},
		},
	}
	err := commands.RunPolicyApply(context.Background(), c, policy)
	if err == nil {
		t.Fatal("expected error from POST failure")
	}
}

// ── applyFingerprints DELETE error ─────────────────────────────────────────

func TestRunPolicyApply_DeleteFingerprintError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/allowlist") && !strings.Contains(r.URL.Path, "/ips") {
			entries := []map[string]interface{}{
				{"id": "del-1", "entry": "t13d1516h2_112233445566_112233445566", "managed_by": "policy"},
			}
			_ = json.NewEncoder(w).Encode(entries)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if r.Method == http.MethodDelete {
			http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	// Empty allowlist fingerprints means the live entry should be removed
	policy := map[string]interface{}{
		"allowlist": map[string]interface{}{
			"fingerprints": []interface{}{},
		},
	}
	err := commands.RunPolicyApply(context.Background(), c, policy)
	if err == nil {
		t.Fatal("expected error from DELETE failure")
	}
}

// ── applyIPs POST error ────────────────────────────────────────────────────

func TestRunPolicyApply_PostIPError(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/ips") {
			callCount++
			http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	policy := map[string]interface{}{
		"allowlist": map[string]interface{}{
			"ips": []interface{}{
				map[string]interface{}{"cidr": "10.0.0.0/24"},
			},
		},
	}
	err := commands.RunPolicyApply(context.Background(), c, policy)
	if err == nil {
		t.Fatal("expected error from POST IP failure")
	}
}

// ── applyIPs DELETE error ──────────────────────────────────────────────────

func TestRunPolicyApply_DeleteIPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/allowlist/ips") {
			entries := []map[string]interface{}{
				{"id": "del-ip-1", "entry": "172.16.0.0/12", "managed_by": "policy"},
			}
			_ = json.NewEncoder(w).Encode(entries)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if r.Method == http.MethodDelete {
			http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	policy := map[string]interface{}{
		"allowlist": map[string]interface{}{
			"ips": []interface{}{},
		},
	}
	err := commands.RunPolicyApply(context.Background(), c, policy)
	if err == nil {
		t.Fatal("expected error from DELETE IP failure")
	}
}

// ── Dial apply error ───────────────────────────────────────────────────────

func TestRunPolicyApply_DialSetError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if r.Method == http.MethodPatch {
			http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	policy := map[string]interface{}{
		"dial": map[string]interface{}{
			"setting": 50,
		},
	}
	err := commands.RunPolicyApply(context.Background(), c, policy)
	if err == nil {
		t.Fatal("expected error from dial set failure")
	}
}

// ── Blocklist fingerprints and IPs via apply ───────────────────────────────

func TestRunPolicyApply_BlocklistFingerprints(t *testing.T) {
	var blocklistPosted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/blocklist") && !strings.Contains(r.URL.Path, "/ips") {
			blocklistPosted = true
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	policy := map[string]interface{}{
		"blocklist": map[string]interface{}{
			"fingerprints": []interface{}{
				map[string]interface{}{"ja4": "t13d1516h2_112233445566_112233445566"},
			},
		},
	}
	err := commands.RunPolicyApply(context.Background(), c, policy)
	if err != nil {
		t.Fatalf("RunPolicyApply error: %v", err)
	}
	if !blocklistPosted {
		t.Error("expected POST to blocklist")
	}
}

func TestRunPolicyApply_BlocklistIPs(t *testing.T) {
	var blocklistIPPosted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/blocklist/ips") {
			blocklistIPPosted = true
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	policy := map[string]interface{}{
		"blocklist": map[string]interface{}{
			"ips": []interface{}{
				map[string]interface{}{"cidr": "192.168.0.0/16", "reason": "internal"},
			},
		},
	}
	err := commands.RunPolicyApply(context.Background(), c, policy)
	if err != nil {
		t.Fatalf("RunPolicyApply error: %v", err)
	}
	if !blocklistIPPosted {
		t.Error("expected POST to blocklist/ips")
	}
}

// ── applyWatchlistIPs error ────────────────────────────────────────────────

func TestRunPolicyApply_WatchlistAddError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/watchlist") {
			http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	policy := map[string]interface{}{
		"watchlist": map[string]interface{}{
			"ips": []interface{}{
				map[string]interface{}{"ip": "10.0.0.5", "reason": "bad"},
			},
		},
	}
	err := commands.RunPolicyApply(context.Background(), c, policy)
	if err == nil {
		t.Fatal("expected error from watchlist add failure")
	}
}

// ── ipsFromPolicySection edge cases ────────────────────────────────────────

func TestRunPolicyApply_NonMapIPItemIgnored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	policy := map[string]interface{}{
		"allowlist": map[string]interface{}{
			"ips": []interface{}{"not-a-map"},
		},
	}
	err := commands.RunPolicyApply(context.Background(), c, policy)
	if err != nil {
		t.Fatalf("should handle non-map IP items: %v", err)
	}
}

func TestRunPolicyApply_NonSliceIPsIgnored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	policy := map[string]interface{}{
		"watchlist": map[string]interface{}{
			"ips": "not-a-slice",
		},
	}
	err := commands.RunPolicyApply(context.Background(), c, policy)
	if err != nil {
		t.Fatalf("should handle non-slice ips: %v", err)
	}
}

// ── diffFingerprints with policy fingerprints ──────────────────────────────

func TestRunPolicyDiff_PolicyFingerprintMatchNoDrift(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		entries := []map[string]interface{}{
			{
				"id":         "1",
				"entry":      "t13d1516h2_aabbccddeeff_aabbccddeeff",
				"managed_by": "manual",
			},
		}
		_ = json.NewEncoder(w).Encode(entries)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	policy := map[string]interface{}{
		"allowlist": map[string]interface{}{
			"fingerprints": []interface{}{
				map[string]interface{}{"ja4": "t13d1516h2_aabbccddeeff_aabbccddeeff"},
			},
		},
		"blocklist": map[string]interface{}{
			"fingerprints": []interface{}{
				map[string]interface{}{"ja4": "t13d1516h2_aabbccddeeff_aabbccddeeff"},
			},
		},
	}
	drift, err := commands.RunPolicyDiff(context.Background(), c, policy)
	if err != nil {
		t.Fatalf("RunPolicyDiff error: %v", err)
	}
	if len(drift) != 0 {
		t.Errorf("entries in policy should not be drift, got %d", len(drift))
	}
}

func TestRunPolicyDiff_BlocklistFetchError(t *testing.T) {
	callNum := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callNum++
		w.Header().Set("Content-Type", "application/json")
		if callNum == 1 {
			// Allowlist returns OK
			_, _ = w.Write([]byte(`[]`))
			return
		}
		// Blocklist fails
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := commands.RunPolicyDiff(context.Background(), c, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error from blocklist fetch failure")
	}
}
