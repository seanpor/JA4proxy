package commands_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/seanpor/ja4proxy/internal/cli/client"
	"github.com/seanpor/ja4proxy/internal/cli/commands"
)

const fingerprintJA4 = "t13d1516h2_aabbccddeeff_aabbccddeeff"

// TestFingerprintHistory verifies that RunFingerprintHistory calls
// GET /api/v1/fingerprints/{ja4}/history and returns the result.
func TestFingerprintHistory(t *testing.T) {
	var gotPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.Method != http.MethodGet {
			t.Errorf("method = %q; want GET", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		// Return a JSON array (matching the []interface{} return type).
		_, _ = w.Write([]byte(`[{"timestamp":"2026-04-01T00:00:00Z","ip":"1.2.3.4","action":"allow"},{"timestamp":"2026-04-02T00:00:00Z","ip":"5.6.7.8","action":"block"}]`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	result, err := commands.RunFingerprintHistory(context.Background(), c, fingerprintJA4, "30d")
	if err != nil {
		t.Fatalf("RunFingerprintHistory returned error: %v", err)
	}

	expectedPath := "/api/v1/fingerprints/" + fingerprintJA4 + "/history"
	if gotPath != expectedPath {
		t.Errorf("path = %q; want %q", gotPath, expectedPath)
	}

	if len(result) == 0 {
		t.Fatal("expected non-empty result")
	}
}

// TestFingerprintHistory_NotFound verifies that a 404 from the API returns an error.
func TestFingerprintHistory_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":"fingerprint not found"}`, http.StatusNotFound)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := commands.RunFingerprintHistory(context.Background(), c, "t13d9999h2_000000000000_000000000000", "7d")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
}

// TestFingerprintHistory_WindowParam verifies that the window parameter is
// forwarded to the API as a query parameter.
func TestFingerprintHistory_WindowParam(t *testing.T) {
	var gotURL string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.String()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := commands.RunFingerprintHistory(context.Background(), c, fingerprintJA4, "7d")
	if err != nil {
		t.Fatalf("RunFingerprintHistory returned error: %v", err)
	}

	// The window should be present as a query parameter (e.g. ?since=7d).
	if !strings.Contains(gotURL, "7d") {
		t.Errorf("URL %q does not contain window '7d'", gotURL)
	}
}
