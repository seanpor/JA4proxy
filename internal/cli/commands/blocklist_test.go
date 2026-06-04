package commands_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/seanpor/ja4proxy/internal/cli/client"
	"github.com/seanpor/ja4proxy/internal/cli/commands"
)

const testBlocklistJA4 = "t13d1516h2_aabbccddeeff_aabbccddeeff"

// TestBlocklistAdd verifies that RunBlocklistAdd calls POST /api/v1/blocklist
// with the correct body fields.
func TestBlocklistAdd(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("failed to decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"bl-01","entry":"` + testBlocklistJA4 + `"}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := commands.RunBlocklistAdd(context.Background(), c, testBlocklistJA4, "known scanner fingerprint", "INC001")
	if err != nil {
		t.Fatalf("RunBlocklistAdd returned error: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q; want POST", gotMethod)
	}
	if gotPath != "/api/v1/blocklist" {
		t.Errorf("path = %q; want /api/v1/blocklist", gotPath)
	}
	if gotBody["entry"] != testBlocklistJA4 {
		t.Errorf("body.entry = %v; want %q", gotBody["entry"], testBlocklistJA4)
	}
	if gotBody["reason"] != "known scanner fingerprint" {
		t.Errorf("body.reason = %v; want 'known scanner fingerprint'", gotBody["reason"])
	}
}

// TestBlocklistRemove_LookupThenDelete verifies that RunBlocklistRemove calls
// GET /api/v1/blocklist to find the entry by JA4, then DELETE /api/v1/blocklist/{id}.
func TestBlocklistRemove_LookupThenDelete(t *testing.T) {
	var calls []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/blocklist":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id":"bl-77","entry":"` + testBlocklistJA4 + `","reason":"scanner"}]`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/blocklist/bl-77":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"removed"}`))
		default:
			t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	if err := commands.RunBlocklistRemove(context.Background(), c, testBlocklistJA4); err != nil {
		t.Fatalf("RunBlocklistRemove returned error: %v", err)
	}

	if len(calls) < 2 {
		t.Fatalf("expected at least 2 calls, got %d: %v", len(calls), calls)
	}
	if !strings.HasPrefix(calls[0], "GET") {
		t.Errorf("first call should be GET, got %q", calls[0])
	}
	if !strings.Contains(calls[1], "DELETE") {
		t.Errorf("second call should be DELETE, got %q", calls[1])
	}
	if !strings.Contains(calls[1], "bl-77") {
		t.Errorf("DELETE call should reference id bl-77, got %q", calls[1])
	}
}

// TestBlocklistRemove_NotFound verifies that RunBlocklistRemove returns an error
// containing "no entry found" when the blocklist contains no matching JA4.
func TestBlocklistRemove_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	err := commands.RunBlocklistRemove(context.Background(), c, "t13d9999h2_000000000000_000000000000")
	if err == nil {
		t.Fatal("expected error for not-found JA4, got nil")
	}

	if !strings.Contains(strings.ToLower(err.Error()), "no entry found") {
		t.Errorf("error %q does not contain 'no entry found'", err.Error())
	}
}

// TestBlocklistList verifies that RunBlocklistList calls GET /api/v1/blocklist
// and returns the list of entries.
func TestBlocklistList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q; want GET", r.Method)
		}
		if r.URL.Path != "/api/v1/blocklist" {
			t.Errorf("path = %q; want /api/v1/blocklist", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"id":"bl-01","entry":"` + testBlocklistJA4 + `","reason":"scanner"}]`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	entries, err := commands.RunBlocklistList(context.Background(), c)
	if err != nil {
		t.Fatalf("RunBlocklistList returned error: %v", err)
	}

	if len(entries) == 0 {
		t.Error("expected at least one entry, got zero")
	}
}
