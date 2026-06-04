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

const testJA4 = "t13d1516h2_aabbccddeeff_aabbccddeeff"

// TestAllowlistAdd verifies that RunAllowlistAdd calls POST /api/v1/allowlist
// with the correct body fields.
func TestAllowlistAdd(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("failed to decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"al-01","entry":"` + testJA4 + `"}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := commands.RunAllowlistAdd(context.Background(), c, testJA4, "legitimate scanner", "2027-01-01T00:00:00Z", "CHG001")
	if err != nil {
		t.Fatalf("RunAllowlistAdd returned error: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q; want POST", gotMethod)
	}
	if gotPath != "/api/v1/allowlist" {
		t.Errorf("path = %q; want /api/v1/allowlist", gotPath)
	}
	if gotBody["entry"] != testJA4 {
		t.Errorf("body.entry = %v; want %q", gotBody["entry"], testJA4)
	}
	if gotBody["reason"] != "legitimate scanner" {
		t.Errorf("body.reason = %v; want 'legitimate scanner'", gotBody["reason"])
	}
}

// TestAllowlistRemove_LookupThenDelete verifies that RunAllowlistRemove calls
// GET /api/v1/allowlist to find the entry by JA4, then DELETE /api/v1/allowlist/{id}.
func TestAllowlistRemove_LookupThenDelete(t *testing.T) {
	var calls []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/allowlist":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id":"al-99","entry":"` + testJA4 + `","reason":"test"}]`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/allowlist/al-99":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"removed"}`))
		default:
			t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	if err := commands.RunAllowlistRemove(context.Background(), c, testJA4); err != nil {
		t.Fatalf("RunAllowlistRemove returned error: %v", err)
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
	if !strings.Contains(calls[1], "al-99") {
		t.Errorf("DELETE call should reference id al-99, got %q", calls[1])
	}
}

// TestAllowlistRemove_NotFound verifies that RunAllowlistRemove returns an error
// containing "no entry found" when the allowlist contains no matching JA4.
func TestAllowlistRemove_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	err := commands.RunAllowlistRemove(context.Background(), c, "t13d9999h2_000000000000_000000000000")
	if err == nil {
		t.Fatal("expected error for not-found JA4, got nil")
	}

	if !strings.Contains(strings.ToLower(err.Error()), "no entry found") {
		t.Errorf("error %q does not contain 'no entry found'", err.Error())
	}
}

// TestAllowlistList verifies that RunAllowlistList calls GET /api/v1/allowlist
// and returns a non-nil slice.
func TestAllowlistList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q; want GET", r.Method)
		}
		if r.URL.Path != "/api/v1/allowlist" {
			t.Errorf("path = %q; want /api/v1/allowlist", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"id":"al-01","entry":"` + testJA4 + `","reason":"test"}]`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	entries, err := commands.RunAllowlistList(context.Background(), c)
	if err != nil {
		t.Fatalf("RunAllowlistList returned error: %v", err)
	}

	if len(entries) == 0 {
		t.Error("expected at least one entry, got zero")
	}
}
