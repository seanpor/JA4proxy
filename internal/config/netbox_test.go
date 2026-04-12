package config

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestLoadTrustedCIDRsFromNetBox_OK verifies that a 200 response with two
// prefixes returns both prefixes in the result slice.
func TestLoadTrustedCIDRsFromNetBox_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Token test-token-123" {
			t.Errorf("Authorization header: got %q, want %q", got, "Token test-token-123")
		}
		if got := r.URL.Query().Get("tag"); got != "ja4proxy-trusted" {
			t.Errorf("tag query param: got %q, want %q", got, "ja4proxy-trusted")
		}
		resp := map[string]interface{}{
			"count": 2,
			"results": []map[string]interface{}{
				{"prefix": "10.0.0.0/8", "tag": []map[string]string{{"name": "ja4proxy-trusted"}}},
				{"prefix": "172.16.0.0/12", "tag": []map[string]string{{"name": "ja4proxy-trusted"}}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatal(err)
		}
	}))
	defer srv.Close()

	cidrs, err := LoadTrustedCIDRsFromNetBox(context.Background(), srv.URL, "test-token-123", "ja4proxy-trusted")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cidrs) != 2 {
		t.Fatalf("len(cidrs) = %d, want 2", len(cidrs))
	}
	if cidrs[0] != "10.0.0.0/8" {
		t.Errorf("cidrs[0] = %q, want %q", cidrs[0], "10.0.0.0/8")
	}
	if cidrs[1] != "172.16.0.0/12" {
		t.Errorf("cidrs[1] = %q, want %q", cidrs[1], "172.16.0.0/12")
	}
}

// TestLoadTrustedCIDRsFromNetBox_ServerError verifies that a 500 response
// returns an empty slice and no error (fail-open).
func TestLoadTrustedCIDRsFromNetBox_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	cidrs, err := LoadTrustedCIDRsFromNetBox(context.Background(), srv.URL, "token", "tag")
	if err != nil {
		t.Fatalf("expected nil error (fail-open), got: %v", err)
	}
	if len(cidrs) != 0 {
		t.Errorf("expected empty slice on 500, got %v", cidrs)
	}
}

// TestLoadTrustedCIDRsFromNetBox_Timeout verifies that a server that never
// responds within the timeout returns an empty slice and no error (fail-open).
func TestLoadTrustedCIDRsFromNetBox_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second) // longer than the 5s timeout
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	cidrs, err := LoadTrustedCIDRsFromNetBox(ctx, srv.URL, "token", "tag")
	if err != nil {
		t.Fatalf("expected nil error (fail-open), got: %v", err)
	}
	if len(cidrs) != 0 {
		t.Errorf("expected empty slice on timeout, got %v", cidrs)
	}
}

// TestLoadTrustedCIDRsFromNetBox_MalformedJSON verifies that a response with
// invalid JSON returns an empty slice and no error (fail-open).
func TestLoadTrustedCIDRsFromNetBox_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{not valid json!!!`))
	}))
	defer srv.Close()

	cidrs, err := LoadTrustedCIDRsFromNetBox(context.Background(), srv.URL, "token", "tag")
	if err != nil {
		t.Fatalf("expected nil error (fail-open), got: %v", err)
	}
	if len(cidrs) != 0 {
		t.Errorf("expected empty slice on malformed JSON, got %v", cidrs)
	}
}

// TestLoadTrustedCIDRsFromNetBox_MissingTag verifies that when the server
// receives a request without the expected tag, it can handle it gracefully.
// The test stub returns an empty results array for a missing tag.
func TestLoadTrustedCIDRsFromNetBox_MissingTag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tag := r.URL.Query().Get("tag")
		if tag == "" {
			// Server returns empty results when tag is missing
			resp := map[string]interface{}{
				"count":   0,
				"results": []map[string]interface{}{},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		// Normal response when tag is present
		resp := map[string]interface{}{
			"count": 1,
			"results": []map[string]interface{}{
				{"prefix": "10.0.0.0/8"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	// Call with empty tag — should get empty slice (no error)
	cidrs, err := LoadTrustedCIDRsFromNetBox(context.Background(), srv.URL, "token", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cidrs) != 0 {
		t.Errorf("expected empty slice for empty tag, got %v", cidrs)
	}

	// Call with tag present — should get the prefix
	cidrs, err = LoadTrustedCIDRsFromNetBox(context.Background(), srv.URL, "token", "ja4proxy-trusted")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cidrs) != 1 || cidrs[0] != "10.0.0.0/8" {
		t.Errorf("cidrs = %v, want [10.0.0.0/8]", cidrs)
	}
}
