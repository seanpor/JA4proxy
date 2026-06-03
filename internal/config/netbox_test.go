package config

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func init() {
	os.Setenv("JA4PROXY_TEST_ALLOW_INSECURE_NETBOX", "true")
}

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
			"results": []map[string]string{
				{"prefix": "192.168.1.0/24"},
				{"prefix": "10.0.0.0/8"},
			},
			"next": nil,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	cidrs, err := LoadTrustedCIDRsFromNetBox(context.Background(), srv.URL, "test-token-123", "ja4proxy-trusted")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"192.168.1.0/24", "10.0.0.0/8"}
	if len(cidrs) != len(want) {
		t.Fatalf("len(cidrs) = %d, want %d", len(cidrs), len(want))
	}
	for i := range want {
		if cidrs[i] != want[i] {
			t.Errorf("cidrs[%d] = %q, want %q", i, cidrs[i], want[i])
		}
	}
}

// TestLoadTrustedCIDRsFromNetBox_ServerError verifies fail-open on 500.
func TestLoadTrustedCIDRsFromNetBox_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cidrs, err := LoadTrustedCIDRsFromNetBox(context.Background(), srv.URL, "token", "tag")
	if err != nil {
		t.Fatalf("expected nil error (fail-open), got: %v", err)
	}
	if len(cidrs) != 0 {
		t.Errorf("expected 0 cidrs on error, got %d", len(cidrs))
	}
}

// TestLoadTrustedCIDRsFromNetBox_Timeout verifies fail-open on timeout.
func TestLoadTrustedCIDRsFromNetBox_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	cidrs, err := LoadTrustedCIDRsFromNetBox(ctx, srv.URL, "token", "tag")
	if err != nil {
		t.Fatalf("expected nil error (fail-open), got: %v", err)
	}
	if len(cidrs) != 0 {
		t.Errorf("expected 0 cidrs on timeout, got %d", len(cidrs))
	}
}

// TestLoadTrustedCIDRsFromNetBox_MalformedJSON verifies fail-open on bad JSON.
func TestLoadTrustedCIDRsFromNetBox_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"results": []}`)
	}))
	defer srv.Close()

	cidrs, err := LoadTrustedCIDRsFromNetBox(context.Background(), srv.URL, "token", "tag")
	if err != nil {
		t.Fatalf("expected nil error (fail-open), got: %v", err)
	}
	if len(cidrs) != 0 {
		t.Errorf("expected 0 cidrs on malformed JSON, got %d", len(cidrs))
	}
}

// TestLoadTrustedCIDRsFromNetBox_MissingTag verifies query param is sent.
func TestLoadTrustedCIDRsFromNetBox_MissingTag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("tag") != "" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"results": []}`)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	_, err := LoadTrustedCIDRsFromNetBox(context.Background(), srv.URL, "token", "mytag")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestLoadTrustedCIDRsFromNetBox_Pagination verifies that "next" pointer is followed.
func TestLoadTrustedCIDRsFromNetBox_Pagination(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			next := "http://" + r.Host + "/page2"
			resp := map[string]interface{}{
				"results": []map[string]string{{"prefix": "1.1.1.1/32"}},
				"next":    next,
			}
			json.NewEncoder(w).Encode(resp)
		} else {
			resp := map[string]interface{}{
				"results": []map[string]string{{"prefix": "2.2.2.2/32"}},
				"next":    nil,
			}
			json.NewEncoder(w).Encode(resp)
		}
	}))
	defer srv.Close()

	cidrs, err := LoadTrustedCIDRsFromNetBox(context.Background(), srv.URL, "token", "tag")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cidrs) != 2 {
		t.Errorf("expected 2 cidrs, got %d", len(cidrs))
	}
}

// TestLoadTrustedCIDRsFromNetBox_RejectsDefaultRoute verifies protection
// against overly-broad CIDRs.
func TestLoadTrustedCIDRsFromNetBox_RejectsDefaultRoute(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"results": []map[string]string{
				{"prefix": "0.0.0.0/0"},
				{"prefix": "::/0"},
				{"prefix": "1.2.3.4/32"},
			},
			"next": nil,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	cidrs, err := LoadTrustedCIDRsFromNetBox(context.Background(), srv.URL, "token", "tag")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cidrs) != 1 || cidrs[0] != "1.2.3.4/32" {
		t.Errorf("expected only 1.2.3.4/32, got %v", cidrs)
	}
}

// TestLoadTrustedCIDRsFromNetBox_ContextCancellation verifies that
// cancellation is respected.
func TestLoadTrustedCIDRsFromNetBox_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	cidrs, err := LoadTrustedCIDRsFromNetBox(ctx, srv.URL, "token", "tag")
	if err != nil {
		t.Fatalf("expected nil error (fail-open), got: %v", err)
	}
	if len(cidrs) != 0 {
		t.Errorf("expected 0 cidrs on cancellation, got %d", len(cidrs))
	}
}
