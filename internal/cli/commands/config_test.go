package commands_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anomalyco/ja4proxy/internal/cli/client"
	"github.com/anomalyco/ja4proxy/internal/cli/commands"
)

// TestConfigReload_AllNodes verifies that RunConfigReload with an empty node
// argument first calls GET /api/v1/nodes, then calls POST /api/v1/nodes/{host}/reload
// for each node returned.
func TestConfigReload_AllNodes(t *testing.T) {
	var calls []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/nodes":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"nodes":[{"host":"ja4proxy-01"},{"host":"ja4proxy-02"}],"count":2}`))
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/nodes/") &&
			strings.HasSuffix(r.URL.Path, "/reload"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"published":true}`))
		default:
			t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	if err := commands.RunConfigReload(context.Background(), c, ""); err != nil {
		t.Fatalf("RunConfigReload returned error: %v", err)
	}

	// Expect: 1 GET /api/v1/nodes + 2 POST reload calls
	if len(calls) < 3 {
		t.Fatalf("expected at least 3 calls, got %d: %v", len(calls), calls)
	}

	if calls[0] != "GET /api/v1/nodes" {
		t.Errorf("first call should be GET /api/v1/nodes, got %q", calls[0])
	}

	reloadCalls := 0
	for _, call := range calls[1:] {
		if strings.Contains(call, "reload") {
			reloadCalls++
		}
	}
	if reloadCalls < 2 {
		t.Errorf("expected 2 reload calls, got %d; all calls: %v", reloadCalls, calls)
	}
}

// TestConfigReload_SpecificNode verifies that RunConfigReload with a specific
// node host only calls POST /api/v1/nodes/{host}/reload (no GET nodes call).
func TestConfigReload_SpecificNode(t *testing.T) {
	var calls []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/nodes/ja4proxy-01/reload" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"published":true,"host":"ja4proxy-01"}`))
		} else {
			t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	if err := commands.RunConfigReload(context.Background(), c, "ja4proxy-01"); err != nil {
		t.Fatalf("RunConfigReload returned error: %v", err)
	}

	if len(calls) != 1 {
		t.Errorf("expected exactly 1 call, got %d: %v", len(calls), calls)
	}
	if calls[0] != "POST /api/v1/nodes/ja4proxy-01/reload" {
		t.Errorf("call = %q; want POST /api/v1/nodes/ja4proxy-01/reload", calls[0])
	}
}
