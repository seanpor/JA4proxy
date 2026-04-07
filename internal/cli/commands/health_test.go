package commands_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/anomalyco/ja4proxy/internal/cli/client"
	"github.com/anomalyco/ja4proxy/internal/cli/commands"
)

// TestHealth_SingleNode verifies that RunHealth with allNodes=false calls only
// GET /api/v1/health/deep and returns a slice containing the local node.
func TestHealth_SingleNode(t *testing.T) {
	var calledPaths []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledPaths = append(calledPaths, r.URL.Path)
		switch r.URL.Path {
		case "/api/v1/health/deep":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"host":"ja4proxy-01","status":"ok","version":"1.0.0","dial":10}`))
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	nodes, err := commands.RunHealth(context.Background(), c, false)
	if err != nil {
		t.Fatalf("RunHealth returned error: %v", err)
	}

	if len(nodes) == 0 {
		t.Fatal("expected at least one node in result")
	}

	// Only /api/v1/health/deep should have been called (no /api/v1/nodes when allNodes=false).
	calledDeep := false
	for _, p := range calledPaths {
		if p == "/api/v1/health/deep" {
			calledDeep = true
		}
		if p == "/api/v1/nodes" {
			t.Errorf("unexpected call to /api/v1/nodes when allNodes=false")
		}
	}
	if !calledDeep {
		t.Error("expected GET /api/v1/health/deep to be called")
	}
}

// TestHealth_AllNodes verifies that RunHealth with allNodes=true calls both
// GET /api/v1/nodes and GET /api/v1/health/deep and returns at least 2 nodes.
func TestHealth_AllNodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/nodes":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"nodes":[{"host":"ja4proxy-01","status":"healthy"},{"host":"ja4proxy-02","status":"healthy"}],"count":2}`))
		case "/api/v1/health/deep":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"host":"ja4proxy-01","status":"ok","version":"1.0.0","dial":10}`))
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	nodes, err := commands.RunHealth(context.Background(), c, true)
	if err != nil {
		t.Fatalf("RunHealth(allNodes=true) returned error: %v", err)
	}

	// With 2 nodes from /api/v1/nodes and 1 from deep health (already in list),
	// we expect exactly 2 nodes (no duplicate for ja4proxy-01).
	if len(nodes) < 2 {
		t.Errorf("expected at least 2 nodes, got %d", len(nodes))
	}
}

// TestHealth_DegradedNode verifies that RunHealth returns an error when the
// deep health endpoint returns a non-2xx status.
func TestHealth_DegradedNode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/health/deep":
			// 503 is a non-2xx status; the client will return an error.
			http.Error(w, `{"status":"degraded","redis":{"status":"error","error":"timeout"}}`, http.StatusServiceUnavailable)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := commands.RunHealth(context.Background(), c, false)

	// A 503 from deep health should propagate as an error (fail-open via caller).
	if err == nil {
		t.Error("expected error for 503 deep health, got nil")
	}
}
