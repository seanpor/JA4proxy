package client_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anomalyco/ja4proxy/internal/cli/client"
)

// TestClient_SetsAuthHeader verifies that every HTTP request carries an
// Authorization: Bearer <token> header.
func TestClient_SetsAuthHeader(t *testing.T) {
	t.Helper()

	var receivedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "my-test-token")
	_, err := c.Get("/api/v1/health/deep")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "Bearer my-test-token"
	if receivedAuth != want {
		t.Errorf("Authorization header = %q; want %q", receivedAuth, want)
	}
}

// TestClient_Returns401Error verifies that a 401 response produces a
// descriptive error containing "unauthorized" or "401".
func TestClient_Returns401Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":"Unauthorized"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "bad-token")
	_, err := c.Get("/api/v1/dial")
	if err == nil {
		t.Fatal("expected an error for 401, got nil")
	}

	errLower := strings.ToLower(err.Error())
	if !strings.Contains(errLower, "unauthorized") && !strings.Contains(errLower, "401") {
		t.Errorf("error %q does not mention unauthorized or 401", err.Error())
	}
}

// TestClient_Returns5xxError verifies that a 500 response produces an error.
func TestClient_Returns5xxError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":"Internal Server Error"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := c.Get("/api/v1/dial")
	if err == nil {
		t.Fatal("expected an error for 500, got nil")
	}
}

// TestClient_Timeout verifies that the client respects a short timeout when
// the server hangs and does not return.
func TestClient_Timeout(t *testing.T) {
	// A server that hangs indefinitely.
	hung := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-hung // block forever
	}))
	defer func() {
		close(hung)
		srv.Close()
	}()

	// Create a client with a very short timeout so the test finishes quickly.
	c := client.NewWithTimeout(srv.URL, "token", 50*time.Millisecond)
	_, err := c.Get("/api/v1/health/deep")
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

// TestClient_PostSetsAuthHeader verifies that POST requests also carry the auth header.
func TestClient_PostSetsAuthHeader(t *testing.T) {
	var receivedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "post-token")
	_, err := c.Post("/api/v1/bans/1.2.3.4", map[string]interface{}{"ttl": 3600, "reason": "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "Bearer post-token"
	if receivedAuth != want {
		t.Errorf("Authorization header = %q; want %q", receivedAuth, want)
	}
}

// TestClient_DeleteSetsAuthHeader verifies that DELETE requests carry the auth header.
func TestClient_DeleteSetsAuthHeader(t *testing.T) {
	var receivedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "delete-token")
	_, err := c.Delete("/api/v1/bans/1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "Bearer delete-token"
	if receivedAuth != want {
		t.Errorf("Authorization header = %q; want %q", receivedAuth, want)
	}
}
