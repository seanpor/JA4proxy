package commands_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anomalyco/ja4proxy/internal/cli/client"
	"github.com/anomalyco/ja4proxy/internal/cli/commands"
)

// TestIPBan_CallsCorrectEndpoint verifies that RunIPBan makes a POST request
// to /api/v1/bans/{ip} with the expected body fields.
func TestIPBan_CallsCorrectEndpoint(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("failed to decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"Ban created","ip":"198.51.100.4","ttl":3600,"reason":"test"}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	if err := commands.RunIPBan(c, "198.51.100.4", 3600, "test"); err != nil {
		t.Fatalf("RunIPBan returned error: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q; want POST", gotMethod)
	}
	if gotPath != "/api/v1/bans/198.51.100.4" {
		t.Errorf("path = %q; want /api/v1/bans/198.51.100.4", gotPath)
	}
	if gotBody["reason"] != "test" {
		t.Errorf("body.reason = %v; want test", gotBody["reason"])
	}
}

// TestIPBan_CIDR verifies that banning a CIDR calls
// POST /api/v1/bans/198.51.100.0/24 (path allows slashes).
func TestIPBan_CIDR(t *testing.T) {
	var gotPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"Ban created","ip":"198.51.100.0/24","ttl":3600,"reason":"scanning"}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	if err := commands.RunIPBan(c, "198.51.100.0/24", 3600, "scanning"); err != nil {
		t.Fatalf("RunIPBan (CIDR) returned error: %v", err)
	}

	if gotPath != "/api/v1/bans/198.51.100.0/24" {
		t.Errorf("path = %q; want /api/v1/bans/198.51.100.0/24", gotPath)
	}
}

// TestIPRelease_CallsCorrectEndpoint verifies RunIPRelease makes DELETE /api/v1/bans/{ip}.
func TestIPRelease_CallsCorrectEndpoint(t *testing.T) {
	var gotMethod, gotPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"Ban lifted","ip":"198.51.100.4"}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	if err := commands.RunIPRelease(c, "198.51.100.4"); err != nil {
		t.Fatalf("RunIPRelease returned error: %v", err)
	}

	if gotMethod != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", gotMethod)
	}
	if gotPath != "/api/v1/bans/198.51.100.4" {
		t.Errorf("path = %q; want /api/v1/bans/198.51.100.4", gotPath)
	}
}

// TestIPWatchlistAdd verifies that RunWatchlistAdd calls POST /api/v1/watchlist.
func TestIPWatchlistAdd(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("failed to decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"uuid-1","entry":"10.0.0.1","reason":"monitoring"}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	if err := commands.RunWatchlistAdd(c, "10.0.0.1", 3600, "monitoring"); err != nil {
		t.Fatalf("RunWatchlistAdd returned error: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q; want POST", gotMethod)
	}
	if gotPath != "/api/v1/watchlist" {
		t.Errorf("path = %q; want /api/v1/watchlist", gotPath)
	}
}

// TestIPWatchlistRemove_LookupThenDelete verifies that RunWatchlistRemove performs
// GET /api/v1/watchlist to find the ID, then DELETE /api/v1/watchlist/{id}.
func TestIPWatchlistRemove_LookupThenDelete(t *testing.T) {
	var calls []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/watchlist":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id":"wl-42","entry":"10.0.0.1","reason":"monitoring"}]`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/watchlist/wl-42":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"removed"}`))
		default:
			t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	if err := commands.RunWatchlistRemove(c, "10.0.0.1"); err != nil {
		t.Fatalf("RunWatchlistRemove returned error: %v", err)
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
}

// TestIPWatchlistRemove_NotFound verifies that RunWatchlistRemove returns an error
// containing "no entry found" when the watchlist is empty.
func TestIPWatchlistRemove_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	err := commands.RunWatchlistRemove(c, "10.0.0.99")
	if err == nil {
		t.Fatal("expected error for not-found IP, got nil")
	}

	if !strings.Contains(strings.ToLower(err.Error()), "no entry found") {
		t.Errorf("error %q does not contain 'no entry found'", err.Error())
	}
}

// TestIPLookup_AggregatesRequests verifies that RunIPLookup calls both
// /api/v1/bans/{ip} AND /api/v1/connections?ip={ip}&limit=10.
func TestIPLookup_AggregatesRequests(t *testing.T) {
	var calledPaths []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledPaths = append(calledPaths, r.URL.String())
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	if _, err := commands.RunIPLookup(c, "1.2.3.4"); err != nil {
		t.Fatalf("RunIPLookup returned error: %v", err)
	}

	wantPaths := []string{
		"/api/v1/bans/1.2.3.4",
		"/api/v1/connections",
	}

	for _, want := range wantPaths {
		found := false
		for _, got := range calledPaths {
			if strings.HasPrefix(got, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected a call to %q, got calls: %v", want, calledPaths)
		}
	}

	// Verify the connections query includes ip and limit params.
	var connectionsCall string
	for _, p := range calledPaths {
		if strings.HasPrefix(p, "/api/v1/connections") {
			connectionsCall = p
			break
		}
	}
	if connectionsCall == "" {
		t.Fatal("no call to /api/v1/connections")
	}
	if !strings.Contains(connectionsCall, "ip=1.2.3.4") {
		t.Errorf("connections call %q missing ip=1.2.3.4", connectionsCall)
	}
	if !strings.Contains(connectionsCall, "limit=10") {
		t.Errorf("connections call %q missing limit=10", connectionsCall)
	}
}
