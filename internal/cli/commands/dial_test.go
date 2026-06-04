package commands_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/seanpor/ja4proxy/internal/cli/client"
	"github.com/seanpor/ja4proxy/internal/cli/commands"
)

// TestDialGet verifies that RunDialGet calls GET /api/v1/dial and returns the
// current dial setting.
func TestDialGet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q; want GET", r.Method)
		}
		if r.URL.Path != "/api/v1/dial" {
			t.Errorf("path = %q; want /api/v1/dial", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"setting":42}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	dv, err := commands.RunDialGet(context.Background(), c)
	if err != nil {
		t.Fatalf("RunDialGet returned error: %v", err)
	}

	if dv.Setting != 42 {
		t.Errorf("dial setting = %d; want 42", dv.Setting)
	}
}

// TestDialSet_Success verifies that RunDialSet calls PATCH /api/v1/dial and
// returns nil on HTTP 200.
func TestDialSet_Success(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("failed to decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"setting":70,"updated_at":"2026-04-07T00:00:00Z"}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	err := commands.RunDialSet(context.Background(), c, 70, "CHG001", "raising for incident response")
	if err != nil {
		t.Fatalf("RunDialSet returned error: %v", err)
	}

	if gotMethod != http.MethodPatch {
		t.Errorf("method = %q; want PATCH", gotMethod)
	}
	if gotPath != "/api/v1/dial" {
		t.Errorf("path = %q; want /api/v1/dial", gotPath)
	}
}

// TestDialSet_PendingApproval verifies that a 202 response causes RunDialSet to
// return a PendingApprovalError containing the decision ID.
func TestDialSet_PendingApproval(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"decision_id":"dec-001","status":"pending_approval"}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	err := commands.RunDialSet(context.Background(), c, 80, "CHG002", "needs four-eyes approval")

	if err == nil {
		t.Fatal("expected PendingApprovalError, got nil")
	}

	var pendingErr *commands.PendingApprovalError
	if !errors.As(err, &pendingErr) {
		t.Fatalf("expected *commands.PendingApprovalError, got %T: %v", err, err)
	}

	if pendingErr.DecisionID != "dec-001" {
		t.Errorf("DecisionID = %q; want dec-001", pendingErr.DecisionID)
	}
}

// TestDialSet_InvalidRange verifies that setting dial above 100 returns an error
// before any HTTP call is made.
func TestDialSet_InvalidRange(t *testing.T) {
	// No server needed — the validation is local and should fail before any HTTP call.
	c := client.New("http://127.0.0.1:0", "token")
	err := commands.RunDialSet(context.Background(), c, 150, "", "")
	if err == nil {
		t.Fatal("expected error for dial=150, got nil")
	}
}
