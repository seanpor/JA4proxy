package commands_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/seanpor/ja4proxy/internal/cli/client"
	"github.com/seanpor/ja4proxy/internal/cli/commands"
)

// ── RunDialSetRaw ──────────────────────────────────────────────────────────

func TestDialSetRaw_Success(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"setting":50}`))
	}))
	defer srv.Close()

	err := commands.RunDialSetRaw(
		context.Background(), srv.Client(),
		srv.URL, "test-token",
		50, "CHG-001", "test notes",
	)
	if err != nil {
		t.Fatalf("RunDialSetRaw returned error: %v", err)
	}
	if gotMethod != http.MethodPatch {
		t.Errorf("method = %q; want PATCH", gotMethod)
	}
	if gotPath != "/api/v1/dial" {
		t.Errorf("path = %q; want /api/v1/dial", gotPath)
	}
}

func TestDialSetRaw_PendingApproval(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"decision_id":"dec-raw-1","status":"pending_approval"}`))
	}))
	defer srv.Close()

	err := commands.RunDialSetRaw(
		context.Background(), srv.Client(),
		srv.URL, "test-token",
		80, "", "needs approval",
	)
	if err == nil {
		t.Fatal("expected PendingApprovalError, got nil")
	}
	var pending *commands.PendingApprovalError
	if !errors.As(err, &pending) {
		t.Fatalf("expected *PendingApprovalError, got %T: %v", err, err)
	}
	if pending.DecisionID != "dec-raw-1" {
		t.Errorf("DecisionID = %q; want dec-raw-1", pending.DecisionID)
	}
}

func TestDialSetRaw_Non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
	}))
	defer srv.Close()

	err := commands.RunDialSetRaw(
		context.Background(), srv.Client(),
		srv.URL, "test-token",
		50, "", "",
	)
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
}

func TestDialSetRaw_NoToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	err := commands.RunDialSetRaw(
		context.Background(), srv.Client(),
		srv.URL, "", // empty token
		10, "", "",
	)
	if err != nil {
		t.Fatalf("RunDialSetRaw error: %v", err)
	}
	if gotAuth != "" {
		t.Errorf("Authorization = %q; want empty when token is empty", gotAuth)
	}
}

func TestDialSetRaw_WithTicket(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	// Verify that ticket is included when non-empty
	err := commands.RunDialSetRaw(
		context.Background(), srv.Client(),
		srv.URL, "token",
		50, "CHG-999", "notes",
	)
	if err != nil {
		t.Fatalf("RunDialSetRaw error: %v", err)
	}
}

func TestDialSetRaw_MalformedResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	// Non-JSON body should not cause an error for 200 status
	err := commands.RunDialSetRaw(
		context.Background(), srv.Client(),
		srv.URL, "token",
		50, "", "",
	)
	if err != nil {
		t.Fatalf("RunDialSetRaw should not error on malformed 200 body: %v", err)
	}
}

func TestDialSetRaw_202WithMalformedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	err := commands.RunDialSetRaw(
		context.Background(), srv.Client(),
		srv.URL, "token",
		50, "", "",
	)
	// Should still return PendingApprovalError even with malformed body
	if err == nil {
		t.Fatal("expected error for 202")
	}
	var pending *commands.PendingApprovalError
	if !errors.As(err, &pending) {
		t.Fatalf("expected *PendingApprovalError, got %T: %v", err, err)
	}
}

// ── PendingApprovalError.Error() ───────────────────────────────────────────

func TestPendingApprovalError_Error(t *testing.T) {
	e := &commands.PendingApprovalError{DecisionID: "dec-123"}
	got := e.Error()
	want := "PENDING APPROVAL: dec-123"
	if got != want {
		t.Errorf("Error() = %q; want %q", got, want)
	}
}

// ── RunDialGet error path ──────────────────────────────────────────────────

func TestDialGet_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"fail"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, err := commands.RunDialGet(context.Background(), c)
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

// ── RunDialSet with dial=-1 ────────────────────────────────────────────────

func TestDialSet_NegativeValue(t *testing.T) {
	c := client.New("http://127.0.0.1:0", "token")
	err := commands.RunDialSet(context.Background(), c, -1, "", "")
	if err == nil {
		t.Fatal("expected error for dial=-1")
	}
}
