package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── TestMain / fixture helpers ────────────────────────────────────────────────

func TestClientSendsBearerToken(t *testing.T) {
	var capturedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","redis":"ok","proxy_instances":0,"geoip":"ok","uptime_seconds":0.1}`))
	}))
	defer server.Close()

	c, err := New(server.URL, "test-token-abc123")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}

	if capturedAuth != "Bearer test-token-abc123" {
		t.Errorf("Authorization header = %q, want %q", capturedAuth, "Bearer test-token-abc123")
	}
}

func TestClientURLEncodesPathParams(t *testing.T) {
	var capturedPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Go 1.20+ decodes %2F to / in r.URL.Path, so we check r.RequestURI
		// which preserves the raw encoding.
		if r.RequestURI != "" {
			capturedPath = r.RequestURI
		} else {
			capturedPath = r.URL.Path
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Ban created","ip":"198.51.100.0/24","ttl":3600,"reason":"test"}`))
	}))
	defer server.Close()

	c, err := New(server.URL, "tok")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Ban CIDR with slash must be URL-encoded to %2F
	_, err = c.CreateBan(context.Background(), "198.51.100.0/24", 3600, "test")
	if err != nil {
		t.Fatalf("CreateBan() error = %v", err)
	}

	if !strings.Contains(capturedPath, "%2F") && !strings.Contains(capturedPath, "%2f") {
		t.Errorf("Path should contain URL-encoded slash %%2F, got %q", capturedPath)
	}
}

func TestClientHandles401(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"detail":"Invalid or expired token"}`))
	}))
	defer server.Close()

	c, err := New(server.URL, "bad-token")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = c.Health(context.Background())
	if err == nil {
		t.Fatal("Expected error for 401, got nil")
	}

	// Error should mention authentication/unauthorized
	if !strings.Contains(strings.ToLower(err.Error()), "401") &&
		!strings.Contains(strings.ToLower(err.Error()), "unauthorized") &&
		!strings.Contains(strings.ToLower(err.Error()), "auth") {
		t.Errorf("Error should mention auth/401, got: %v", err)
	}
}

func TestClientHandles404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"detail":"Resource not found"}`))
	}))
	defer server.Close()

	c, err := New(server.URL, "tok")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = c.GetBan(context.Background(), "10.0.0.1")
	if err == nil {
		t.Fatal("Expected error for 404, got nil")
	}
}

func TestClientHandles400(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"detail":"Dial change of 50 exceeds the maximum of 10 per request"}`))
	}))
	defer server.Close()

	c, err := New(server.URL, "tok")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = c.UpdateDial(context.Background(), 50)
	if err == nil {
		t.Fatal("Expected error for 400, got nil")
	}
}

func TestClientPostBansSendsCorrectBody(t *testing.T) {
	var receivedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &receivedBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Ban created","ip":"10.0.0.1","ttl":7200,"reason":"abuse"}`))
	}))
	defer server.Close()

	c, err := New(server.URL, "tok")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = c.CreateBan(context.Background(), "10.0.0.1", 7200, "abuse")
	if err != nil {
		t.Fatalf("CreateBan() error = %v", err)
	}

	if ttl, ok := receivedBody["ttl"].(float64); !ok || int(ttl) != 7200 {
		t.Errorf("Request body ttl = %v, want 7200", receivedBody["ttl"])
	}
	if reason, ok := receivedBody["reason"].(string); !ok || reason != "abuse" {
		t.Errorf("Request body reason = %v, want 'abuse'", receivedBody["reason"])
	}
}

func TestClientPostListEntrySendsCorrectBody(t *testing.T) {
	var receivedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &receivedBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{
			"id":"550e8400-e29b-41d4-a716-446655440000",
			"entry":"jarm:123",
			"list_type":"blocklist",
			"managed_by":"terraform",
			"note":"test note",
			"created_at":"2026-01-01T00:00:00Z",
			"created_by":"terraform",
			"expires_at":null
		}`))
	}))
	defer server.Close()

	c, err := New(server.URL, "tok")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = c.CreateListEntry(context.Background(), "blocklist", "jarm:123", "terraform", "test note", nil)
	if err != nil {
		t.Fatalf("CreateListEntry() error = %v", err)
	}

	if entry, ok := receivedBody["entry"].(string); !ok || entry != "jarm:123" {
		t.Errorf("Request body entry = %v, want 'jarm:123'", receivedBody["entry"])
	}
	if mb, ok := receivedBody["managed_by"].(string); !ok || mb != "terraform" {
		t.Errorf("Request body managed_by = %v, want 'terraform'", receivedBody["managed_by"])
	}
}

func TestClientPatchDialSendsCorrectBody(t *testing.T) {
	var receivedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("Expected PATCH, got %s", r.Method)
		}
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &receivedBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"value":55,"updated_at":"2026-01-01T00:00:00Z"}`))
	}))
	defer server.Close()

	c, err := New(server.URL, "tok")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = c.UpdateDial(context.Background(), 55)
	if err != nil {
		t.Fatalf("UpdateDial() error = %v", err)
	}

	if val, ok := receivedBody["value"].(float64); !ok || int(val) != 55 {
		t.Errorf("Request body value = %v, want 55", receivedBody["value"])
	}
}

func TestClientDeleteWebhook(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("Expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	c, err := New(server.URL, "tok")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = c.DeleteWebhook(context.Background(), "550e8400-e29b-41d4-a716-446655440000")
	if err != nil {
		t.Fatalf("DeleteWebhook() error = %v", err)
	}
}

func TestClientDeleteBan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("Expected DELETE, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Ban lifted","ip":"10.0.0.1"}`))
	}))
	defer server.Close()

	c, err := New(server.URL, "tok")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = c.DeleteBan(context.Background(), "10.0.0.1")
	if err != nil {
		t.Fatalf("DeleteBan() error = %v", err)
	}
}

func TestClientDeleteListEntry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	c, err := New(server.URL, "tok")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = c.DeleteListEntry(context.Background(), "allowlist", "550e8400-e29b-41d4-a716-446655440000")
	if err != nil {
		t.Fatalf("DeleteListEntry() error = %v", err)
	}
}

func TestClientGetListEntries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"entries":[{
				"id":"550e8400-e29b-41d4-a716-446655440000",
				"entry":"jarm:abc",
				"list_type":"allowlist",
				"managed_by":"terraform",
				"note":"test",
				"created_at":"2026-01-01T00:00:00Z",
				"created_by":"terraform",
				"expires_at":null
			}],
			"count":1
		}`))
	}))
	defer server.Close()

	c, err := New(server.URL, "tok")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	resp, err := c.ListEntries(context.Background(), "allowlist")
	if err != nil {
		t.Fatalf("ListEntries() error = %v", err)
	}

	if resp.Count != 1 {
		t.Errorf("Count = %d, want 1", resp.Count)
	}
	if len(resp.Entries) != 1 {
		t.Fatalf("Entries length = %d, want 1", len(resp.Entries))
	}
}

func TestClientGetListEntryByID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"id":"550e8400-e29b-41d4-a716-446655440000",
			"entry":"jarm:abc",
			"list_type":"allowlist",
			"managed_by":"terraform",
			"note":"test",
			"created_at":"2026-01-01T00:00:00Z",
			"created_by":"terraform",
			"expires_at":null
		}`))
	}))
	defer server.Close()

	c, err := New(server.URL, "tok")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	entry, err := c.GetListEntryByID(context.Background(), "allowlist", "550e8400-e29b-41d4-a716-446655440000")
	if err != nil {
		t.Fatalf("GetListEntryByID() error = %v", err)
	}

	if entry.ID != "550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("ID = %q, want %q", entry.ID, "550e8400-e29b-41d4-a716-446655440000")
	}
}

func TestClientGetWebhook(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"id":"wh-001",
			"url":"https://example.com/hook",
			"events":["ban.created"],
			"active":true,
			"created_at":"2026-01-01T00:00:00Z",
			"managed_by":"terraform"
		}`))
	}))
	defer server.Close()

	c, err := New(server.URL, "tok")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	wh, err := c.GetWebhook(context.Background(), "wh-001")
	if err != nil {
		t.Fatalf("GetWebhook() error = %v", err)
	}

	if wh.URL != "https://example.com/hook" {
		t.Errorf("URL = %q, want %q", wh.URL, "https://example.com/hook")
	}
	if !wh.Active {
		t.Error("Expected Active = true")
	}
}

func TestClientCreateWebhook(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{
			"id":"wh-002",
			"url":"https://hooks.example.com/notify",
			"events":["ban.created","dial.changed"],
			"active":true,
			"created_at":"2026-01-01T00:00:00Z",
			"managed_by":"terraform",
			"secret":"whsec_abc123xyz"
		}`))
	}))
	defer server.Close()

	c, err := New(server.URL, "tok")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	resp, err := c.CreateWebhook(context.Background(), "https://hooks.example.com/notify", []string{"ban.created", "dial.changed"}, true)
	if err != nil {
		t.Fatalf("CreateWebhook() error = %v", err)
	}

	if resp.Secret != "whsec_abc123xyz" {
		t.Errorf("Secret = %q, want %q", resp.Secret, "whsec_abc123xyz")
	}
}

func TestClientUpdateWebhook(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("Expected PUT, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"id":"wh-001",
			"url":"https://new-url.example.com/hook",
			"events":["ban.deleted"],
			"active":false,
			"created_at":"2026-01-01T00:00:00Z",
			"managed_by":"terraform"
		}`))
	}))
	defer server.Close()

	c, err := New(server.URL, "tok")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	resp, err := c.UpdateWebhook(context.Background(), "wh-001", "https://new-url.example.com/hook", nil, false)
	if err != nil {
		t.Fatalf("UpdateWebhook() error = %v", err)
	}

	if resp.URL != "https://new-url.example.com/hook" {
		t.Errorf("URL = %q, want %q", resp.URL, "https://new-url.example.com/hook")
	}
	if resp.Active {
		t.Error("Expected Active = false")
	}
}

func TestClientGetDial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"value":30,"updated_at":null}`))
	}))
	defer server.Close()

	c, err := New(server.URL, "tok")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	d, err := c.GetDial(context.Background())
	if err != nil {
		t.Fatalf("GetDial() error = %v", err)
	}

	if d.Value != 30 {
		t.Errorf("Value = %d, want 30", d.Value)
	}
}

func TestClientGetBans(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"bans":[
				{"ip":"10.0.0.1","reason":"abuse","ttl_remaining":3000},
				{"ip":"192.168.1.0/24","reason":"scan","ttl_remaining":null}
			],
			"count":2
		}`))
	}))
	defer server.Close()

	c, err := New(server.URL, "tok")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	resp, err := c.ListBans(context.Background())
	if err != nil {
		t.Fatalf("ListBans() error = %v", err)
	}

	if resp.Count != 2 {
		t.Errorf("Count = %d, want 2", resp.Count)
	}
	if len(resp.Bans) != 2 {
		t.Fatalf("Bans length = %d, want 2", len(resp.Bans))
	}
}

func TestClientBanNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"detail":"No active ban found for IP: 10.0.0.1"}`))
	}))
	defer server.Close()

	c, err := New(server.URL, "tok")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = c.GetBan(context.Background(), "10.0.0.1")
	if err == nil {
		t.Fatal("Expected error for missing ban, got nil")
	}
}
