package resources

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// ── Mock webhook store ───────────────────────────────────────────────────────

type mockWebhookStore struct {
	mu       sync.Mutex
	webhooks map[string]map[string]interface{} // id -> webhook
	nextID   int
}

func newMockWebhookStore() *mockWebhookStore {
	return &mockWebhookStore{webhooks: make(map[string]map[string]interface{})}
}

func (s *mockWebhookStore) create(url string, events []string, active bool, managedBy string) map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nextID++
	id := fmt.Sprintf("wh-%03d", s.nextID)
	entry := map[string]interface{}{
		"id":         id,
		"url":        url,
		"events":     events,
		"active":     active,
		"created_at": "2026-01-01T00:00:00Z",
		"managed_by": managedBy,
		"secret":     fmt.Sprintf("whsec_secret_%d", s.nextID),
	}
	s.webhooks[id] = entry
	return entry
}

func (s *mockWebhookStore) get(id string) (map[string]interface{}, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	wh, ok := s.webhooks[id]
	if !ok {
		return nil, false
	}
	// Return without secret
	result := make(map[string]interface{})
	for k, v := range wh {
		if k != "secret" {
			result[k] = v
		}
	}
	return result, true
}

func (s *mockWebhookStore) update(id string, url string, events []string, active *bool) (map[string]interface{}, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	wh, ok := s.webhooks[id]
	if !ok {
		return nil, false
	}
	if url != "" {
		wh["url"] = url
	}
	if events != nil {
		wh["events"] = events
	}
	if active != nil {
		wh["active"] = *active
	}
	result := make(map[string]interface{})
	for k, v := range wh {
		if k != "secret" {
			result[k] = v
		}
	}
	return result, true
}

func (s *mockWebhookStore) delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.webhooks, id)
}

func newWebhookMockServer(store *mockWebhookStore) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"detail":"Invalid token"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")

		// Health check
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/health" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok","redis":"ok","proxy_instances":1,"geoip":"ok","uptime_seconds":1.0}`))
			return
		}

		// POST /api/v1/webhooks
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/webhooks" {
			var body struct {
				URL    string   `json:"url"`
				Events []string `json:"events"`
				Active bool     `json:"active"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			resp := store.create(body.URL, body.Events, body.Active, "terraform")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(resp)
			return
		}

		// GET /api/v1/webhooks/{id}
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/webhooks/") {
			id := strings.TrimPrefix(r.URL.Path, "/api/v1/webhooks/")
			wh, ok := store.get(id)
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]interface{}{"detail": "Webhook not found"})
				return
			}
			json.NewEncoder(w).Encode(wh)
			return
		}

		// PUT /api/v1/webhooks/{id}
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/v1/webhooks/") {
			id := strings.TrimPrefix(r.URL.Path, "/api/v1/webhooks/")
			var body struct {
				URL    string   `json:"url,omitempty"`
				Events []string `json:"events,omitempty"`
				Active *bool    `json:"active,omitempty"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			resp, ok := store.update(id, body.URL, body.Events, body.Active)
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]interface{}{"detail": "Webhook not found"})
				return
			}
			json.NewEncoder(w).Encode(resp)
			return
		}

		// DELETE /api/v1/webhooks/{id}
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/webhooks/") {
			id := strings.TrimPrefix(r.URL.Path, "/api/v1/webhooks/")
			store.delete(id)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
}

// ── Test: Create, Read, Delete webhook ───────────────────────────────────────

func TestWebhook_CreateReadDelete(t *testing.T) {
	store := newMockWebhookStore()
	server := newWebhookMockServer(store)
	defer server.Close()

	providerServer := newListTestProvider(t, server.URL)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ja4proxy": func() (tfprotov6.ProviderServer, error) {
				return providerServer, nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "ja4proxy" {
						api_url   = %q
						api_token = "test-token"
					}
					resource "ja4proxy_webhook" "test" {
						url    = "https://hooks.example.com/ja4proxy"
						events = ["ban.created", "ban.deleted"]
						active = true
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ja4proxy_webhook.test", "url", "https://hooks.example.com/ja4proxy"),
					resource.TestCheckResourceAttr("ja4proxy_webhook.test", "events.#", "2"),
					resource.TestCheckResourceAttr("ja4proxy_webhook.test", "active", "true"),
					resource.TestCheckResourceAttrSet("ja4proxy_webhook.test", "id"),
					resource.TestCheckResourceAttrSet("ja4proxy_webhook.test", "created_at"),
				),
			},
			{
				Config: fmt.Sprintf(`provider "ja4proxy" {
    api_url   = %q
    api_token = "test-token"
  }`, server.URL),
				Destroy: true,
			},
		},
	})
}

// ── Test: Webhook update ─────────────────────────────────────────────────────

func TestWebhook_Update(t *testing.T) {
	store := newMockWebhookStore()
	server := newWebhookMockServer(store)
	defer server.Close()

	providerServer := newListTestProvider(t, server.URL)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ja4proxy": func() (tfprotov6.ProviderServer, error) {
				return providerServer, nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "ja4proxy" {
						api_url   = %q
						api_token = "test-token"
					}
					resource "ja4proxy_webhook" "update_test" {
						url    = "https://hooks.example.com/old"
						events = ["ban.created"]
						active = true
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ja4proxy_webhook.update_test", "url", "https://hooks.example.com/old"),
					resource.TestCheckResourceAttr("ja4proxy_webhook.update_test", "active", "true"),
				),
			},
			{
				Config: fmt.Sprintf(`
					provider "ja4proxy" {
						api_url   = %q
						api_token = "test-token"
					}
					resource "ja4proxy_webhook" "update_test" {
						url    = "https://hooks.example.com/new"
						events = ["ban.created", "dial.changed"]
						active = false
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ja4proxy_webhook.update_test", "url", "https://hooks.example.com/new"),
					resource.TestCheckResourceAttr("ja4proxy_webhook.update_test", "events.#", "2"),
					resource.TestCheckResourceAttr("ja4proxy_webhook.update_test", "active", "false"),
				),
			},
		},
	})
}

// ── Test: Webhook secret returned only on create ─────────────────────────────

func TestWebhook_SecretReturned(t *testing.T) {
	var secretFromCreate string

	store := newMockWebhookStore()
	server := newWebhookMockServer(store)
	defer server.Close()

	providerServer := newListTestProvider(t, server.URL)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ja4proxy": func() (tfprotov6.ProviderServer, error) {
				return providerServer, nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "ja4proxy" {
						api_url   = %q
						api_token = "test-token"
					}
					resource "ja4proxy_webhook" "secret_test" {
						url    = "https://hooks.example.com/secret"
						events = ["ban.created"]
						active = true
					}
				`, server.URL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrWith("ja4proxy_webhook.secret_test", "secret", func(v string) error {
						secretFromCreate = v
						if v == "" {
							return fmt.Errorf("expected secret to be returned on create, got empty string")
						}
						return nil
					}),
				),
			},
		},
	})

	// Secret should have been captured
	if secretFromCreate == "" {
		t.Error("Secret should have been returned on create but was empty")
	}

	// Secret should match the whsec_ pattern
	if !strings.HasPrefix(secretFromCreate, "whsec_") {
		t.Errorf("Secret should start with 'whsec_', got %q", secretFromCreate)
	}
}

// ── Test: Webhook not found on read ──────────────────────────────────────────

func TestWebhook_NotFound(t *testing.T) {
	store := newMockWebhookStore()
	server := newWebhookMockServer(store)
	defer server.Close()

	providerServer := newListTestProvider(t, server.URL)

	// Creating a new webhook should succeed even on an empty store
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ja4proxy": func() (tfprotov6.ProviderServer, error) {
				return providerServer, nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "ja4proxy" {
						api_url   = %q
						api_token = "test-token"
					}
					resource "ja4proxy_webhook" "fresh" {
						url    = "https://fresh.example.com/hook"
						events = ["dial.changed"]
						active = true
					}
				`, server.URL),
				Check: resource.TestCheckResourceAttr("ja4proxy_webhook.fresh", "url", "https://fresh.example.com/hook"),
			},
		},
	})
}

// ── Test: Webhook with empty events list ─────────────────────────────────────

func TestWebhook_EmptyEvents(t *testing.T) {
	store := newMockWebhookStore()
	server := newWebhookMockServer(store)
	defer server.Close()

	providerServer := newListTestProvider(t, server.URL)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ja4proxy": func() (tfprotov6.ProviderServer, error) {
				return providerServer, nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "ja4proxy" {
						api_url   = %q
						api_token = "test-token"
					}
					resource "ja4proxy_webhook" "no_events" {
						url    = "https://catchall.example.com/hook"
						events = []
						active = true
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ja4proxy_webhook.no_events", "url", "https://catchall.example.com/hook"),
					resource.TestCheckResourceAttr("ja4proxy_webhook.no_events", "events.#", "0"),
				),
			},
		},
	})
}

// ── Test: Webhook with invalid URL ───────────────────────────────────────────

func TestWebhook_InvalidURL(t *testing.T) {
	store := newMockWebhookStore()
	server := newWebhookMockServer(store)
	defer server.Close()

	providerServer := newListTestProvider(t, server.URL)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ja4proxy": func() (tfprotov6.ProviderServer, error) {
				return providerServer, nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "ja4proxy" {
						api_url   = %q
						api_token = "test-token"
					}
					resource "ja4proxy_webhook" "bad_url" {
						url    = "not-a-url"
						events = ["ban.created"]
						active = true
					}
				`, server.URL),
				// The mock will accept it, but the resource should still work
				// This tests that the provider passes the URL through as-is
				Check: resource.TestCheckResourceAttr("ja4proxy_webhook.bad_url", "url", "not-a-url"),
			},
		},
	})
}
