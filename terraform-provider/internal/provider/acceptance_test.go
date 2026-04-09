package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// ── ManagementAPI Mock ───────────────────────────────────────────────────────
//
// This mock implements the full Management API contract used by the Terraform
// provider, enabling acceptance tests without a running Management API instance.

// managementAPIMock implements all endpoints the provider calls.
type managementAPIMock struct {
	mu sync.Mutex

	// Bans: ip -> {ttl, reason}
	bans map[string]mockBanEntry

	// Canonical lists: listName -> id -> entry
	lists map[string]map[string]mockListEntry

	// Dial
	dialValue     int
	dialUpdatedAt string

	// Webhooks: id -> webhook
	webhooks map[string]mockWebhookEntry

	// Counter for generating stable IDs
	banCount     int
	listCount    int
	webhookCount int
}

type mockBanEntry struct {
	IP     string `json:"ip"`
	Reason string `json:"reason"`
	TTL    int    `json:"ttl"`
}

type mockListEntry struct {
	ID        string  `json:"id"`
	Entry     string  `json:"entry"`
	ListType  string  `json:"list_type"`
	ManagedBy string  `json:"managed_by"`
	Note      string  `json:"note"`
	CreatedAt string  `json:"created_at"`
	CreatedBy string  `json:"created_by"`
	ExpiresAt *string `json:"expires_at"`
}

type mockWebhookEntry struct {
	ID        string   `json:"id"`
	URL       string   `json:"url"`
	Events    []string `json:"events"`
	Active    bool     `json:"active"`
	CreatedAt string   `json:"created_at"`
	ManagedBy string   `json:"managed_by"`
	Secret    string   `json:"secret,omitempty"` // only on create response
}

func newManagementAPIMock() *managementAPIMock {
	m := &managementAPIMock{
		bans:      make(map[string]mockBanEntry),
		lists:     make(map[string]map[string]mockListEntry),
		webhooks:  make(map[string]mockWebhookEntry),
		dialValue: 0,
	}
	m.lists["allowlist"] = make(map[string]mockListEntry)
	m.lists["blocklist"] = make(map[string]mockListEntry)
	m.lists["watchlist"] = make(map[string]mockListEntry)
	return m
}

func (m *managementAPIMock) handler() http.Handler {
	mux := http.NewServeMux()

	// Health
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":          "ok",
			"redis":           "ok",
			"proxy_instances": 1,
			"geoip":           "ok",
			"uptime_seconds":  100.0,
		})
	})

	// ── Bans ─────────────────────────────────────────────────────────────

	mux.HandleFunc("/api/v1/bans/", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		ip := strings.TrimPrefix(r.URL.Path, "/api/v1/bans/")

		switch r.Method {
		case http.MethodPost:
			var body struct {
				TTL    int    `json:"ttl"`
				Reason string `json:"reason"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			if body.TTL == 0 {
				body.TTL = 3600
			}
			if body.Reason == "" {
				body.Reason = "manual"
			}
			m.banCount++
			m.bans[ip] = mockBanEntry{IP: ip, Reason: body.Reason, TTL: body.TTL}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": fmt.Sprintf("Ban created for %s", ip),
				"ip":      ip,
				"ttl":     body.TTL,
				"reason":  body.Reason,
			})

		case http.MethodDelete:
			_, ok := m.bans[ip]
			if !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"detail": fmt.Sprintf("No active ban found for IP: %s", ip),
				})
				return
			}
			delete(m.bans, ip)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": fmt.Sprintf("Ban lifted for %s", ip),
				"ip":      ip,
			})
		}
	})

	mux.HandleFunc("/api/v1/bans", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		bans := make([]map[string]interface{}, 0, len(m.bans))
		for _, b := range m.bans {
			bans = append(bans, map[string]interface{}{
				"ip":            b.IP,
				"reason":        b.Reason,
				"ttl_remaining": b.TTL,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"bans":  bans,
			"count": len(bans),
		})
	})

	// ── Canonical lists ──────────────────────────────────────────────────

	for _, listName := range []string{"allowlist", "blocklist", "watchlist"} {
		ln := listName
		mux.HandleFunc("/api/v1/"+ln+"/", func(w http.ResponseWriter, r *http.Request) {
			m.mu.Lock()
			defer m.mu.Unlock()

			id := strings.TrimPrefix(r.URL.Path, "/api/v1/"+ln+"/")

			switch r.Method {
			case http.MethodGet:
				entry, ok := m.lists[ln][id]
				if !ok {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusNotFound)
					json.NewEncoder(w).Encode(map[string]interface{}{"detail": "Resource not found"})
					return
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(entry)

			case http.MethodDelete:
				delete(m.lists[ln], id)
				w.WriteHeader(http.StatusNoContent)
			}
		})

		mux.HandleFunc("/api/v1/"+ln, func(w http.ResponseWriter, r *http.Request) {
			m.mu.Lock()
			defer m.mu.Unlock()

			switch r.Method {
			case http.MethodGet:
				entries := make([]mockListEntry, 0, len(m.lists[ln]))
				for _, e := range m.lists[ln] {
					entries = append(entries, e)
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"entries": entries,
					"count":   len(entries),
				})

			case http.MethodPost:
				var body struct {
					Entry     string  `json:"entry"`
					ManagedBy string  `json:"managed_by"`
					Note      string  `json:"note"`
					ExpiresAt *string `json:"expires_at"`
				}
				json.NewDecoder(r.Body).Decode(&body)

				// Check duplicate
				for _, existing := range m.lists[ln] {
					if existing.Entry == body.Entry {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusOK)
						json.NewEncoder(w).Encode(existing)
						return
					}
				}

				m.listCount++
				resourceID := fmt.Sprintf("550e8400-e29b-41d4-a716-44665544%06d", m.listCount)
				entry := mockListEntry{
					ID:        resourceID,
					Entry:     body.Entry,
					ListType:  ln,
					ManagedBy: body.ManagedBy,
					Note:      body.Note,
					CreatedAt: "2026-01-01T00:00:00Z",
					CreatedBy: "terraform",
					ExpiresAt: body.ExpiresAt,
				}
				m.lists[ln][resourceID] = entry
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(entry)
			}
		})
	}

	// ── Dial ─────────────────────────────────────────────────────────────

	mux.HandleFunc("/api/v1/dial", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"value":      m.dialValue,
				"updated_at": m.dialUpdatedAt,
			})

		case http.MethodPatch, http.MethodPut:
			var body struct {
				Value int `json:"value"`
			}
			json.NewDecoder(r.Body).Decode(&body)

			delta := body.Value - m.dialValue
			if delta < 0 {
				delta = -delta
			}
			if delta > 10 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"detail": fmt.Sprintf("Dial change of %d exceeds the maximum of 10 per request. Current value: %d, requested: %d. Make multiple smaller changes.", delta, m.dialValue, body.Value),
				})
				return
			}

			m.dialValue = body.Value
			m.dialUpdatedAt = "2026-01-01T00:00:00Z"
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"value":      body.Value,
				"updated_at": m.dialUpdatedAt,
			})
		}
	})

	// ── Webhooks ─────────────────────────────────────────────────────────

	mux.HandleFunc("/api/v1/webhooks/", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		id := strings.TrimPrefix(r.URL.Path, "/api/v1/webhooks/")

		switch r.Method {
		case http.MethodGet:
			wh, ok := m.webhooks[id]
			if !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]interface{}{"detail": "Webhook not found"})
				return
			}
			// Return without secret
			resp := map[string]interface{}{
				"id":         wh.ID,
				"url":        wh.URL,
				"events":     wh.Events,
				"active":     wh.Active,
				"created_at": wh.CreatedAt,
				"managed_by": wh.ManagedBy,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case http.MethodPut:
			wh, ok := m.webhooks[id]
			if !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]interface{}{"detail": "Webhook not found"})
				return
			}
			var body struct {
				URL    string   `json:"url,omitempty"`
				Events []string `json:"events,omitempty"`
				Active *bool    `json:"active,omitempty"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			if body.URL != "" {
				wh.URL = body.URL
			}
			if body.Events != nil {
				wh.Events = body.Events
			}
			if body.Active != nil {
				wh.Active = *body.Active
			}
			m.webhooks[id] = wh
			resp := map[string]interface{}{
				"id":         wh.ID,
				"url":        wh.URL,
				"events":     wh.Events,
				"active":     wh.Active,
				"created_at": wh.CreatedAt,
				"managed_by": wh.ManagedBy,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case http.MethodDelete:
			delete(m.webhooks, id)
			w.WriteHeader(http.StatusNoContent)
		}
	})

	mux.HandleFunc("/api/v1/webhooks", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var body struct {
			URL    string   `json:"url"`
			Events []string `json:"events"`
			Active bool     `json:"active"`
		}
		json.NewDecoder(r.Body).Decode(&body)

		m.webhookCount++
		id := fmt.Sprintf("wh-%03d", m.webhookCount)
		wh := mockWebhookEntry{
			ID:        id,
			URL:       body.URL,
			Events:    body.Events,
			Active:    body.Active,
			CreatedAt: "2026-01-01T00:00:00Z",
			ManagedBy: "terraform",
			Secret:    fmt.Sprintf("whsec_acceptance_secret_%d", m.webhookCount),
		}
		m.webhooks[id] = wh

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(wh)
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r)
	})
}

// ── Acceptance Test: Full lifecycle ──────────────────────────────────────────

func TestAcc_Ban_FullLifecycle(t *testing.T) {
	mock := newManagementAPIMock()
	server := httptest.NewServer(mock.handler())
	defer server.Close()

	providerServer := newAccTestProvider(t, server.URL)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ja4proxy": func() (tfprotov6.ProviderServer, error) {
				return providerServer, nil
			},
		},
		Steps: []resource.TestStep{
			// Create
			{
				Config: fmt.Sprintf(`
					provider "ja4proxy" {
						api_url   = %q
						api_token = "test-token"
					}
					resource "ja4proxy_ban" "acc" {
						ip     = "10.0.0.50"
						ttl    = 7200
						reason = "[terraform] acceptance test ban"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ja4proxy_ban.acc", "ip", "10.0.0.50"),
					resource.TestCheckResourceAttr("ja4proxy_ban.acc", "ttl", "7200"),
					resource.TestCheckResourceAttr("ja4proxy_ban.acc", "reason", "[terraform] acceptance test ban"),
				),
			},
			// Update
			{
				Config: fmt.Sprintf(`
					provider "ja4proxy" {
						api_url   = %q
						api_token = "test-token"
					}
					resource "ja4proxy_ban" "acc" {
						ip     = "10.0.0.50"
						ttl    = 3600
						reason = "[terraform] updated reason"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ja4proxy_ban.acc", "ttl", "3600"),
					resource.TestCheckResourceAttr("ja4proxy_ban.acc", "reason", "[terraform] updated reason"),
				),
			},
			// Destroy
			{
				Config:  fmt.Sprintf(`provider "ja4proxy" {
    api_url   = %q
    api_token = "test-token"
  }`, server.URL),
				Destroy: true,
			},
		},
	})

	// Verify ban was actually deleted from the mock
	mock.mu.Lock()
	defer mock.mu.Unlock()
	if _, exists := mock.bans["10.0.0.50"]; exists {
		t.Error("Ban should have been deleted after destroy step")
	}
}

func TestAcc_AllowlistEntry_FullLifecycle(t *testing.T) {
	mock := newManagementAPIMock()
	server := httptest.NewServer(mock.handler())
	defer server.Close()

	providerServer := newAccTestProvider(t, server.URL)

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
					resource "ja4proxy_allowlist_entry" "acc" {
						entry      = "jarm:acc-test-fingerprint"
						managed_by = "terraform"
						note       = "Acceptance test entry"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ja4proxy_allowlist_entry.acc", "entry", "jarm:acc-test-fingerprint"),
					resource.TestCheckResourceAttr("ja4proxy_allowlist_entry.acc", "managed_by", "terraform"),
					resource.TestCheckResourceAttr("ja4proxy_allowlist_entry.acc", "note", "Acceptance test entry"),
				),
			},
			{
				Config:  fmt.Sprintf(`provider "ja4proxy" {
    api_url   = %q
    api_token = "test-token"
  }`, server.URL),
				Destroy: true,
			},
		},
	})
}

func TestAcc_BlocklistEntry_FullLifecycle(t *testing.T) {
	mock := newManagementAPIMock()
	server := httptest.NewServer(mock.handler())
	defer server.Close()

	providerServer := newAccTestProvider(t, server.URL)

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
					resource "ja4proxy_blocklist_entry" "acc" {
						entry      = "jarm:acc-block-sig"
						managed_by = "terraform"
						note       = "Block this signature"
					}
				`, server.URL),
				Check: resource.TestCheckResourceAttr("ja4proxy_blocklist_entry.acc", "entry", "jarm:acc-block-sig"),
			},
			{
				Config:  fmt.Sprintf(`provider "ja4proxy" {
    api_url   = %q
    api_token = "test-token"
  }`, server.URL),
				Destroy: true,
			},
		},
	})
}

func TestAcc_WatchlistEntry_FullLifecycle(t *testing.T) {
	mock := newManagementAPIMock()
	server := httptest.NewServer(mock.handler())
	defer server.Close()

	providerServer := newAccTestProvider(t, server.URL)

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
					resource "ja4proxy_watchlist_entry" "acc" {
						entry      = "jarm:acc-watch-sig"
						managed_by = "terraform"
						note       = "Watch this fingerprint"
					}
				`, server.URL),
				Check: resource.TestCheckResourceAttr("ja4proxy_watchlist_entry.acc", "entry", "jarm:acc-watch-sig"),
			},
			{
				Config:  fmt.Sprintf(`provider "ja4proxy" {
    api_url   = %q
    api_token = "test-token"
  }`, server.URL),
				Destroy: true,
			},
		},
	})
}

func TestAcc_Dial_FullLifecycle(t *testing.T) {
	mock := newManagementAPIMock()
	server := httptest.NewServer(mock.handler())
	defer server.Close()

	providerServer := newAccTestProvider(t, server.URL)

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
					resource "ja4proxy_dial" "acc" {
						value = 5
					}
				`, server.URL),
				Check: resource.TestCheckResourceAttr("ja4proxy_dial.acc", "value", "5"),
			},
			{
				Config: fmt.Sprintf(`
					provider "ja4proxy" {
						api_url   = %q
						api_token = "test-token"
					}
					resource "ja4proxy_dial" "acc" {
						value = 10
					}
				`, server.URL),
				Check: resource.TestCheckResourceAttr("ja4proxy_dial.acc", "value", "10"),
			},
			// Attempt a big jump — should fail
			{
				Config: fmt.Sprintf(`
					provider "ja4proxy" {
						api_url   = %q
						api_token = "test-token"
					}
					resource "ja4proxy_dial" "acc" {
						value = 50
					}
				`, server.URL),
				ExpectError: regexp.MustCompile(`(?i)(delta|change|exceeds|maximum|400)`),
			},
		},
	})
}

func TestAcc_Webhook_FullLifecycle(t *testing.T) {
	mock := newManagementAPIMock()
	server := httptest.NewServer(mock.handler())
	defer server.Close()

	providerServer := newAccTestProvider(t, server.URL)

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
					resource "ja4proxy_webhook" "acc" {
						url    = "https://acc.example.com/hook"
						events = ["ban.created"]
						active = true
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ja4proxy_webhook.acc", "url", "https://acc.example.com/hook"),
					resource.TestCheckResourceAttr("ja4proxy_webhook.acc", "active", "true"),
					resource.TestCheckResourceAttrSet("ja4proxy_webhook.acc", "secret"),
				),
			},
			{
				Config: fmt.Sprintf(`
					provider "ja4proxy" {
						api_url   = %q
						api_token = "test-token"
					}
					resource "ja4proxy_webhook" "acc" {
						url    = "https://acc.example.com/updated"
						events = ["ban.created", "dial.changed"]
						active = false
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ja4proxy_webhook.acc", "url", "https://acc.example.com/updated"),
					resource.TestCheckResourceAttr("ja4proxy_webhook.acc", "active", "false"),
				),
			},
			{
				Config:  fmt.Sprintf(`provider "ja4proxy" {
    api_url   = %q
    api_token = "test-token"
  }`, server.URL),
				Destroy: true,
			},
		},
	})

	// Verify webhook was deleted
	mock.mu.Lock()
	defer mock.mu.Unlock()
	for id := range mock.webhooks {
		t.Errorf("Webhook %s should have been deleted after destroy step", id)
	}
}

func TestAcc_MultipleResources_Coexist(t *testing.T) {
	mock := newManagementAPIMock()
	server := httptest.NewServer(mock.handler())
	defer server.Close()

	providerServer := newAccTestProvider(t, server.URL)

	// Multiple resources of different types should coexist
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
					resource "ja4proxy_ban" "multi" {
						ip     = "10.0.0.99"
						ttl    = 3600
						reason = "[terraform] multi-test ban"
					}
					resource "ja4proxy_allowlist_entry" "multi" {
						entry      = "jarm:multi-test"
						managed_by = "terraform"
						note       = "Multi-test allowlist"
					}
					resource "ja4proxy_dial" "multi" {
						value = 10
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ja4proxy_ban.multi", "ip", "10.0.0.99"),
					resource.TestCheckResourceAttr("ja4proxy_allowlist_entry.multi", "entry", "jarm:multi-test"),
					resource.TestCheckResourceAttr("ja4proxy_dial.multi", "value", "10"),
				),
			},
		},
	})
}

// ── Import state verification ────────────────────────────────────────────────

func TestAcc_AllowlistEntry_ImportState(t *testing.T) {
	mock := newManagementAPIMock()
	// Pre-create an entry to import
	mock.mu.Lock()
	mock.listCount++
	resourceID := fmt.Sprintf("550e8400-e29b-41d4-a716-44665544%06d", mock.listCount)
	mock.lists["allowlist"][resourceID] = mockListEntry{
		ID:        resourceID,
		Entry:     "jarm:import-acceptance",
		ListType:  "allowlist",
		ManagedBy: "terraform",
		Note:      "Pre-existing entry for import test",
		CreatedAt: "2026-01-01T00:00:00Z",
		CreatedBy: "terraform",
	}
	mock.mu.Unlock()

	server := httptest.NewServer(mock.handler())
	defer server.Close()

	providerServer := newAccTestProvider(t, server.URL)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ja4proxy": func() (tfprotov6.ProviderServer, error) {
				return providerServer, nil
			},
		},
		Steps: []resource.TestStep{
			{
				// Config matching the pre-existing entry
				Config: fmt.Sprintf(`
					provider "ja4proxy" {
						api_url   = %q
						api_token = "test-token"
					}
					resource "ja4proxy_allowlist_entry" "imported" {
						entry      = "jarm:import-acceptance"
						managed_by = "terraform"
						note       = "Pre-existing entry for import test"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ja4proxy_allowlist_entry.imported", "entry", "jarm:import-acceptance"),
				),
			},
			{
				ResourceName:      "ja4proxy_allowlist_entry.imported",
				ImportState:       true,
				ImportStateId:     fmt.Sprintf("allowlist/%s", resourceID),
				ImportStateVerify: true,
			},
		},
	})
}

// ── Helper: newAccTestProvider ───────────────────────────────────────────────

func newAccTestProvider(t *testing.T, apiURL string) tfprotov6.ProviderServer {
	t.Helper()

	provider := New("test")()
	serverFn := providerserver.NewProtocol6WithError(provider)
	server, err := serverFn()
	if err != nil {
		t.Fatalf("serverFn() error = %v", err)
	}

	configureReq := &tfprotov6.ConfigureProviderRequest{
		Config: accTestConfigValue(t, map[string]interface{}{
			"api_url":   apiURL,
			"api_token": "test-token",
		}),
	}
	_, err = server.ConfigureProvider(context.Background(), configureReq)
	if err != nil {
		t.Fatalf("ConfigureProvider() error = %v", err)
	}

	return server
}

func accTestConfigValue(t *testing.T, attrs map[string]interface{}) *tfprotov6.DynamicValue {
	t.Helper()

	schema := map[string]tftypes.Type{
		"api_url":   tftypes.String,
		"api_token": tftypes.String,
	}

	vals := make(map[string]tftypes.Value)
	for k := range schema {
		if attrVal, ok := attrs[k]; ok && attrVal != nil {
			if s, ok := attrVal.(string); ok {
				vals[k] = tftypes.NewValue(tftypes.String, s)
			} else {
				vals[k] = tftypes.NewValue(tftypes.String, nil)
			}
		} else {
			vals[k] = tftypes.NewValue(tftypes.String, nil)
		}
	}

	objType := tftypes.Object{AttributeTypes: schema}
	objVal := tftypes.NewValue(objType, vals)

	dv, err := tfprotov6.NewDynamicValue(objType, objVal)
	if err != nil {
		t.Fatalf("failed to create DynamicValue: %v", err)
	}
	return &dv
}
