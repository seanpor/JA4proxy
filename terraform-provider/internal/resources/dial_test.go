package resources

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// ── Mock dial store ──────────────────────────────────────────────────────────

type mockDialStore struct {
	mu        sync.Mutex
	value     int
	updatedAt string
}

func newMockDialStore() *mockDialStore {
	return &mockDialStore{value: 0}
}

func newDialMockServer(store *mockDialStore) *httptest.Server {
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

		// GET /api/v1/dial
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/dial" {
			store.mu.Lock()
			val := store.value
			store.mu.Unlock()
			resp := fmt.Sprintf(`{"value":%d,"updated_at":null}`, val)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(resp))
			return
		}

		// PATCH /api/v1/dial
		if r.Method == http.MethodPatch && r.URL.Path == "/api/v1/dial" {
			var body struct {
				Value int `json:"value"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"detail":"invalid json"}`))
				return
			}
			store.mu.Lock()
			store.value = body.Value
			store.updatedAt = "2026-04-09T12:00:00Z"
			store.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf(`{"value":%d,"updated_at":"2026-04-09T12:00:00Z"}`, body.Value)))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
}

// ── Test: Set and read dial value ────────────────────────────────────────────

func TestDial_SetAndRead(t *testing.T) {
	store := newMockDialStore()
	server := newDialMockServer(store)
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
					resource "ja4proxy_dial" "test" {
						value = 30
					}
				`, server.URL),
				Check: resource.TestCheckResourceAttr("ja4proxy_dial.test", "value", "30"),
			},
		},
	})
}

// ── Test: Max change of 10 ───────────────────────────────────────────────────

func TestDial_MaxChange10(t *testing.T) {
	store := newMockDialStore()
	// Pre-set dial to 50 so that a jump to 80 exceeds the 10-delta limit
	store.value = 50

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		// GET /api/v1/dial
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/dial" {
			store.mu.Lock()
			val := store.value
			store.mu.Unlock()
			resp := fmt.Sprintf(`{"value":%d,"updated_at":null}`, val)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(resp))
			return
		}

		// PATCH /api/v1/dial — reject delta > 10
		if r.Method == http.MethodPatch && r.URL.Path == "/api/v1/dial" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"detail":"Dial change of 50 exceeds the maximum of 10 per request. Current value: 50, requested: 100. Make multiple smaller changes."}`))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	providerServer := newListTestProvider(t, server.URL)

	// The provider should detect the 400 and report a proper error
	// when Terraform tries to apply a value that exceeds the delta
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
					resource "ja4proxy_dial" "big_jump" {
						value = 100
					}
				`, server.URL),
				ExpectError: regexp.MustCompile(`(?i)(delta|change|exceeds|maximum|400)`),
			},
		},
	})
}

// ── Test: Singleton — only one dial resource allowed ─────────────────────────

func TestDial_Singleton(t *testing.T) {
	store := newMockDialStore()
	server := newDialMockServer(store)
	defer server.Close()

	providerServer := newListTestProvider(t, server.URL)

	// Two ja4proxy_dial resources should not be allowed — dial is a singleton
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
					resource "ja4proxy_dial" "first" {
						value = 20
					}
					resource "ja4proxy_dial" "second" {
						value = 30
					}
				`, server.URL),
				ExpectError: regexp.MustCompile(`(?i)(singleton|only one|already exists|multiple)`),
			},
		},
	})
}

// ── Test: Dial update from existing value ────────────────────────────────────

func TestDial_UpdateWithinDelta(t *testing.T) {
	store := newMockDialStore()
	store.value = 30

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"detail":"Invalid token"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/health" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok","redis":"ok","proxy_instances":1,"geoip":"ok","uptime_seconds":1.0}`))
			return
		}

		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/dial" {
			store.mu.Lock()
			val := store.value
			store.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf(`{"value":%d,"updated_at":null}`, val)))
			return
		}

		if r.Method == http.MethodPatch && r.URL.Path == "/api/v1/dial" {
			var body struct {
				Value int `json:"value"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"detail":"invalid json"}`))
				return
			}
			store.mu.Lock()
			store.value = body.Value
			store.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf(`{"value":%d,"updated_at":"2026-01-01T00:00:00Z"}`, body.Value)))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
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
					resource "ja4proxy_dial" "update" {
						value = 40
					}
				`, server.URL),
				Check: resource.TestCheckResourceAttr("ja4proxy_dial.update", "value", "40"),
			},
		},
	})
}

// ── Test: Dial boundary values ───────────────────────────────────────────────

func TestDial_BoundaryValues(t *testing.T) {
	store := newMockDialStore()
	server := newDialMockServer(store)
	defer server.Close()

	providerServer := newListTestProvider(t, server.URL)

	// Test min value (0)
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
					resource "ja4proxy_dial" "min" {
						value = 0
					}
				`, server.URL),
				Check: resource.TestCheckResourceAttr("ja4proxy_dial.min", "value", "0"),
			},
		},
	})
}

func TestDial_MaxValue(t *testing.T) {
	store := newMockDialStore()
	server := newDialMockServer(store)
	defer server.Close()

	providerServer := newListTestProvider(t, server.URL)

	// Test max value (100)
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
					resource "ja4proxy_dial" "max" {
						value = 100
					}
				`, server.URL),
				Check: resource.TestCheckResourceAttr("ja4proxy_dial.max", "value", "100"),
			},
		},
	})
}
