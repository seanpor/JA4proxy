package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// ── Mock server for list resources ───────────────────────────────────────────

type mockListStore struct {
	mu      sync.Mutex
	entries map[string]map[string]interface{} // list_name -> id -> entry
	nextID  int
}

func newMockListStore() *mockListStore {
	return &mockListStore{
		entries: make(map[string]map[string]interface{}),
	}
}

func (s *mockListStore) create(listName, entry, managedBy, note string, expiresAt interface{}) map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.entries[listName] == nil {
		s.entries[listName] = make(map[string]interface{})
	}

	// Check for duplicate
	for id, existing := range s.entries[listName] {
		existingMap := existing.(map[string]interface{})
		if existingMap["entry"] == entry {
			return existingMap
		}
		_ = id
	}

	s.nextID++
	resourceID := fmt.Sprintf("550e8400-e29b-41d4-a716-44665544%06d", s.nextID)
	entryObj := map[string]interface{}{
		"id":         resourceID,
		"entry":      entry,
		"list_type":  listName,
		"managed_by": managedBy,
		"note":       note,
		"created_at": "2026-01-01T00:00:00Z",
		"created_by": "terraform",
		"expires_at": expiresAt,
	}
	s.entries[listName][resourceID] = entryObj
	return entryObj
}

func (s *mockListStore) get(listName, id string) (map[string]interface{}, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if listEntries, ok := s.entries[listName]; ok {
		entry, ok := listEntries[id]
		return entry.(map[string]interface{}), ok
	}
	return nil, false
}

func (s *mockListStore) list(listName string) []map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]map[string]interface{}, 0)
	if listEntries, ok := s.entries[listName]; ok {
		for _, v := range listEntries {
			result = append(result, v.(map[string]interface{}))
		}
	}
	return result
}

func (s *mockListStore) delete(listName, id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if listEntries, ok := s.entries[listName]; ok {
		delete(listEntries, id)
		return true
	}
	return false
}

func newListMockServer(store *mockListStore) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"detail":"Invalid token"}`))
			return
		}

		// Health check
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/health" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok","redis":"ok","proxy_instances":1,"geoip":"ok","uptime_seconds":1.0}`))
			return
		}

		// GET /api/v1/allowlist, blocklist, watchlist
		if r.Method == http.MethodGet {
			for _, listName := range []string{"allowlist", "blocklist", "watchlist"} {
				if r.URL.Path == "/api/v1/"+listName {
					w.Header().Set("Content-Type", "application/json")
					entries := store.list(listName)
					resp := map[string]interface{}{
						"entries": entries,
						"count":   len(entries),
					}
					json.NewEncoder(w).Encode(resp)
					return
				}
				// GET /api/v1/{list}/{id}
				if strings.HasPrefix(r.URL.Path, "/api/v1/"+listName+"/") {
					id := strings.TrimPrefix(r.URL.Path, "/api/v1/"+listName+"/")
					w.Header().Set("Content-Type", "application/json")
					entry, ok := store.get(listName, id)
					if !ok {
						w.WriteHeader(http.StatusNotFound)
						json.NewEncoder(w).Encode(map[string]interface{}{"detail": "Resource not found"})
						return
					}
					json.NewEncoder(w).Encode(entry)
					return
				}
			}
		}

		// POST /api/v1/{list}
		if r.Method == http.MethodPost {
			for _, listName := range []string{"allowlist", "blocklist", "watchlist"} {
				if r.URL.Path == "/api/v1/"+listName {
					var body struct {
						Entry     string      `json:"entry"`
						ManagedBy string      `json:"managed_by"`
						Note      string      `json:"note"`
						ExpiresAt interface{} `json:"expires_at"`
					}
					json.NewDecoder(r.Body).Decode(&body)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusCreated)
					resp := store.create(listName, body.Entry, body.ManagedBy, body.Note, body.ExpiresAt)
					json.NewEncoder(w).Encode(resp)
					return
				}
			}
		}

		// DELETE /api/v1/{list}/{id}
		if r.Method == http.MethodDelete {
			for _, listName := range []string{"allowlist", "blocklist", "watchlist"} {
				if strings.HasPrefix(r.URL.Path, "/api/v1/"+listName+"/") {
					store.delete(listName, strings.TrimPrefix(r.URL.Path, "/api/v1/"+listName+"/"))
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
		}

		w.WriteHeader(http.StatusNotFound)
	}))
}

// ── Test: Create, Read, Delete allowlist_entry ────────────────────────────────

func TestAllowlistEntry_CreateReadDelete(t *testing.T) {
	store := newMockListStore()
	server := newListMockServer(store)
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
					resource "ja4proxy_allowlist_entry" "test" {
						entry      = "jarm:test123"
						managed_by = "terraform"
						note       = "Terraform managed"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ja4proxy_allowlist_entry.test", "entry", "jarm:test123"),
					resource.TestCheckResourceAttr("ja4proxy_allowlist_entry.test", "managed_by", "terraform"),
					resource.TestCheckResourceAttr("ja4proxy_allowlist_entry.test", "note", "Terraform managed"),
					resource.TestCheckResourceAttrSet("ja4proxy_allowlist_entry.test", "id"),
					resource.TestCheckResourceAttrSet("ja4proxy_allowlist_entry.test", "created_at"),
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

// ── Test: Import allowlist_entry ──────────────────────────────────────────────

func TestAllowlistEntry_Import(t *testing.T) {
	store := newMockListStore()
	// Pre-populate an entry to simulate an existing resource for import
	store.create("allowlist", "jarm:import-test", "terraform", "pre-existing", nil)

	server := newListMockServer(store)
	defer server.Close()

	providerServer := newListTestProvider(t, server.URL)

	// Get the ID of the pre-created entry
	entry := store.list("allowlist")[0]
	importID := entry["id"].(string)

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
					resource "ja4proxy_allowlist_entry" "imported" {
						entry = "PLACEHOLDER"
					}
				`, server.URL),
			},
			{
				ResourceName:                         "ja4proxy_allowlist_entry.imported",
				ImportState:                          true,
				ImportStateId:                        fmt.Sprintf("allowlist/%s", importID),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "id",
			},
		},
	})
}

// ── Test: allowlist_entry with expires_at ────────────────────────────────────

func TestAllowlistEntry_WithExpiresAt(t *testing.T) {
	store := newMockListStore()
	server := newListMockServer(store)
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
					resource "ja4proxy_allowlist_entry" "expiring" {
						entry      = "jarm:expiring-entry"
						managed_by = "terraform"
						note       = "Temporary allowlist entry"
						expires_at = "2027-12-31T23:59:59Z"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ja4proxy_allowlist_entry.expiring", "entry", "jarm:expiring-entry"),
					resource.TestCheckResourceAttr("ja4proxy_allowlist_entry.expiring", "expires_at", "2027-12-31T23:59:59Z"),
				),
			},
		},
	})
}

// ── Test: allowlist_entry duplicate is idempotent ─────────────────────────────

func TestAllowlistEntry_Idempotent(t *testing.T) {
	store := newMockListStore()
	server := newListMockServer(store)
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
					resource "ja4proxy_allowlist_entry" "dup" {
						entry      = "jarm:duplicate"
						managed_by = "terraform"
						note       = "first"
					}
				`, server.URL),
			},
			// Re-apply same config — should be no-op (idempotent)
			{
				Config: fmt.Sprintf(`
					provider "ja4proxy" {
						api_url   = %q
						api_token = "test-token"
					}
					resource "ja4proxy_allowlist_entry" "dup" {
						entry      = "jarm:duplicate"
						managed_by = "terraform"
						note       = "first"
					}
				`, server.URL),
				PlanOnly: true,
			},
		},
	})
}

// ── Helper ────────────────────────────────────────────────────────────────────

func newListTestProvider(t *testing.T, apiURL string) tfprotov6.ProviderServer {
	t.Helper()
	provider := New("test")()
	serverFn := providerserver.NewProtocol6WithError(provider)
	server, err := serverFn()
	if err != nil {
		t.Fatalf("serverFn() error = %v", err)
	}

	configureReq := &tfprotov6.ConfigureProviderRequest{
		Config: testConfigValue2(t, map[string]interface{}{
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

func testConfigValue2(t *testing.T, attrs map[string]interface{}) *tfprotov6.DynamicValue {
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
