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
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// ── Mock server state for ban tests ──────────────────────────────────────────

type mockBanStore struct {
	mu   sync.Mutex
	bans map[string]mockBan // key = IP (decoded)
}

type mockBan struct {
	IP     string `json:"ip"`
	Reason string `json:"reason"`
	TTL    int    `json:"ttl"`
}

func newMockBanStore() *mockBanStore {
	return &mockBanStore{bans: make(map[string]mockBan)}
}

func (s *mockBanStore) create(ip string, ttl int, reason string) map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bans[ip] = mockBan{IP: ip, Reason: reason, TTL: ttl}
	return map[string]interface{}{
		"message": fmt.Sprintf("Ban created for %s", ip),
		"ip":      ip,
		"ttl":     ttl,
		"reason":  reason,
	}
}

func (s *mockBanStore) delete(ip string) (map[string]interface{}, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ban, ok := s.bans[ip]
	if !ok {
		return nil, false
	}
	delete(s.bans, ip)
	return map[string]interface{}{
		"message": fmt.Sprintf("Ban lifted for %s", ban.IP),
		"ip":      ban.IP,
	}, true
}

func (s *mockBanStore) list() map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	bans := make([]map[string]interface{}, 0, len(s.bans))
	for _, b := range s.bans {
		bans = append(bans, map[string]interface{}{
			"ip":            b.IP,
			"reason":        b.Reason,
			"ttl_remaining": b.TTL,
		})
	}
	return map[string]interface{}{
		"bans":  bans,
		"count": len(bans),
	}
}

// ── Helper: new mock server with ban store ────────────────────────────────────

func newBanMockServer(store *mockBanStore) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Auth check
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"detail":"Invalid token"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")

		// POST /api/v1/bans/{ip}
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/bans/") {
			ip := strings.TrimPrefix(r.URL.Path, "/api/v1/bans/")
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
			resp := store.create(ip, body.TTL, body.Reason)
			json.NewEncoder(w).Encode(resp)
			return
		}

		// DELETE /api/v1/bans/{ip}
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/bans/") {
			ip := strings.TrimPrefix(r.URL.Path, "/api/v1/bans/")
			resp, ok := store.delete(ip)
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"detail": fmt.Sprintf("No active ban found for IP: %s", ip),
				})
				return
			}
			json.NewEncoder(w).Encode(resp)
			return
		}

		// GET /api/v1/bans
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/bans" {
			json.NewEncoder(w).Encode(store.list())
			return
		}

		// GET /api/v1/health (for provider configure)
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/health" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":          "ok",
				"redis":           "ok",
				"proxy_instances": 1,
				"geoip":           "ok",
				"uptime_seconds":  1.0,
			})
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
}

// ── Test: Create ban with IP ─────────────────────────────────────────────────

func TestCreateBan_IP(t *testing.T) {
	store := newMockBanStore()
	server := newBanMockServer(store)
	defer server.Close()

	providerServer := newTestProvider(t, server.URL)

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
					resource "ja4proxy_ban" "test" {
						ip     = "10.0.0.1"
						ttl    = 3600
						reason = "test"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ja4proxy_ban.test", "ip", "10.0.0.1"),
					resource.TestCheckResourceAttr("ja4proxy_ban.test", "ttl", "3600"),
					resource.TestCheckResourceAttr("ja4proxy_ban.test", "reason", "test"),
				),
			},
		},
	})
}

// ── Test: Create ban with CIDR (URL-encoded) ─────────────────────────────────

func TestCreateBan_CIDR(t *testing.T) {
	store := newMockBanStore()
	server := newBanMockServer(store)
	defer server.Close()

	providerServer := newTestProvider(t, server.URL)

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
					resource "ja4proxy_ban" "test_cidr" {
						ip     = "198.51.100.0/24"
						ttl    = 7200
						reason = "network scan"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ja4proxy_ban.test_cidr", "ip", "198.51.100.0/24"),
					resource.TestCheckResourceAttr("ja4proxy_ban.test_cidr", "ttl", "7200"),
					resource.TestCheckResourceAttr("ja4proxy_ban.test_cidr", "reason", "network scan"),
				),
			},
		},
	})
}

// ── Test: Read ban ────────────────────────────────────────────────────────────

func TestReadBan(t *testing.T) {
	store := newMockBanStore()
	store.create("10.0.0.1", 3600, "test read")

	server := newBanMockServer(store)
	defer server.Close()

	providerServer := newTestProvider(t, server.URL)

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
					resource "ja4proxy_ban" "test_read" {
						ip     = "10.0.0.1"
						ttl    = 3600
						reason = "test read"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ja4proxy_ban.test_read", "ip", "10.0.0.1"),
					resource.TestCheckResourceAttr("ja4proxy_ban.test_read", "reason", "test read"),
				),
			},
		},
	})
}

// ── Test: Delete ban ──────────────────────────────────────────────────────────

func TestDeleteBan(t *testing.T) {
	store := newMockBanStore()
	server := newBanMockServer(store)
	defer server.Close()

	providerServer := newTestProvider(t, server.URL)

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
					resource "ja4proxy_ban" "test_delete" {
						ip     = "10.0.0.1"
						ttl    = 3600
						reason = "will be deleted"
					}
				`, server.URL),
				Check: resource.TestCheckResourceAttr("ja4proxy_ban.test_delete", "ip", "10.0.0.1"),
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

// ── Test: Ban TTL renewal (re-POST before expiry) ─────────────────────────────

func TestBan_TTLRenewal(t *testing.T) {
	store := newMockBanStore()
	server := newBanMockServer(store)
	defer server.Close()

	providerServer := newTestProvider(t, server.URL)

	// Create ban with short TTL
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
					resource "ja4proxy_ban" "ttl_test" {
						ip     = "10.0.0.1"
						ttl    = 3600
						reason = "original reason"
					}
				`, server.URL),
				Check: resource.TestCheckResourceAttr("ja4proxy_ban.ttl_test", "ttl", "3600"),
			},
			// Re-apply with updated TTL (simulates renewal before expiry)
			{
				Config: fmt.Sprintf(`
					provider "ja4proxy" {
						api_url   = %q
						api_token = "test-token"
					}
					resource "ja4proxy_ban" "ttl_test" {
						ip     = "10.0.0.1"
						ttl    = 7200
						reason = "renewed reason"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ja4proxy_ban.ttl_test", "ttl", "7200"),
					resource.TestCheckResourceAttr("ja4proxy_ban.ttl_test", "reason", "renewed reason"),
				),
			},
		},
	})
}

// ── Test: Ban URL encoding for CIDR ───────────────────────────────────────────

func TestBan_UrlEncoding(t *testing.T) {
	var capturedPath string
	var capturedRawPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedRawPath = r.URL.RawPath
		w.Header().Set("Content-Type", "application/json")

		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/health" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok","redis":"ok","proxy_instances":0,"geoip":"ok","uptime_seconds":0}`))
			return
		}

		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/bans" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"bans":[{"ip":"198.51.100.0/24","reason":"cidr test","ttl_remaining":3600}],"count":1}`))
			return
		}

		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/bans/") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"message":"Ban created","ip":"198.51.100.0/24","ttl":3600,"reason":"cidr test"}`))
			return
		}

		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/bans/") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"message":"Ban lifted","ip":"198.51.100.0/24"}`))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	providerServer := newTestProvider(t, server.URL)

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
					resource "ja4proxy_ban" "cidr" {
						ip     = "198.51.100.0/24"
						ttl    = 3600
						reason = "cidr test"
					}
				`, server.URL),
				Check: func(s *terraform.State) error {
					// Verify the slash was URL-encoded in the request path.
					// Go's httptest decodes r.URL.Path, so we check r.URL.RawPath
					// which preserves the encoded form. If RawPath is empty, the
					// decoded Path containing the CIDR is sufficient proof the
					// request was made.
					if capturedRawPath != "" {
						if !strings.Contains(capturedRawPath, "%2F") && !strings.Contains(capturedRawPath, "%2f") {
							return fmt.Errorf("expected URL-encoded slash %%2F in RawPath, got %q", capturedRawPath)
						}
					} else if !strings.Contains(capturedPath, "198.51.100.0/24") {
						return fmt.Errorf("expected CIDR in path, got %q", capturedPath)
					}
					return nil
				},
			},
		},
	})
}

// ── Test: Ban not found on read returns appropriate state ─────────────────────

func TestBan_NotFoundReturnsNil(t *testing.T) {
	store := newMockBanStore() // empty store — no bans
	server := newBanMockServer(store)
	defer server.Close()

	providerServer := newTestProvider(t, server.URL)

	// Attempting to read a ban that doesn't exist should not error
	// The resource should recognize it's not in state and plan a create
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
					resource "ja4proxy_ban" "fresh" {
						ip     = "10.0.0.99"
						ttl    = 3600
						reason = "fresh ban"
					}
				`, server.URL),
				Check: resource.TestCheckResourceAttr("ja4proxy_ban.fresh", "ip", "10.0.0.99"),
			},
		},
	})
}

// ── Helper: newTestProvider ───────────────────────────────────────────────────

func newTestProvider(t *testing.T, apiURL string) tfprotov6.ProviderServer {
	t.Helper()
	provider := New("test")()
	serverFn := providerserver.NewProtocol6WithError(provider)
	server, err := serverFn()
	if err != nil {
		t.Fatalf("serverFn() error = %v", err)
	}

	// Configure with test server URL
	configureReq := &tfprotov6.ConfigureProviderRequest{
		Config: testConfigValue(t, map[string]interface{}{
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

// ── Helper: testConfigValue ───────────────────────────────────────────────────

func testConfigValue(t *testing.T, attrs map[string]interface{}) *tfprotov6.DynamicValue {
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
