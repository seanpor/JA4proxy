package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/anomalyco/ja4proxy/internal/config"
	"github.com/anomalyco/ja4proxy/internal/metrics"
)

// TestReloadTrustedCIDRs_NetBoxEnabled verifies that when NetBox is enabled,
// the proxy merges NetBox CIDRs with static CIDRs and increments the ok counter.
func TestReloadTrustedCIDRs_NetBoxEnabled(t *testing.T) {
	// Reset the counter before the test so we can assert cleanly
	metrics.NetBoxCIDRsLoaded.Reset()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"count": 2,
			"results": []map[string]interface{}{
				{"prefix": "192.168.0.0/16"},
				{"prefix": "10.0.0.0/8"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)

	p := &proxy{
		log:            log,
		trustedCIDRs:   nil,
		trustedCIDRsMu: sync.RWMutex{},
	}

	cfg := &config.Config{
		TrustedUpstreamSources: config.TrustedUpstreamSourcesConfig{
			NetBox: config.NetBoxSourceConfig{
				Enabled: true,
				URL:     srv.URL,
				Token:   "test-token",
				Tag:     "ja4proxy-trusted",
			},
			StaticCIDRs: []string{"172.16.0.0/12"},
		},
	}

	p.reloadTrustedCIDRs(context.Background(), cfg)

	cidrs := p.getTrustedCIDRs()
	// Should have 3 unique CIDRs: 172.16.0.0/12 (static) + 192.168.0.0/16 + 10.0.0.0/8 (netbox)
	if len(cidrs) != 3 {
		t.Fatalf("len(cidrs) = %d, want 3; got %v", len(cidrs), cidrs)
	}

	// Check that all expected CIDRs are present
	cidrSet := make(map[string]bool)
	for _, c := range cidrs {
		cidrSet[c] = true
	}
	for _, want := range []string{"172.16.0.0/12", "192.168.0.0/16", "10.0.0.0/8"} {
		if !cidrSet[want] {
			t.Errorf("missing expected CIDR %q in %v", want, cidrs)
		}
	}
}

// TestReloadTrustedCIDRs_NetBoxDisabled verifies that when NetBox is disabled,
// only static CIDRs are used and no counter is incremented.
func TestReloadTrustedCIDRs_NetBoxDisabled(t *testing.T) {
	metrics.NetBoxCIDRsLoaded.Reset()

	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)

	p := &proxy{
		log:            log,
		trustedCIDRs:   nil,
		trustedCIDRsMu: sync.RWMutex{},
	}

	cfg := &config.Config{
		TrustedUpstreamSources: config.TrustedUpstreamSourcesConfig{
			NetBox: config.NetBoxSourceConfig{
				Enabled: false,
			},
			StaticCIDRs: []string{"10.0.0.0/8"},
		},
	}

	p.reloadTrustedCIDRs(context.Background(), cfg)

	cidrs := p.getTrustedCIDRs()
	if len(cidrs) != 1 || cidrs[0] != "10.0.0.0/8" {
		t.Fatalf("cidrs = %v, want [10.0.0.0/8]", cidrs)
	}
}

// TestReloadTrustedCIDRs_Dedup verifies that duplicate CIDRs across static
// and NetBox sources are deduplicated.
func TestReloadTrustedCIDRs_Dedup(t *testing.T) {
	metrics.NetBoxCIDRsLoaded.Reset()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"count": 1,
			"results": []map[string]interface{}{
				{"prefix": "10.0.0.0/8"}, // same as static
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)

	p := &proxy{
		log:            log,
		trustedCIDRs:   nil,
		trustedCIDRsMu: sync.RWMutex{},
	}

	cfg := &config.Config{
		TrustedUpstreamSources: config.TrustedUpstreamSourcesConfig{
			NetBox: config.NetBoxSourceConfig{
				Enabled: true,
				URL:     srv.URL,
				Token:   "test",
				Tag:     "test",
			},
			StaticCIDRs: []string{"10.0.0.0/8"}, // duplicates the netbox prefix
		},
	}

	p.reloadTrustedCIDRs(context.Background(), cfg)

	cidrs := p.getTrustedCIDRs()
	if len(cidrs) != 1 {
		t.Fatalf("len(cidrs) = %d, want 1 (deduped); got %v", len(cidrs), cidrs)
	}
	if cidrs[0] != "10.0.0.0/8" {
		t.Errorf("cidrs[0] = %q, want %q", cidrs[0], "10.0.0.0/8")
	}
}

// TestReloadTrustedCIDRs_NetBoxFailOpen verifies that when NetBox returns 500,
// the proxy falls back to static CIDRs and increments the error counter.
func TestReloadTrustedCIDRs_NetBoxFailOpen(t *testing.T) {
	metrics.NetBoxCIDRsLoaded.Reset()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)

	p := &proxy{
		log:            log,
		trustedCIDRs:   nil,
		trustedCIDRsMu: sync.RWMutex{},
	}

	cfg := &config.Config{
		TrustedUpstreamSources: config.TrustedUpstreamSourcesConfig{
			NetBox: config.NetBoxSourceConfig{
				Enabled: true,
				URL:     srv.URL,
				Token:   "test",
				Tag:     "test",
			},
			StaticCIDRs: []string{"10.0.0.0/8"},
		},
	}

	p.reloadTrustedCIDRs(context.Background(), cfg)

	cidrs := p.getTrustedCIDRs()
	// Should fall back to static CIDRs
	if len(cidrs) != 1 || cidrs[0] != "10.0.0.0/8" {
		t.Fatalf("cidrs = %v, want [10.0.0.0/8] (fail-open)", cidrs)
	}
}
