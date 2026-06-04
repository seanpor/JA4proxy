package main

import (
	"context"
	"encoding/json"
	"github.com/seanpor/ja4proxy/internal/config"
	"github.com/sirupsen/logrus"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func init() {
	os.Setenv("JA4PROXY_TEST_ALLOW_INSECURE_NETBOX", "true")
}

func TestReloadTrustedCIDRs_NetBoxEnabled(t *testing.T) {
	// 1. Mock NetBox
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"results": []map[string]string{
				{"prefix": "10.0.0.0/8"},
				{"prefix": "192.168.0.0/16"},
			},
			"next": nil,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	// 2. Setup Proxy
	cfg := &config.Config{}
	cfg.TrustedUpstreamSources.NetBox.Enabled = true
	cfg.TrustedUpstreamSources.NetBox.URL = srv.URL
	cfg.TrustedUpstreamSources.NetBox.Token = "test"
	cfg.TrustedUpstreamSources.NetBox.Tag = "ja4"
	cfg.TrustedUpstreamSources.StaticCIDRs = []string{"172.16.0.0/12"}

	p := &proxy{
		cfg: cfg,
		log: logrus.New(),
	}

	// 3. Reload
	p.reloadTrustedCIDRs(context.Background(), cfg)

	// 4. Verify
	cidrs := p.getTrustedCIDRs()
	if len(cidrs) != 3 {
		t.Errorf("len(cidrs) = %d, want 3; got %v", len(cidrs), cidrs)
	}
}

func TestReloadTrustedCIDRs_NetBoxDisabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.TrustedUpstreamSources.NetBox.Enabled = false
	cfg.TrustedUpstreamSources.StaticCIDRs = []string{"1.1.1.1/32"}

	p := &proxy{
		cfg: cfg,
		log: logrus.New(),
	}

	p.reloadTrustedCIDRs(context.Background(), cfg)

	cidrs := p.getTrustedCIDRs()
	if len(cidrs) != 1 || cidrs[0] != "1.1.1.1/32" {
		t.Errorf("got %v, want [1.1.1.1/32]", cidrs)
	}
}
