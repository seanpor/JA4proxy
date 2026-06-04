package proxy

import (
	"testing"

	"github.com/seanpor/ja4proxy/internal/config"
)

// TestIsTrustedProxySource_TrustedCIDR_IPv4 verifies that an IP matching
// a configured trusted CIDR returns true.
func TestIsTrustedProxySource_TrustedCIDR_IPv4(t *testing.T) {
	cfg := &config.Config{
		Proxy: config.ProxyConfig{
			ProxyProtocol: true,
			UpstreamTrust: config.UpstreamTrustConfig{
				Enabled:      true,
				TrustedCIDRs: []string{"10.0.0.0/8", "172.16.0.0/12"},
			},
		},
	}

	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", false}, // not in any trusted CIDR
		{"8.8.8.8", false},
	}

	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			got := IsTrustedProxySource(tc.ip, cfg)
			if got != tc.want {
				t.Errorf("IsTrustedProxySource(%q) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

// TestIsTrustedProxySource_TrustedCIDR_IPv6 verifies IPv6 CIDR matching.
func TestIsTrustedProxySource_TrustedCIDR_IPv6(t *testing.T) {
	cfg := &config.Config{
		Proxy: config.ProxyConfig{
			ProxyProtocol: true,
			UpstreamTrust: config.UpstreamTrustConfig{
				Enabled:      true,
				TrustedCIDRs: []string{"fd00::/8"},
			},
		},
	}

	cases := []struct {
		ip   string
		want bool
	}{
		{"fd00::1", true},
		{"fd00:abcd::1", true},
		{"::1", false},
		{"2001:db8::1", false},
	}

	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			got := IsTrustedProxySource(tc.ip, cfg)
			if got != tc.want {
				t.Errorf("IsTrustedProxySource(%q) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

// TestIsTrustedProxySource_EnabledFalse verifies that when
// upstream_trust.enabled is false, no IP is trusted — even if CIDRs match.
func TestIsTrustedProxySource_EnabledFalse(t *testing.T) {
	cfg := &config.Config{
		Proxy: config.ProxyConfig{
			ProxyProtocol: true,
			UpstreamTrust: config.UpstreamTrustConfig{
				Enabled:      false,
				TrustedCIDRs: []string{"0.0.0.0/0"}, // would match everything
			},
		},
	}

	if IsTrustedProxySource("10.0.0.1", cfg) {
		t.Error("IP should not be trusted when enabled=false")
	}
}

// TestIsTrustedProxySource_EmptyCIDRs verifies that an empty trusted_cidrs
// list returns false (fail-open: don't trust any source).
func TestIsTrustedProxySource_EmptyCIDRs(t *testing.T) {
	cfg := &config.Config{
		Proxy: config.ProxyConfig{
			ProxyProtocol: true,
			UpstreamTrust: config.UpstreamTrustConfig{
				Enabled:      true,
				TrustedCIDRs: []string{},
			},
		},
	}

	if IsTrustedProxySource("10.0.0.1", cfg) {
		t.Error("IP should not be trusted when trusted_cidrs is empty")
	}
}

// TestIsTrustedProxySource_NilConfig verifies that a nil config returns
// false without panicking.
func TestIsTrustedProxySource_NilConfig(t *testing.T) {
	if IsTrustedProxySource("10.0.0.1", nil) {
		t.Error("nil config should return false")
	}
}

// TestIsTrustedProxySource_InvalidIP verifies that an invalid IP string
// returns false without panicking.
func TestIsTrustedProxySource_InvalidIP(t *testing.T) {
	cfg := &config.Config{
		Proxy: config.ProxyConfig{
			ProxyProtocol: true,
			UpstreamTrust: config.UpstreamTrustConfig{
				Enabled:      true,
				TrustedCIDRs: []string{"10.0.0.0/8"},
			},
		},
	}

	invalidIPs := []string{
		"not-an-ip",
		"999.999.999.999",
		"",
		" ",
	}

	for _, ip := range invalidIPs {
		t.Run(ip, func(t *testing.T) {
			if IsTrustedProxySource(ip, cfg) {
				t.Errorf("IsTrustedProxySource(%q) should return false for invalid IP", ip)
			}
		})
	}
}

// TestIsTrustedProxySource_InvalidCIDR verifies that a malformed CIDR
// in the config is skipped rather than causing a panic (fail-open).
func TestIsTrustedProxySource_InvalidCIDR(t *testing.T) {
	cfg := &config.Config{
		Proxy: config.ProxyConfig{
			ProxyProtocol: true,
			UpstreamTrust: config.UpstreamTrustConfig{
				Enabled:      true,
				TrustedCIDRs: []string{"not-a-cidr", "10.0.0.0/8"},
			},
		},
	}

	// "not-a-cidr" is invalid, but "10.0.0.0/8" is valid — 10.0.0.1 should still match.
	if !IsTrustedProxySource("10.0.0.1", cfg) {
		t.Error("10.0.0.1 should be trusted via the valid CIDR despite the invalid one")
	}

	// An IP that doesn't match any valid CIDR should be rejected.
	if IsTrustedProxySource("192.168.1.1", cfg) {
		t.Error("192.168.1.1 should not be trusted")
	}
}

// TestIsTrustedProxySource_DefaultConfig verifies that the default config
// (no upstream_trust set) returns false for all IPs.
func TestIsTrustedProxySource_DefaultConfig(t *testing.T) {
	// defaultConfig() does not set UpstreamTrust, so Enabled defaults to false.
	cfg := config.DefaultConfig()

	if IsTrustedProxySource("10.0.0.1", cfg) {
		t.Error("default config should not trust any IP")
	}
}
