package config

import (
	"errors"
	"strings"
	"testing"
)

// Regression test for JA4PROXY-2026-0008 — Unauthenticated /metrics and
// /health/deep Endpoints (CRITICAL, CVSS 7.5 elevated per C-3).
//
// Before the fix, the Go proxy bound the metrics HTTP server to a bare
// ":port" (all interfaces) with no authentication. /metrics, /health/deep,
// and /metrics/summary exposed dial setting, ban rates, active-connection
// counts and cert expiry to anyone on the network — reconnaissance before
// an attack. ValidateMetricsAccess refuses startup when metrics is
// enabled and bound to a non-loopback interface without an AuthToken,
// with a JA4PROXY_ALLOW_UNAUTH_METRICS=1 escape hatch for internal
// test clusters.

func metricsCfg(enabled bool, host, token string) *Config {
	cfg := &Config{}
	cfg.Metrics.Enabled = enabled
	cfg.Metrics.BindHost = host
	cfg.Metrics.AuthToken = token
	return cfg
}

func TestRegression_JA4PROXY_2026_0008_refuses_remote_unauth_metrics(t *testing.T) {
	cases := []string{
		"0.0.0.0",
		"::",
		"",
		"10.0.0.5",
		"192.168.1.10",
		"2001:db8::1",
		"metrics.internal",
	}
	for _, host := range cases {
		t.Setenv("JA4PROXY_ALLOW_UNAUTH_METRICS", "")
		err := ValidateMetricsAccess(metricsCfg(true, host, ""))
		if err == nil {
			t.Errorf("host=%q: expected ErrMetricsAuthRequired, got nil", host)
			continue
		}
		if !errors.Is(err, ErrMetricsAuthRequired) {
			t.Errorf("host=%q: expected ErrMetricsAuthRequired, got %v", host, err)
		}
		if !strings.Contains(err.Error(), "JA4PROXY-2026-0008") {
			t.Errorf("host=%q: error must name the finding ID for ops; got %v", host, err)
		}
	}
}

func TestRegression_JA4PROXY_2026_0008_allows_loopback_unauth_metrics(t *testing.T) {
	cases := []string{
		"127.0.0.1",
		"127.0.0.2",
		"::1",
		"[::1]",
		"localhost",
		"LOCALHOST",
	}
	for _, host := range cases {
		t.Setenv("JA4PROXY_ALLOW_UNAUTH_METRICS", "")
		if err := ValidateMetricsAccess(metricsCfg(true, host, "")); err != nil {
			t.Errorf("host=%q: loopback bind must not require token; got %v", host, err)
		}
	}
}

func TestRegression_JA4PROXY_2026_0008_allows_remote_with_token(t *testing.T) {
	t.Setenv("JA4PROXY_ALLOW_UNAUTH_METRICS", "")
	if err := ValidateMetricsAccess(metricsCfg(true, "0.0.0.0", "s3cret-token")); err != nil {
		t.Fatalf("remote bind with token must pass; got %v", err)
	}
}

func TestRegression_JA4PROXY_2026_0008_env_override_allows_unauth(t *testing.T) {
	t.Setenv("JA4PROXY_ALLOW_UNAUTH_METRICS", "1")
	if err := ValidateMetricsAccess(metricsCfg(true, "0.0.0.0", "")); err != nil {
		t.Fatalf("JA4PROXY_ALLOW_UNAUTH_METRICS=1 must bypass the check; got %v", err)
	}
}

func TestRegression_JA4PROXY_2026_0008_rejects_whitespace_only_token(t *testing.T) {
	t.Setenv("JA4PROXY_ALLOW_UNAUTH_METRICS", "")
	if err := ValidateMetricsAccess(metricsCfg(true, "0.0.0.0", "   ")); err == nil {
		t.Fatal("whitespace-only token must not count as authentication")
	}
}

func TestRegression_JA4PROXY_2026_0008_disabled_metrics_is_safe(t *testing.T) {
	t.Setenv("JA4PROXY_ALLOW_UNAUTH_METRICS", "")
	// When metrics is disabled entirely, the server never starts, so there
	// is nothing to protect — a bad BindHost is harmless.
	if err := ValidateMetricsAccess(metricsCfg(false, "0.0.0.0", "")); err != nil {
		t.Fatalf("disabled metrics must not fail validation; got %v", err)
	}
}

func TestRegression_JA4PROXY_2026_0008_nil_config_is_safe(t *testing.T) {
	if err := ValidateMetricsAccess(nil); err != nil {
		t.Fatalf("nil config must not explode; got %v", err)
	}
}

func TestRegression_JA4PROXY_2026_0008_default_config_binds_loopback(t *testing.T) {
	// Any operator who never touches proxy.yml still gets the fix: the
	// default bind must be loopback, not all-interfaces.
	cfg := DefaultConfig()
	host := strings.TrimSpace(cfg.Metrics.BindHost)
	if !isLocalMetricsBind(host) {
		t.Fatalf("DefaultConfig().Metrics.BindHost must be a loopback address for 0008 fix; got %q", host)
	}
	t.Setenv("JA4PROXY_ALLOW_UNAUTH_METRICS", "")
	if err := ValidateMetricsAccess(cfg); err != nil {
		t.Fatalf("DefaultConfig() must pass ValidateMetricsAccess with no env overrides; got %v", err)
	}
}

func TestMetricsRequestIsLocal(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:41234":       true,
		"127.0.0.2:1":           true,
		"[::1]:41234":           true,
		"10.0.0.5:41234":        false,
		"[2001:db8::1]:41234":   false,
		"198.51.100.7:41234":    false,
		"malformed":             false,
		"":                      false,
	}
	for addr, want := range cases {
		if got := MetricsRequestIsLocal(addr); got != want {
			t.Errorf("MetricsRequestIsLocal(%q) = %v, want %v", addr, got, want)
		}
	}
}
