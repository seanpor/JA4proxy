package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_ActualProxyYML(t *testing.T) {
	// Load the real proxy.yml from the repo root — must not error
	cfg, err := Load("../../config/proxy.yml")
	if err != nil {
		t.Fatalf("Load(proxy.yml) failed: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load returned nil config")
	}
	// Spot-check a few known values from proxy.yml
	if cfg.Proxy.BindPort.Int() != 8080 {
		t.Errorf("BindPort: got %d, want 8080", cfg.Proxy.BindPort)
	}
	if cfg.Redis.Port.Int() != 6379 {
		t.Errorf("Redis.Port: got %d, want 6379", cfg.Redis.Port)
	}
	if cfg.RiskScorer.Thresholds.Block != 70 {
		t.Errorf("RiskScorer.Block: got %d, want 70", cfg.RiskScorer.Thresholds.Block)
	}
	// JA4PROXY-2026-0004: ALPN browser bypass now defaults to OFF because
	// ALPN is an attacker-controlled TLS field. Operators must opt in.
	if cfg.SecurityPolicy.ALPNBrowserBypass.Enabled {
		t.Error("ALPNBrowserBypass must default to DISABLED (JA4PROXY-2026-0004)")
	}
}

func TestLoad_UnknownKeysIgnored(t *testing.T) {
	// YAML with unknown keys should not return an error
	yaml := `
proxy:
  bind_port: 9999
  unknown_key_foo: "bar"   # unknown — should be ignored
  nested_unknown:
    deeply: nested
`
	cfg, err := loadFromString(yaml)
	if err != nil {
		t.Fatalf("unknown keys caused error: %v", err)
	}
	if cfg.Proxy.BindPort.Int() != 9999 {
		t.Errorf("BindPort: got %d, want 9999", cfg.Proxy.BindPort)
	}
}

func TestLoad_EnvVarExpansion_WithValue(t *testing.T) {
	t.Setenv("TEST_BACKEND_HOST", "mybackend.example.com")
	yaml := `
proxy:
  backend_host: "${TEST_BACKEND_HOST:-fallback}"
  bind_port: 8080
`
	cfg, err := loadFromString(yaml)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Proxy.BackendHost != "mybackend.example.com" {
		t.Errorf("backend_host: got %q, want %q", cfg.Proxy.BackendHost, "mybackend.example.com")
	}
}

func TestLoad_EnvVarExpansion_WithDefault(t *testing.T) {
	// Ensure the variable is not set
	os.Unsetenv("TEST_UNSET_VAR_XYZ")
	yaml := `
proxy:
  backend_host: "${TEST_UNSET_VAR_XYZ:-mydefaulthost}"
  bind_port: 8080
`
	cfg, err := loadFromString(yaml)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Proxy.BackendHost != "mydefaulthost" {
		t.Errorf("backend_host: got %q, want %q", cfg.Proxy.BackendHost, "mydefaulthost")
	}
}

func TestLoad_EnvVarExpansion_NoDefault(t *testing.T) {
	// ${VAR} without default when var is unset → empty string
	os.Unsetenv("TEST_EMPTY_VAR_XYZ")
	yaml := `
proxy:
  bind_host: "${TEST_EMPTY_VAR_XYZ}"
  bind_port: 8080
`
	cfg, err := loadFromString(yaml)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	// Empty string is the result (no default specified)
	if cfg.Proxy.BindHost != "" {
		t.Errorf("bind_host: got %q, want empty string", cfg.Proxy.BindHost)
	}
}

func TestLoad_Defaults(t *testing.T) {
	// Empty YAML should return default values
	cfg, err := loadFromString("")
	if err != nil {
		t.Fatalf("Load of empty YAML failed: %v", err)
	}
	if cfg.Proxy.BindPort.Int() != 8080 {
		t.Errorf("default BindPort: got %d, want 8080", cfg.Proxy.BindPort)
	}
	if cfg.RiskScorer.Thresholds.Flag != 20 {
		t.Errorf("default Flag threshold: got %d, want 20", cfg.RiskScorer.Thresholds.Flag)
	}
	if cfg.RiskScorer.Thresholds.RateLimit != 35 {
		t.Errorf("default RateLimit threshold: got %d, want 35", cfg.RiskScorer.Thresholds.RateLimit)
	}
	if cfg.RiskScorer.Thresholds.Tarpit != 55 {
		t.Errorf("default Tarpit threshold: got %d, want 55", cfg.RiskScorer.Thresholds.Tarpit)
	}
	if cfg.RiskScorer.Thresholds.Block != 70 {
		t.Errorf("default Block threshold: got %d, want 70", cfg.RiskScorer.Thresholds.Block)
	}
	if cfg.RiskScorer.Thresholds.Ban != 85 {
		t.Errorf("default Ban threshold: got %d, want 85", cfg.RiskScorer.Thresholds.Ban)
	}
	if cfg.MonitorMode.Dial != 0 {
		t.Errorf("default Dial: got %d, want 0", cfg.MonitorMode.Dial)
	}
	if cfg.Tarpit.MaxActiveConnections != 500 {
		t.Errorf("default MaxActiveConnections: got %d, want 500", cfg.Tarpit.MaxActiveConnections)
	}
}

func TestLoad_SecurityPolicyDefaults(t *testing.T) {
	cfg, err := loadFromString("")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	// JA4PROXY-2026-0004: ALPN is attacker-controlled; bypass defaults OFF.
	if cfg.SecurityPolicy.ALPNBrowserBypass.Enabled {
		t.Error("ALPNBrowserBypass must default to DISABLED (JA4PROXY-2026-0004)")
	}
	if !cfg.SecurityPolicy.JA4WhitelistBypass.Enabled {
		t.Error("JA4WhitelistBypass should default to enabled")
	}
	if !cfg.SecurityPolicy.JA4BlockingEnabled.Enabled {
		t.Error("JA4BlockingEnabled should default to enabled")
	}
	if !cfg.SecurityPolicy.MTLSBypass.Enabled {
		t.Error("MTLSBypass should default to enabled")
	}
	if !cfg.SecurityPolicy.StaticIPAllowlist.Enabled {
		t.Error("StaticIPAllowlist should default to enabled")
	}
	if !cfg.SecurityPolicy.CountryBlockingEnabled.Enabled {
		t.Error("CountryBlockingEnabled should default to enabled")
	}
	if !cfg.SecurityPolicy.SpamhausBypass.Enabled {
		t.Error("SpamhausBypass should default to enabled")
	}
	if !cfg.SecurityPolicy.TLSVersionBypass.Enabled {
		t.Error("TLSVersionBypass should default to enabled")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/proxy.yml")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	_, err := loadFromString("invalid: yaml: [unclosed")
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

func TestLoad_SecurityListsLoaded(t *testing.T) {
	// Verify whitelist and blacklist are loaded from proxy.yml
	cfg, err := Load("../../config/proxy.yml")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(cfg.Security.Whitelist) == 0 {
		t.Error("expected non-empty whitelist from proxy.yml")
	}
	if len(cfg.Security.Blacklist) == 0 {
		t.Error("expected non-empty blacklist from proxy.yml")
	}
	// Check Chrome is in whitelist
	found := false
	for _, fp := range cfg.Security.Whitelist {
		if strings.HasPrefix(fp, "t13d1516h2") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected Chrome fingerprint t13d1516h2... in whitelist")
	}
}

func TestExpandEnvVars(t *testing.T) {
	cases := []struct {
		input    string
		env      map[string]string
		expected string
	}{
		{
			input:    "${FOO:-bar}",
			env:      nil,
			expected: "bar",
		},
		{
			input:    "${FOO:-bar}",
			env:      map[string]string{"FOO": "baz"},
			expected: "baz",
		},
		{
			input:    "prefix_${FOO:-default}_suffix",
			env:      nil,
			expected: "prefix_default_suffix",
		},
		{
			input:    "no_vars_here",
			env:      nil,
			expected: "no_vars_here",
		},
		{
			input:    "${A:-x}${B:-y}",
			env:      map[string]string{"A": "hello"},
			expected: "helloy",
		},
	}

	for _, tc := range cases {
		// Set env vars
		for k, v := range tc.env {
			t.Setenv(k, v)
		}
		// Unset any vars not in the map
		if _, ok := tc.env["FOO"]; !ok {
			os.Unsetenv("FOO")
		}
		if _, ok := tc.env["A"]; !ok {
			os.Unsetenv("A")
		}
		if _, ok := tc.env["B"]; !ok {
			os.Unsetenv("B")
		}

		got := expandEnvVars(tc.input)
		if got != tc.expected {
			t.Errorf("expandEnvVars(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

// loadFromString writes yaml to a temp file and calls Load.
func loadFromString(content string) (*Config, error) {
	dir := os.TempDir()
	f, err := os.CreateTemp(dir, "proxy-*.yml")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(content); err != nil {
		return nil, err
	}
	f.Close()
	return Load(filepath.Join(dir, filepath.Base(f.Name())))
}

func TestLoad_TrustedUpstreamSourcesFromProxyYML(t *testing.T) {
	cfg, err := Load("../../config/proxy.yml")
	if err != nil {
		t.Fatalf("Load(proxy.yml) failed: %v", err)
	}
	// NetBox should be disabled by default (conservative default per phase-94i2)
	if cfg.TrustedUpstreamSources.NetBox.Enabled {
		t.Error("NetBox should be disabled by default")
	}
	// static_cidrs should have at least one entry
	if len(cfg.TrustedUpstreamSources.StaticCIDRs) == 0 {
		t.Error("expected non-empty static_cidrs from proxy.yml")
	}
	if cfg.TrustedUpstreamSources.NetBox.Tag != "ja4proxy-trusted" {
		t.Errorf("NetBox tag: got %q, want %q", cfg.TrustedUpstreamSources.NetBox.Tag, "ja4proxy-trusted")
	}
	if !cfg.TrustedUpstreamSources.NetBox.RefreshOnSIGHUP {
		t.Error("expected refresh_on_sighup to be true")
	}
}
