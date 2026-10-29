// Package config provides configuration loading and validation for the JA4proxy Go proxy.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
	"pgregory.net/rapid"
)

// ---------------------------------------------------------------------------
// Native Go Fuzz Targets
// ---------------------------------------------------------------------------

// FuzzLoadYAML fuzzes full configuration unmarshaling and validation across arbitrary YAML payloads.
func FuzzLoadYAML(f *testing.F) {
	f.Add([]byte(``))
	f.Add([]byte(`
proxy:
  bind_port: 8443
  backend_host: "backend"
  backend_port: 443
redis:
  host: "127.0.0.1"
  port: 6379
`))
	f.Add([]byte(`::: invalid :::`))
	f.Add([]byte("a: &a [*a, *a]\n"))
	f.Add([]byte(`
security:
  tarpit_enabled: "invalid_bool"
proxy:
  bind_port: -50
`))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "proxy.yml")
		if err := os.WriteFile(configFile, data, 0o600); err != nil {
			return
		}

		// Loading must never panic
		cfg, err := Load(configFile)
		if err == nil && cfg != nil {
			_ = cfg.Validate()
			_ = cfg.Security.ProtocolLockdownEnabled()
		}
	})
}

// FuzzFlexInt fuzzes FlexInt unmarshaling across varied integer and string representations.
func FuzzFlexInt(f *testing.F) {
	f.Add([]byte(`8080`))
	f.Add([]byte(`"8080"`))
	f.Add([]byte(`"  8443  "`))
	f.Add([]byte(`"-1"`))
	f.Add([]byte(`"invalid"`))
	f.Add([]byte(`""`))
	f.Add([]byte(`[1, 2, 3]`))
	f.Add([]byte(`true`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var fi FlexInt
		var node yaml.Node
		if err := yaml.Unmarshal(data, &node); err != nil {
			return
		}
		if len(node.Content) > 0 {
			_ = fi.UnmarshalYAML(node.Content[0])
		}
	})
}

// FuzzExpandEnvVars fuzzes environment variable pattern interpolation.
func FuzzExpandEnvVars(f *testing.F) {
	f.Add("no_vars_here")
	f.Add("${FOO:-default}")
	f.Add("${VAR}")
	f.Add("${INVALID:-${NESTED}}")
	f.Add("prefix_${A:-1}_mid_${B:-2}_suffix")
	f.Add("${}")
	f.Add("${:-}")

	f.Fuzz(func(t *testing.T, input string) {
		out := expandEnvVars(input)
		_ = out
	})
}

// ---------------------------------------------------------------------------
// Rapid Property-Based Invariant Tests
// ---------------------------------------------------------------------------

// TestProperty_ValidationStrictness proves that invalid ports, out-of-bounds security dials,
// or non-monotonic risk thresholds always fail Validate().
func TestProperty_ValidationStrictness(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		cfg := DefaultConfig()

		scenario := rapid.IntRange(0, 3).Draw(rt, "violation_scenario")
		switch scenario {
		case 0:
			// Invalid bind port (< 1 or > 65535)
			invalidPort := rapid.OneOf(
				rapid.IntRange(-10000, 0),
				rapid.IntRange(65536, 1000000),
			).Draw(rt, "invalid_bind_port")
			cfg.Proxy.BindPort = FlexInt(invalidPort)

			err := cfg.Validate()
			if err == nil {
				rt.Fatalf("expected validation error for invalid bind port %d, got nil", invalidPort)
			}
			if !strings.Contains(err.Error(), "bind port") {
				rt.Fatalf("expected error mentioning bind port, got: %v", err)
			}

		case 1:
			// Invalid backend port (< 1 or > 65535)
			invalidPort := rapid.OneOf(
				rapid.IntRange(-10000, 0),
				rapid.IntRange(65536, 1000000),
			).Draw(rt, "invalid_backend_port")
			cfg.Proxy.BackendPort = FlexInt(invalidPort)

			err := cfg.Validate()
			if err == nil {
				rt.Fatalf("expected validation error for invalid backend port %d, got nil", invalidPort)
			}
			if !strings.Contains(err.Error(), "backend port") {
				rt.Fatalf("expected error mentioning backend port, got: %v", err)
			}

		case 2:
			// Invalid security dial (< 0 or > 100)
			invalidDial := rapid.OneOf(
				rapid.IntRange(-1000, -1),
				rapid.IntRange(101, 1000),
			).Draw(rt, "invalid_dial")
			cfg.MonitorMode.Dial = invalidDial

			err := cfg.Validate()
			if err == nil {
				rt.Fatalf("expected validation error for invalid security dial %d, got nil", invalidDial)
			}
			if !strings.Contains(err.Error(), "dial") {
				rt.Fatalf("expected error mentioning dial, got: %v", err)
			}

		case 3:
			// Inverted risk thresholds (flag > ban)
			flag := rapid.IntRange(50, 95).Draw(rt, "flag")
			ban := rapid.IntRange(1, 40).Draw(rt, "ban")
			cfg.RiskScorer.Thresholds = ThresholdsConfig{
				Flag:      flag,
				RateLimit: flag,
				Tarpit:    flag,
				Block:     flag,
				Ban:       ban,
			}

			err := cfg.Validate()
			if err == nil {
				rt.Fatalf("expected validation error for non-monotonic thresholds (flag=%d > ban=%d), got nil", flag, ban)
			}
			if !strings.Contains(err.Error(), "non-decreasing") && !strings.Contains(err.Error(), "monotonic") {
				rt.Fatalf("expected error mentioning non-decreasing thresholds, got: %v", err)
			}
		}
	})
}

// TestProperty_EnvExpansionDeterminism proves that for arbitrary variable names and defaults,
// unset variables strictly expand to defaultVal, while set variables strictly expand to their value.
func TestProperty_EnvExpansionDeterminism(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		varName := "TEST_CFG_EXP_" + rapid.StringMatching(`^[A-Z0-9_]{3,10}$`).Draw(rt, "var_name")
		defaultVal := rapid.StringMatching(`^[a-z0-9_-]{1,20}$`).Draw(rt, "default_val")

		// Case 1: Unset variable expands to default
		os.Unsetenv(varName)
		input1 := fmt.Sprintf("${%s:-%s}", varName, defaultVal)
		res1 := expandEnvVars(input1)
		if res1 != defaultVal {
			rt.Fatalf("expected %q to expand to default %q, got %q", input1, defaultVal, res1)
		}

		// Case 2: Set variable expands to its value
		setVal := rapid.StringMatching(`^[a-z0-9_-]{1,20}$`).Draw(rt, "set_val")
		os.Setenv(varName, setVal)
		defer os.Unsetenv(varName)

		input2 := fmt.Sprintf("${%s:-%s}", varName, defaultVal)
		res2 := expandEnvVars(input2)
		if res2 != setVal {
			rt.Fatalf("expected %q to expand to set value %q, got %q", input2, setVal, res2)
		}
	})
}

// TestProperty_DefaultConfigInvariants proves that DefaultConfig() always passes Validate()
// and preserves security defaults (metrics loopback binding, positive timeouts).
func TestProperty_DefaultConfigInvariants(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultConfig() failed Validate(): %v", err)
	}

	if cfg.Proxy.BindPort.Int() != 8080 || cfg.Proxy.BackendPort.Int() != 443 {
		t.Fatalf("unexpected proxy ports: bind=%d backend=%d", cfg.Proxy.BindPort.Int(), cfg.Proxy.BackendPort.Int())
	}

	if cfg.Metrics.BindHost != "127.0.0.1" {
		t.Fatalf("metrics bind host must default to loopback (127.0.0.1), got %q", cfg.Metrics.BindHost)
	}

	if cfg.Proxy.MaxConnections <= 0 {
		t.Fatalf("max connections must be positive, got %d", cfg.Proxy.MaxConnections)
	}
}

// ---------------------------------------------------------------------------
// Micro-Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkConfigLoad(b *testing.B) {
	yamlContent := `
proxy:
  bind_host: "0.0.0.0"
  bind_port: 8443
  backend_host: "backend"
  backend_port: 443
  max_connections: 50000
redis:
  host: "127.0.0.1"
  port: 6379
  timeout_ms: 100
security:
  tarpit_enabled: true
  protocol_lockdown: true
risk_scorer:
  thresholds:
    flag: 20
    rate_limit: 40
    tarpit: 60
    block: 80
    ban: 100
metrics:
  bind_host: "127.0.0.1"
  bind_port: 9090
`
	tmpDir := b.TempDir()
	configFile := filepath.Join(tmpDir, "benchmark.yml")
	if err := os.WriteFile(configFile, []byte(yamlContent), 0o600); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg, err := Load(configFile)
		if err != nil || cfg == nil {
			b.Fatalf("Load failed: %v", err)
		}
	}
}

func BenchmarkConfigValidate(b *testing.B) {
	cfg := DefaultConfig()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := cfg.Validate(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkExpandEnvVars(b *testing.B) {
	input := "host_${REDIS_HOST:-127.0.0.1}_port_${REDIS_PORT:-6379}_token_${SECRET_TOKEN:-none}"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = expandEnvVars(input)
	}
}
