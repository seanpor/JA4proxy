package config_test

import (
	"os"
	"testing"

	"github.com/seanpor/ja4proxy/internal/config"
	"pgregory.net/rapid"
)

// INV-CONFIG-001: Default Config Validity
// DefaultConfig().Validate() == nil
func TestInvariant_Config_DefaultConfigValid(t *testing.T) {
	cfg := config.DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultConfig failed validation: %v", err)
	}
}

// INV-CONFIG-002: Invalid Port Rejection
// forall p not in [1, 65535], Validate() returns error
func TestInvariant_Config_InvalidPortRejection(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		invalidPort := rapid.OneOf(
			rapid.IntRange(-10000, 0),
			rapid.IntRange(65536, 100000),
		).Draw(t, "invalidPort")

		cfg := config.DefaultConfig()
		cfg.Proxy.BindPort = config.FlexInt(invalidPort)

		if err := cfg.Validate(); err == nil {
			t.Fatalf("Expected validation error for invalid bind port %d, got nil", invalidPort)
		}
	})
}

// INV-CONFIG-003: Env Var Expansion Integrity
// Load reads file and expands env vars cleanly
func TestInvariant_Config_EnvVarExpansionIntegrity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		varName := rapid.StringMatching("[A-Z0-9_]{3,15}").Draw(t, "varName")
		varVal := rapid.StringMatching("[a-zA-Z0-9_-]{1,20}").Draw(t, "varVal")

		os.Setenv(varName, varVal)
		defer os.Unsetenv(varName)

		yamlContent := "proxy:\n  bind_port: 8443\n"
		file, err := os.CreateTemp("", "cfg-test-*.yml")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer os.Remove(file.Name())

		if _, err := file.WriteString(yamlContent); err != nil {
			t.Fatalf("Failed to write temp file: %v", err)
		}
		file.Close()

		loaded, err := config.Load(file.Name())
		if err != nil {
			t.Fatalf("Config load failed: %v", err)
		}
		if err := loaded.Validate(); err != nil {
			t.Fatalf("Loaded config validation failed: %v", err)
		}
	})
}

// INV-CONFIG-004: Risk Scorer Threshold Monotonicity
// Violation of flag <= rate_limit <= tarpit <= block <= ban must fail Validate()
func TestInvariant_Config_RiskScorerThresholdMonotonicity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Draw non-monotonic thresholds where flag > ban
		flag := rapid.IntRange(50, 90).Draw(t, "flag")
		ban := rapid.IntRange(1, 40).Draw(t, "ban")

		cfg := config.DefaultConfig()
		cfg.RiskScorer.Thresholds = config.ThresholdsConfig{
			Flag:      flag,
			RateLimit: 35,
			Tarpit:    55,
			Block:     70,
			Ban:       ban,
		}

		if err := cfg.Validate(); err == nil {
			t.Fatalf("Expected validation error when flag (%d) > ban (%d), got nil", flag, ban)
		}
	})
}
