package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/anomalyco/ja4proxy/internal/cli/config"
)

// writeConfigUnderHome creates ~/.config/ja4proxy/cli.yaml inside dir
// and sets HOME=dir so config.Load() finds it.
func writeConfigUnderHome(t *testing.T, dir, yaml string) {
	t.Helper()
	subdir := filepath.Join(dir, ".config", "ja4proxy")
	if err := os.MkdirAll(subdir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "cli.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("HOME", dir)
}

// TestCLIConfig_ConfirmMutatingField_ParsesFalse verifies that
// confirm_mutating: false is parsed correctly.
func TestCLIConfig_ConfirmMutatingField_ParsesFalse(t *testing.T) {
	dir := t.TempDir()
	writeConfigUnderHome(t, dir, `url: http://localhost:8090
token: testtoken
confirm_mutating: false
`)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.ConfirmMutating {
		t.Errorf("ConfirmMutating = true; want false when confirm_mutating: false in config")
	}
}

// TestCLIConfig_ConfirmMutatingField_ParsesTrue verifies that
// confirm_mutating: true is parsed correctly.
func TestCLIConfig_ConfirmMutatingField_ParsesTrue(t *testing.T) {
	dir := t.TempDir()
	writeConfigUnderHome(t, dir, `url: http://localhost:8090
token: testtoken
confirm_mutating: true
`)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if !cfg.ConfirmMutating {
		t.Errorf("ConfirmMutating = false; want true when confirm_mutating: true in config")
	}
}

// TestCLIConfig_ConfirmMutatingField_AbsentDefaultsFalse verifies that when
// the key is absent from the YAML file, ConfirmMutating is false (Go zero
// value).  Callers that need a safe default should use NewDefaultCLIConfig().
func TestCLIConfig_ConfirmMutatingField_AbsentDefaultsFalse(t *testing.T) {
	dir := t.TempDir()
	writeConfigUnderHome(t, dir, `url: http://localhost:8090
token: testtoken
`)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	// When the key is absent, Go zero-value (false) is returned.
	if cfg.ConfirmMutating {
		t.Errorf("ConfirmMutating = true; want false (zero value) when key absent from config")
	}
}

// TestNewDefaultCLIConfig_ConfirmMutatingDefaultsTrue verifies that the
// convenience constructor sets ConfirmMutating to true (safe default).
func TestNewDefaultCLIConfig_ConfirmMutatingDefaultsTrue(t *testing.T) {
	t.Parallel()
	cfg := config.NewDefaultCLIConfig()
	if !cfg.ConfirmMutating {
		t.Errorf("NewDefaultCLIConfig().ConfirmMutating = false; want true (safe default)")
	}
}
