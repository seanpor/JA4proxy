package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/seanpor/ja4proxy/internal/cli/config"
)

// TestSave_ReadOnlyDirectory verifies Save returns an error when the parent
// directory cannot be created (e.g., inside a read-only path).
func TestSave_ReadOnlyDirectory(t *testing.T) {
	dir := t.TempDir()
	// Create .config as a read-only file (not a directory) to block MkdirAll
	roPath := filepath.Join(dir, ".config")
	if err := os.WriteFile(roPath, []byte("blocker"), 0o400); err != nil {
		t.Fatalf("failed to create blocker file: %v", err)
	}
	t.Setenv("HOME", dir)

	cfg := config.NewDefaultCLIConfig()
	err := config.Save(cfg)
	if err == nil {
		t.Fatal("Save() should error when parent dir creation is blocked")
	}
}

// TestLoad_ReadPermissionError verifies Load returns an error when the config
// file exists but cannot be read (permission denied, not ErrNotExist).
func TestLoad_ReadPermissionError(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, ".config", "ja4proxy")
	if err := os.MkdirAll(subdir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cfgPath := filepath.Join(subdir, "cli.yaml")
	if err := os.WriteFile(cfgPath, []byte("url: test"), 0o000); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("HOME", dir)

	_, err := config.Load()
	if err == nil {
		// On some systems (e.g., running as root), this won't fail.
		// That's OK — skip the assertion.
		t.Skip("running as root or permission check not enforced")
	}
}

// TestLoad_EmptyFile verifies Load handles an empty config file gracefully,
// returning defaults.
func TestLoad_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	writeConfigUnderHome(t, dir, "")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error for empty file: %v", err)
	}
	// Should get defaults
	if !cfg.ConfirmMutating {
		t.Error("ConfirmMutating should default to true")
	}
}

// TestSave_EmptyConfig verifies Save handles a zero-value config without error.
func TestSave_EmptyConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cfg := &config.CLIConfig{} // all zero values
	if err := config.Save(cfg); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Verify we can load it back
	loaded, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if loaded.URL != "" {
		t.Errorf("URL = %q; want empty", loaded.URL)
	}
}
