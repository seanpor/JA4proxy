package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/seanpor/ja4proxy/internal/cli/config"
)

// TestSave_CreatesFileAndDirs verifies Save writes a config file and creates
// parent directories as needed.
func TestSave_CreatesFileAndDirs(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cfg := config.NewDefaultCLIConfig()
	cfg.URL = "http://localhost:8090"
	cfg.Token = "test-token"
	cfg.DefaultOutput = "json"

	if err := config.Save(cfg); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Verify file was created
	path := filepath.Join(dir, ".config", "ja4proxy", "cli.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read saved config: %v", err)
	}

	content := string(data)
	if content == "" {
		t.Fatal("saved config file is empty")
	}

	// Load it back and verify roundtrip
	loaded, err := config.Load()
	if err != nil {
		t.Fatalf("Load() after Save() error: %v", err)
	}
	if loaded.URL != "http://localhost:8090" {
		t.Errorf("URL = %q; want http://localhost:8090", loaded.URL)
	}
	if loaded.Token != "test-token" {
		t.Errorf("Token = %q; want test-token", loaded.Token)
	}
	if loaded.DefaultOutput != "json" {
		t.Errorf("DefaultOutput = %q; want json", loaded.DefaultOutput)
	}
	if !loaded.ConfirmMutating {
		t.Error("ConfirmMutating should be true (safe default)")
	}
}

// TestSave_OverwritesExistingFile verifies Save overwrites a previous config.
func TestSave_OverwritesExistingFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cfg1 := config.NewDefaultCLIConfig()
	cfg1.URL = "http://first:8090"
	if err := config.Save(cfg1); err != nil {
		t.Fatalf("first Save() error: %v", err)
	}

	cfg2 := config.NewDefaultCLIConfig()
	cfg2.URL = "http://second:8090"
	if err := config.Save(cfg2); err != nil {
		t.Fatalf("second Save() error: %v", err)
	}

	loaded, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if loaded.URL != "http://second:8090" {
		t.Errorf("URL = %q; want http://second:8090", loaded.URL)
	}
}

// TestLoad_FileDoesNotExist verifies Load returns a default config when the
// config file is missing (not an error).
func TestLoad_FileDoesNotExist(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() should not error for missing file: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil config")
	}
	if !cfg.ConfirmMutating {
		t.Error("default ConfirmMutating should be true")
	}
}

// TestLoad_MalformedYAML verifies Load returns an error for invalid YAML.
func TestLoad_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	writeConfigUnderHome(t, dir, "{{{{ invalid yaml")

	_, err := config.Load()
	if err == nil {
		t.Fatal("Load() should return error for malformed YAML")
	}
}

// TestSave_RoundtripWithAllFields verifies all fields survive a save/load cycle.
func TestSave_RoundtripWithAllFields(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cfg := &config.CLIConfig{
		URL:             "https://proxy.example.com:8090",
		Token:           "secret-token-123",
		DefaultOutput:   "csv",
		ConfirmMutating: false,
		UseKeyring:      true,
	}
	if err := config.Save(cfg); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	loaded, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if loaded.URL != cfg.URL {
		t.Errorf("URL = %q; want %q", loaded.URL, cfg.URL)
	}
	if loaded.Token != cfg.Token {
		t.Errorf("Token = %q; want %q", loaded.Token, cfg.Token)
	}
	if loaded.DefaultOutput != cfg.DefaultOutput {
		t.Errorf("DefaultOutput = %q; want %q", loaded.DefaultOutput, cfg.DefaultOutput)
	}
	if loaded.ConfirmMutating != cfg.ConfirmMutating {
		t.Errorf("ConfirmMutating = %v; want %v", loaded.ConfirmMutating, cfg.ConfirmMutating)
	}
	if loaded.UseKeyring != cfg.UseKeyring {
		t.Errorf("UseKeyring = %v; want %v", loaded.UseKeyring, cfg.UseKeyring)
	}
}
