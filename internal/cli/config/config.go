// Package config provides a simple YAML configuration file loader and writer
// for the ja4proxy-cli binary.  The config file lives at
// ~/.config/ja4proxy/cli.yaml and contains default URL, token, and output format.
package config

import (
	"errors"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// CLIConfig holds the persisted CLI preferences.
type CLIConfig struct {
	// URL is the default Management API base URL (e.g. "http://localhost:8090").
	URL string `yaml:"url"`

	// Token is the default API bearer token.
	Token string `yaml:"token"`

	// DefaultOutput is the default output format: "table", "json", or "csv".
	DefaultOutput string `yaml:"default_output"`

	// ConfirmMutating controls whether mutating commands require the
	// --confirm flag.  Set to false to skip the confirmation prompt in
	// non-interactive scripts and CI pipelines.  Defaults to true (safe
	// default) when created via NewDefaultCLIConfig.
	ConfirmMutating bool `yaml:"confirm_mutating"`
}

// NewDefaultCLIConfig returns a CLIConfig with safe production defaults.
// Use this instead of a bare struct literal when you need ConfirmMutating
// to default to true (the safe value) rather than Go's zero value (false).
func NewDefaultCLIConfig() *CLIConfig {
	return &CLIConfig{
		ConfirmMutating: true,
	}
}

// configPath returns the canonical path of the CLI config file.
func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "ja4proxy", "cli.yaml"), nil
}

// Load reads the CLI config file from ~/.config/ja4proxy/cli.yaml.
// If the file does not exist, an empty CLIConfig is returned without error.
func Load() (*CLIConfig, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &CLIConfig{}, nil
		}
		return nil, err
	}

	var cfg CLIConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Save writes cfg to ~/.config/ja4proxy/cli.yaml, creating parent directories
// as needed.
func Save(cfg *CLIConfig) error {
	path, err := configPath()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o600)
}
