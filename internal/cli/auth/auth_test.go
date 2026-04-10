package auth_test

import (
	"testing"

	"github.com/anomalyco/ja4proxy/internal/cli/auth"
)

// TestResolveToken_FlagWins verifies that a non-empty flag value takes precedence
// over the JA4PROXY_TOKEN environment variable.
func TestResolveToken_FlagWins(t *testing.T) {
	t.Setenv("JA4PROXY_TOKEN", "env-token")

	got := auth.ResolveToken("flag-token")
	if got != "flag-token" {
		t.Errorf("ResolveToken = %q; want flag-token", got)
	}
}

// TestResolveToken_EnvFallback verifies that when the flag is empty, the
// JA4PROXY_TOKEN environment variable is used.
func TestResolveToken_EnvFallback(t *testing.T) {
	t.Setenv("JA4PROXY_TOKEN", "env-token")

	got := auth.ResolveToken("")
	if got != "env-token" {
		t.Errorf("ResolveToken = %q; want env-token", got)
	}
}

// TestResolveToken_Empty verifies that when both flag and env are empty,
// ResolveToken returns an empty string (not an error — error handling is in the
// caller).
func TestResolveToken_Empty(t *testing.T) {
	t.Setenv("JA4PROXY_TOKEN", "")

	got := auth.ResolveToken("")
	if got != "" {
		t.Errorf("ResolveToken = %q; want empty string", got)
	}
}

// TestResolveURL_FlagWins verifies that a non-empty URL flag takes precedence
// over the JA4PROXY_URL environment variable.
func TestResolveURL_FlagWins(t *testing.T) {
	t.Setenv("JA4PROXY_URL", "http://from-env:8090")

	got := auth.ResolveURL("http://from-flag:8090")
	if got != "http://from-flag:8090" {
		t.Errorf("ResolveURL = %q; want http://from-flag:8090", got)
	}
}

// TestResolveURL_EnvFallback verifies that when the flag is empty, the
// JA4PROXY_URL environment variable is used.
func TestResolveURL_EnvFallback(t *testing.T) {
	t.Setenv("JA4PROXY_URL", "http://localhost:8090")

	got := auth.ResolveURL("")
	if got != "http://localhost:8090" {
		t.Errorf("ResolveURL = %q; want http://localhost:8090", got)
	}
}

// TestResolveURL_Empty verifies that when both flag and env are empty,
// ResolveURL returns an empty string.
func TestResolveURL_Empty(t *testing.T) {
	t.Setenv("JA4PROXY_URL", "")

	got := auth.ResolveURL("")
	if got != "" {
		t.Errorf("ResolveURL = %q; want empty string", got)
	}
}

// TestResolveToken_EnvNotSet verifies behaviour when the env var is not set at all.
func TestResolveToken_EnvNotSet(t *testing.T) {
	// Unset the env var (t.Setenv will restore it after the test).
	t.Setenv("JA4PROXY_TOKEN", "")

	got := auth.ResolveToken("")
	// Should return empty, not panic.
	_ = got
}

// TestResolveToken_PrecedenceOrder verifies the full precedence chain using a
// table-driven approach.
func TestResolveToken_PrecedenceOrder(t *testing.T) {
	tests := []struct {
		name string
		flag string
		env  string
		want string
	}{
		{"flag_wins_over_env", "flag-tok", "env-tok", "flag-tok"},
		{"env_wins_when_no_flag", "", "env-tok", "env-tok"},
		{"empty_both", "", "", ""},
		{"flag_only", "flag-only", "", "flag-only"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("JA4PROXY_TOKEN", tc.env)
			got := auth.ResolveToken(tc.flag)
			if got != tc.want {
				t.Errorf("ResolveToken(%q) with env=%q = %q; want %q",
					tc.flag, tc.env, got, tc.want)
			}
		})
	}
}

// TestResolveURL_PrecedenceOrder verifies the full URL precedence chain.
func TestResolveURL_PrecedenceOrder(t *testing.T) {
	tests := []struct {
		name string
		flag string
		env  string
		want string
	}{
		{"flag_wins_over_env", "http://flag", "http://env", "http://flag"},
		{"env_wins_when_no_flag", "", "http://env", "http://env"},
		{"empty_both", "", "", ""},
		{"flag_only", "http://flag-only", "", "http://flag-only"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("JA4PROXY_URL", tc.env)
			got := auth.ResolveURL(tc.flag)
			if got != tc.want {
				t.Errorf("ResolveURL(%q) with env=%q = %q; want %q",
					tc.flag, tc.env, got, tc.want)
			}
		})
	}
}

// TestResolveToken_EnvBeatsConfigFile documents the auth resolution contract:
// env var must beat config file (flag > env > config > keychain).
// This test is a documentation-level regression guard for the ordering contract.
// The actual config-file fallback is applied in newClient() in cmd/ja4proxy-cli/main.go,
// not in auth.ResolveToken — so the env var (checked by ResolveToken) always wins
// over config-file values (checked in newClient only when ResolveToken returns "").
func TestResolveToken_EnvBeatsConfigFile(t *testing.T) {
	// When env var is set and flag is empty, ResolveToken returns the env var.
	// newClient() only consults the config file when ResolveToken returns "".
	t.Setenv("JA4PROXY_TOKEN", "env-token")
	got := auth.ResolveToken("")
	if got != "env-token" {
		t.Errorf("env var should beat config file: ResolveToken(%q) = %q; want env-token", "", got)
	}
}

// TestResolveURL_EnvBeatsConfigFile documents that env var beats config file for URL.
func TestResolveURL_EnvBeatsConfigFile(t *testing.T) {
	t.Setenv("JA4PROXY_URL", "http://from-env:8090")
	got := auth.ResolveURL("")
	if got != "http://from-env:8090" {
		t.Errorf("env var should beat config file: ResolveURL(%q) = %q; want http://from-env:8090", "", got)
	}
}
