package auth_test

import (
	"testing"

	"github.com/seanpor/ja4proxy/internal/cli/auth"
	"github.com/zalando/go-keyring"
)

// init sets the keyring provider to the in-memory mock for all tests in this
// file.  This must run before any test that calls ResolveTokenWithKeychain or
// StoreTokenInKeychain so no real OS keyring daemon is required.
func init() {
	keyring.MockInit()
}

// TestResolveTokenWithKeychain_FlagWins verifies that a non-empty flag value
// beats a token stored in the keyring.
func TestResolveTokenWithKeychain_FlagWins(t *testing.T) {
	keyring.MockInit() // reset to clean state
	if err := keyring.Set("ja4proxy-cli", "token", "keyring-token"); err != nil {
		t.Fatalf("keyring.Set: %v", err)
	}
	t.Cleanup(func() { _ = keyring.Delete("ja4proxy-cli", "token") })

	got := auth.ResolveTokenWithKeychain("flag-token")
	if got != "flag-token" {
		t.Errorf("ResolveTokenWithKeychain(%q) = %q; want flag-token", "flag-token", got)
	}
}

// TestResolveTokenWithKeychain_EnvWins verifies that the JA4PROXY_TOKEN env
// var beats a token stored in the keyring.
func TestResolveTokenWithKeychain_EnvWins(t *testing.T) {
	keyring.MockInit() // reset to clean state
	if err := keyring.Set("ja4proxy-cli", "token", "keyring-token"); err != nil {
		t.Fatalf("keyring.Set: %v", err)
	}
	t.Cleanup(func() { _ = keyring.Delete("ja4proxy-cli", "token") })

	t.Setenv("JA4PROXY_TOKEN", "env-token")

	got := auth.ResolveTokenWithKeychain("")
	if got != "env-token" {
		t.Errorf("ResolveTokenWithKeychain(%q) with env=env-token = %q; want env-token", "", got)
	}
}

// TestResolveTokenWithKeychain_KeyringFallback verifies that the token stored
// in the keyring is returned when neither the flag nor the env var is set.
func TestResolveTokenWithKeychain_KeyringFallback(t *testing.T) {
	keyring.MockInit() // reset to clean state
	if err := keyring.Set("ja4proxy-cli", "token", "keyring-token"); err != nil {
		t.Fatalf("keyring.Set: %v", err)
	}
	t.Cleanup(func() { _ = keyring.Delete("ja4proxy-cli", "token") })

	t.Setenv("JA4PROXY_TOKEN", "")

	got := auth.ResolveTokenWithKeychain("")
	if got != "keyring-token" {
		t.Errorf("ResolveTokenWithKeychain(%q) = %q; want keyring-token", "", got)
	}
}

// TestResolveTokenWithKeychain_Empty verifies that "" is returned when no
// flag, env var, or keyring entry is set.
func TestResolveTokenWithKeychain_Empty(t *testing.T) {
	keyring.MockInit() // reset to clean state — no entry stored

	t.Setenv("JA4PROXY_TOKEN", "")

	got := auth.ResolveTokenWithKeychain("")
	if got != "" {
		t.Errorf("ResolveTokenWithKeychain(%q) = %q; want empty string", "", got)
	}
}

// TestStoreTokenInKeychain_StoreAndRetrieve verifies round-trip store+retrieve.
func TestStoreTokenInKeychain_StoreAndRetrieve(t *testing.T) {
	keyring.MockInit() // reset to clean state

	if err := auth.StoreTokenInKeychain("my-secret-token"); err != nil {
		t.Fatalf("StoreTokenInKeychain: %v", err)
	}
	t.Cleanup(func() { _ = keyring.Delete("ja4proxy-cli", "token") })

	t.Setenv("JA4PROXY_TOKEN", "")
	got := auth.ResolveTokenWithKeychain("")
	if got != "my-secret-token" {
		t.Errorf("after StoreTokenInKeychain: ResolveTokenWithKeychain = %q; want my-secret-token", got)
	}
}

// TestStoreTokenInKeychain_FlagStillWins verifies that the flag beats the
// keyring even after StoreTokenInKeychain has been called.
func TestStoreTokenInKeychain_FlagStillWins(t *testing.T) {
	keyring.MockInit() // reset to clean state

	if err := auth.StoreTokenInKeychain("stored-token"); err != nil {
		t.Fatalf("StoreTokenInKeychain: %v", err)
	}
	t.Cleanup(func() { _ = keyring.Delete("ja4proxy-cli", "token") })

	got := auth.ResolveTokenWithKeychain("explicit-flag-token")
	if got != "explicit-flag-token" {
		t.Errorf("ResolveTokenWithKeychain with flag = %q; want explicit-flag-token", got)
	}
}

// TestDeleteTokenFromKeychain verifies that deleting the keyring token causes
// ResolveTokenWithKeychain to return "".
func TestDeleteTokenFromKeychain(t *testing.T) {
	keyring.MockInit() // reset to clean state

	if err := auth.StoreTokenInKeychain("to-be-deleted"); err != nil {
		t.Fatalf("StoreTokenInKeychain: %v", err)
	}

	if err := auth.DeleteTokenFromKeychain(); err != nil {
		t.Fatalf("DeleteTokenFromKeychain: %v", err)
	}

	t.Setenv("JA4PROXY_TOKEN", "")
	got := auth.ResolveTokenWithKeychain("")
	if got != "" {
		t.Errorf("after DeleteTokenFromKeychain: ResolveTokenWithKeychain = %q; want empty string", got)
	}
}

// TestResolveTokenWithKeychain_PrecedenceTable is a table-driven test
// documenting the full precedence chain for keychain resolution.
func TestResolveTokenWithKeychain_PrecedenceTable(t *testing.T) {
	tests := []struct {
		name       string
		flag       string
		env        string
		keyringVal string // set in mock keyring; "" means not stored
		want       string
	}{
		{
			name:       "flag_wins_over_all",
			flag:       "flag-tok",
			env:        "env-tok",
			keyringVal: "ring-tok",
			want:       "flag-tok",
		},
		{
			name:       "env_wins_over_keyring",
			flag:       "",
			env:        "env-tok",
			keyringVal: "ring-tok",
			want:       "env-tok",
		},
		{
			name:       "keyring_used_when_no_flag_or_env",
			flag:       "",
			env:        "",
			keyringVal: "ring-tok",
			want:       "ring-tok",
		},
		{
			name:       "all_empty_returns_empty",
			flag:       "",
			env:        "",
			keyringVal: "",
			want:       "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyring.MockInit() // fresh mock for each sub-test
			if tc.keyringVal != "" {
				if err := keyring.Set("ja4proxy-cli", "token", tc.keyringVal); err != nil {
					t.Fatalf("keyring.Set: %v", err)
				}
			}
			t.Setenv("JA4PROXY_TOKEN", tc.env)

			got := auth.ResolveTokenWithKeychain(tc.flag)
			if got != tc.want {
				t.Errorf("ResolveTokenWithKeychain(%q) env=%q keyring=%q = %q; want %q",
					tc.flag, tc.env, tc.keyringVal, got, tc.want)
			}
		})
	}
}
