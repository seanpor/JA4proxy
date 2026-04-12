// Package auth provides token and URL resolution for the ja4proxy-cli.
// Resolution order for token without keychain: flag value → environment variable → empty string.
// Resolution order with keychain enabled: flag value → environment variable → OS keyring → empty string.
package auth

import (
	"os"

	"github.com/zalando/go-keyring"
)

const (
	// keyringService is the service name used to store the token in the OS keyring.
	keyringService = "ja4proxy-cli"
	// keyringUser is the user/account name under which the token is stored.
	keyringUser = "token"
)

// ResolveToken returns the API bearer token.
// Resolution order: flagValue → JA4PROXY_TOKEN env var → "".
func ResolveToken(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv("JA4PROXY_TOKEN")
}

// ResolveTokenWithKeychain extends ResolveToken with a keychain fallback.
// Resolution order: flagValue → JA4PROXY_TOKEN env var → OS keyring → "".
// If the keyring is unavailable (e.g. headless server without a secret-service
// daemon), the error is silently ignored and "" is returned — callers must
// handle the case where no token is available.
func ResolveTokenWithKeychain(flagValue string) string {
	if tok := ResolveToken(flagValue); tok != "" {
		return tok
	}
	tok, err := keyring.Get(keyringService, keyringUser)
	if err == nil && tok != "" {
		return tok
	}
	return ""
}

// StoreTokenInKeychain stores a token in the OS keyring (macOS Keychain,
// Linux Secret Service / kwallet, Windows Credential Manager).
// Returns an error if the keyring service is unavailable.
func StoreTokenInKeychain(token string) error {
	return keyring.Set(keyringService, keyringUser, token)
}

// DeleteTokenFromKeychain removes the stored token from the OS keyring.
// Returns an error if the token was not found or the keyring is unavailable.
func DeleteTokenFromKeychain() error {
	return keyring.Delete(keyringService, keyringUser)
}

// ResolveURL returns the Management API base URL.
// Resolution order: flagValue → JA4PROXY_URL env var → "".
func ResolveURL(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv("JA4PROXY_URL")
}
