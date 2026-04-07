// Package auth provides token and URL resolution for the ja4proxy-cli.
// Resolution order for both token and URL: flag value → environment variable → empty string.
package auth

import "os"

// ResolveToken returns the API bearer token.
// Resolution order: flagValue → JA4PROXY_TOKEN env var → "".
func ResolveToken(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv("JA4PROXY_TOKEN")
}

// ResolveURL returns the Management API base URL.
// Resolution order: flagValue → JA4PROXY_URL env var → "".
func ResolveURL(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv("JA4PROXY_URL")
}
