// SPDX-License-Identifier: MIT

//go:build no_ja4plus

package tls

import (
	"testing"
)

func TestExtractJA4X_Stub(t *testing.T) {
	expected := "000000000000_000000000000_000000000000"
	if got := ExtractJA4X([]byte("dummy")); got != expected {
		t.Fatalf("ExtractJA4X() = %q, want %q", got, expected)
	}
	if got := ExtractJA4XFromPEM([]byte("dummy")); got != expected {
		t.Fatalf("ExtractJA4XFromPEM() = %q, want %q", got, expected)
	}
}
