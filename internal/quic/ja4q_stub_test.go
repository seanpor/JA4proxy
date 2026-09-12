// SPDX-License-Identifier: MIT

//go:build no_ja4plus

package quic

import (
	"testing"
)

func TestComputeJA4Q_Stub(t *testing.T) {
	features := &ClientHelloFeatures{
		SNI: "example.com",
	}
	if got := ComputeJA4Q(Version1, features); got != "" {
		t.Fatalf("ComputeJA4Q() = %q, want empty string in no_ja4plus build", got)
	}
}
