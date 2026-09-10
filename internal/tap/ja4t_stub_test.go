// SPDX-License-Identifier: MIT

//go:build no_ja4plus

package tap

import (
	"testing"
)

func TestComputeJA4T_Stub(t *testing.T) {
	var f StackFeatures
	f.HasSYN = true
	if got := ComputeJA4T(f); got != "" {
		t.Fatalf("ComputeJA4T() = %q, want empty string in no_ja4plus build", got)
	}
}
