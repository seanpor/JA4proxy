package tls

import "testing"

func TestJA4T_Empty(t *testing.T) {
	if got := ComputeJA4T(nil); got != "" {
		t.Errorf("ComputeJA4T(nil) = %q; want empty string", got)
	}
}

func TestJA4T_NoAlerts(t *testing.T) {
	if got := ComputeJA4T([]uint8{}); got != "" {
		t.Errorf("ComputeJA4T([]) = %q; want empty string", got)
	}
}
