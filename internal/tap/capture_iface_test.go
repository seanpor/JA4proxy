package tap

import "testing"

// TestCheckInterfaceUp exercises F-015's startup verification: capture
// should refuse to start against a nonexistent interface, and lo (present
// and up on every Linux host, including CI runners) should pass.
func TestCheckInterfaceUp(t *testing.T) {
	if err := checkInterfaceUp("lo"); err != nil {
		t.Fatalf("checkInterfaceUp(lo) = %v, want nil", err)
	}

	if err := checkInterfaceUp("ja4tap-does-not-exist0"); err == nil {
		t.Fatal("checkInterfaceUp(nonexistent) = nil, want error")
	}
}
