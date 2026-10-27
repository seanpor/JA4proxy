package tls

import (
	"testing"
)

func TestParseClientHello_AllocBudget(t *testing.T) {
	hello := generateTestClientHello()

	// Warm up
	if _, err := ParseClientHello(hello); err != nil {
		t.Fatalf("warmup failed: %v", err)
	}

	allocs := testing.AllocsPerRun(1000, func() {
		info, err := ParseClientHello(hello)
		if err != nil {
			t.Fatalf("ParseClientHello failed: %v", err)
		}
		_ = info
	})

	t.Logf("ParseClientHello allocs/run: %.2f", allocs)
	// Currently ~8 allocs/op. Budget gate: must never exceed 8, target <= 5
	if allocs > 8.0 {
		t.Errorf("ParseClientHello exceeded allocation budget: got %.2f, max allowed 8.0", allocs)
	}
}

func TestComputeJA4_AllocBudget(t *testing.T) {
	hello := generateTestClientHello()
	info, err := ParseClientHello(hello)
	if err != nil {
		t.Fatalf("ParseClientHello failed: %v", err)
	}

	// Warm up
	_ = ComputeJA4(info)

	allocs := testing.AllocsPerRun(1000, func() {
		ja4 := ComputeJA4(info)
		if ja4 == "" {
			t.Fatal("empty ja4")
		}
	})

	t.Logf("ComputeJA4 allocs/run: %.2f", allocs)
	// Reduced from ~41 allocs/op to 4 allocs/op (75% heap reduction).
	// Budget gate: must never exceed 5 allocs/run.
	if allocs > 5.0 {
		t.Errorf("ComputeJA4 exceeded allocation budget: got %.2f, max allowed 5.0", allocs)
	}
}
