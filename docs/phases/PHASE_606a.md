# Cryptographic, TLS & QUIC Parsing Invariants

## Goal
Implement rigorous, property-based invariant test suites for JA4proxy's core cryptographic and protocol parsing engines (`internal/tls/`, `internal/fingerprint/`, and `internal/quic/`). Establish formal mathematical guarantees that the parser is total (never panics or loops indefinitely on any byte sequence), strictly adheres to canonical JA4 grammar, handles GREASE permutations with zero fingerprint drift, and properly maintains the duality between canonical (`JA4`) and raw wire-order (`JA4_r`) fingerprints.

---

## Scope
1. **Target Packages**:
   - `internal/tls/` (ClientHello parsing, extension extraction, SNI/ALPN extraction).
   - `internal/fingerprint/` (JA4 and JA4_r computation, hashing, formatting).
   - `internal/quic/` (QUIC Initial packet decoding, Crypto frame reassembly, JA4Q extraction).
2. **New Test Files**:
   - `internal/tls/invariant_test.go`
   - `internal/fingerprint/invariant_test.go`
   - `internal/quic/invariant_test.go`
3. **Formal Invariants to Enforce**:
   - **Invariant 1 (GREASE Independence)**: Injecting any combination or permutation of GREASE cipher suites (0x0A0A..0xFAFA), extensions, or supported groups must yield the exact same canonical JA4 fingerprint.
   - **Invariant 2 (Strict Alphabet & Grammar)**: Every computed JA4 string must strictly match the canonical regex `^[tq][0-9]{2}[di][0-9]{2}[0-9]{2}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$` (length exactly 36 chars).
   - **Invariant 3 (Total Function / Non-Panic)**: For any arbitrary byte slice $b \in \{0, 1\}^*$, calling `ParseClientHello(b)` or `ParseQUICInitial(b)` returns a typed error (`ErrTruncated`, `ErrMalformed`) or a valid record. It must NEVER panic, never enter an infinite loop, and memory allocation must be strictly bounded $O(|b|)$.
   - **Invariant 4 (Wire Order Duality)**: Permuting non-GREASE extensions must yield an identical `JA4` fingerprint (canonical sorted order) but a distinct `JA4_r` fingerprint (raw wire order).
   - **Invariant 5 (SNI & ALPN Normalization)**: Extracted SNIs must be lowercase 7-bit ASCII without null bytes or control characters. Empty or absent ALPN must emit '00'; valid ALPNs must map to their 2-character prefix per JA4 specification.

---

## Junior Developer Implementation Guide

### Step 1: Set up Test Harness & Imports
In `internal/tls/invariant_test.go`:
```go
package tls_test

import (
	"bytes"
	"crypto/rand"
	"regexp"
	"testing"
	"testing/quick"

	"github.com/seanpor/ja4proxy/internal/fingerprint"
	"github.com/seanpor/ja4proxy/internal/tls"
)
```

### Step 2: Implement GREASE Table and Injection Generator
Define the canonical RFC 8701 GREASE values:
```go
var greaseValues = []uint16{
	0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
	0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}
```
Construct a helper `InjectGREASE(clientHello []byte, greaseVal uint16) []byte` that inserts a GREASE cipher suite and a GREASE extension into a valid baseline ClientHello payload.

### Step 3: Implement Invariant 1 Test (GREASE Independence)
```go
func TestInvariant_GREASEIndependence(t *testing.T) {
	baselineHello := getBaselineClientHello() // load fixture or generate standard TLS 1.3 ClientHello
	baselineJA4 := fingerprint.ComputeJA4(baselineHello)

	for _, g := range greaseValues {
		mutatedHello := InjectGREASE(baselineHello, g)
		mutatedJA4 := fingerprint.ComputeJA4(mutatedHello)

		if mutatedJA4 != baselineJA4 {
			t.Fatalf("GREASE value 0x%04x caused JA4 drift: got %s, want %s", g, mutatedJA4, baselineJA4)
		}
	}
}
```

### Step 4: Implement Invariant 2 Test (Grammar & Regex Enforcement)
```go
var ja4Regex = regexp.MustCompile(`^[tq][0-9]{2}[di][0-9]{2}[0-9]{2}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)

func TestInvariant_GrammarAdherence(t *testing.T) {
	property := func(raw []byte) bool {
		fp, err := fingerprint.Compute(raw)
		if err != nil {
			return true // Errored safely, valid
		}
		return ja4Regex.MatchString(fp.JA4) && len(fp.JA4) == 36
	}

	config := &quick.Config{MaxCount: 5000}
	if err := quick.Check(property, config); err != nil {
		t.Fatalf("Grammar invariant violated: %v", err)
	}
}
```

### Step 5: Implement Invariant 3 Test (Total Function / Truncation Non-Panic)
Test that systematically truncating a valid ClientHello byte-by-byte from length $N$ down to 0 never triggers a panic or runtime crash:
```go
func TestInvariant_PrefixTruncationTotalFunction(t *testing.T) {
	hello := getBaselineClientHello()
	for i := len(hello); i >= 0; i-- {
		truncated := hello[:i]
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Panic on prefix truncation at length %d: %v", i, r)
				}
			}()
			_, _ = tls.ParseClientHello(truncated)
		}()
	}
}
```

### Step 6: Implement Invariant 4 Test (Wire Order Duality)
In `internal/fingerprint/invariant_test.go`:
Take two extensions $E_1$ and $E_2$.
Construct $H_A$ with order $[E_1, E_2]$ and $H_B$ with order $[E_2, E_1]$.
Assert:
- `ComputeJA4(H_A) == ComputeJA4(H_B)` (Canonical sort)
- `ComputeJA4_r(H_A) != ComputeJA4_r(H_B)` (Raw order preserved)

### Step 7: QUIC Invariants
In `internal/quic/invariant_test.go`:
Apply the same non-panic and grammar validation against `ParseQUICInitial` with corrupted header flags, truncated connection IDs, and randomized token lengths.

---

## Test Strategy
- Run natively using snap Go toolchain:
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./internal/tls ./internal/fingerprint ./internal/quic -run Invariant`
- Run with race detector:
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -race ./internal/tls ./internal/fingerprint ./internal/quic`
- Validate that standard unit tests continue passing:
  `make test-unit`

---

## Acceptance Criteria
- [ ] `internal/tls/invariant_test.go` implemented and passing.
- [ ] `internal/fingerprint/invariant_test.go` implemented and passing.
- [ ] `internal/quic/invariant_test.go` implemented and passing.
- [ ] 100% adherence to JA4 grammar across 5,000+ randomized fuzz iterations.
- [ ] Zero panics on prefix truncation and arbitrary bit flips.
- [ ] GREASE independence verified against all 16 RFC 8701 values.
- [ ] Full preflight (`make preflight`) passes 100% green.

---

## Out of Scope
- Proxy transport splicing (covered in 606b).
- Rate limiter state store (covered in 606d).
- Changing JA4 specification algorithms.
