# Cryptographic & TLS Parsing Invariants

## Goal
Implement property-based invariant test suites for JA4proxy's TLS ClientHello parsing engine (`internal/tls`). Establish formal guarantees that the parser is total (never panics or loops indefinitely on any byte slice), strictly adheres to canonical JA4 grammar, handles GREASE permutations with zero fingerprint drift, and ensures extension-order permutations do not mutate the canonical JA4 fingerprint.

---

## Read These First
- `internal/tls/parser.go` (ClientHello record decoding and extension parsing)
- `internal/tls/hello_info.go` (ClientHelloInfo struct and ComputeJA4 algorithm)
- `internal/tls/fuzz_test.go` (existing Go fuzz targets)
- `internal/tls/bench_test.go` (existing ClientHello benchmark helpers)
- `tests/fixtures/clienthello/README.md` (canonical test fixture corpus)

---

## Verified API Surface
- `tlsparse.ParseClientHello(data []byte) (*ClientHelloInfo, error)` — `internal/tls/parser.go:78`
- `tlsparse.ComputeJA4(info *ClientHelloInfo) string` — `internal/tls/hello_info.go:12`
- `tlsparse.ClientHelloInfo` — `internal/tls/hello_info.go:5`
- `tlsfixture.Build(spec)` — `internal/testutil/tlsfixture/builder.go`
- `tlsfixture.GenSpec()` — `internal/testutil/tlsfixture/gen.go`

---

## Invariants

| ID | Plain-English Statement | Formal Statement | SecOps Rationale |
|---|---|---|---|
| `INV-TLS-001` | GREASE Independence | $\forall H, \forall G \subseteq \text{GREASE}, \quad \text{ComputeJA4}(H \oplus G) \equiv \text{ComputeJA4}(H)$ | Prevents attackers from evading JA4 detection by injecting RFC 8701 GREASE values into TLS handshakes. |
| `INV-TLS-002` | Extension Permutation Invariance | $\forall H, \quad \text{ComputeJA4}(\text{PermuteExts}(H)) \equiv \text{ComputeJA4}(H)$ | Guarantees canonical sorting of extensions so wire-order variation does not cause fingerprint fragmentation. |
| `INV-TLS-003` | Canonical JA4 Grammar Adherence | $\forall H, \quad \text{ComputeJA4}(H) \in \mathcal{L}(\text{JA4\_REGEX})$ | Ensures all emitted fingerprints match FoxIO standard `t[0-9]{2}[di][0-9]{2}[0-9]{2}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}` (36 chars). |
| `INV-TLS-004` | Parser Totality & Non-Panic | $\forall b \in \{0,1\}^*, \quad \text{Panic}(\text{ParseClientHello}(b)) == \text{false}$ | Guarantees malformed or truncated byte sequences emit typed errors without crashing proxy worker goroutines. |

---

## Step-by-Step Implementation Guide

### Step 1: Create `internal/tls/invariant_test.go`
```go
package tls_test

import (
	"regexp"
	"testing"

	"pgregory.net/rapid"
	tlsparse "github.com/seanpor/ja4proxy/internal/tls"
	"github.com/seanpor/ja4proxy/internal/testutil/tlsfixture"
)

var ja4Regex = regexp.MustCompile(`^t[0-9]{2}[di][0-9]{2}[0-9]{2}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)

func TestInvariant_TLS_GREASEIndependence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		spec := tlsfixture.GenSpec().Draw(t, "spec")
		baselineRaw := tlsfixture.Build(spec)
		infoBaseline, err := tlsparse.ParseClientHello(baselineRaw)
		if err != nil {
			t.Skip()
		}
		baselineJA4 := tlsparse.ComputeJA4(infoBaseline)

		greaseVal := rapid.SampledFrom(tlsfixture.GREASE[:]).Draw(t, "grease")
		greaseSpec := tlsfixture.WithGREASE(spec, greaseVal)
		greaseRaw := tlsfixture.Build(greaseSpec)
		infoGrease, err := tlsparse.ParseClientHello(greaseRaw)
		if err != nil {
			t.Fatalf("Failed to parse ClientHello with injected GREASE 0x%04x: %v", greaseVal, err)
		}
		greaseJA4 := tlsparse.ComputeJA4(infoGrease)

		if greaseJA4 != baselineJA4 {
			t.Fatalf("GREASE 0x%04x mutated JA4: got %s, want %s", greaseVal, greaseJA4, baselineJA4)
		}
	})
}

func TestInvariant_TLS_ExtensionPermutationInvariance(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		spec := tlsfixture.GenSpec().Draw(t, "spec")
		seed := rapid.Int64().Draw(t, "seed")
		shuffledSpec := tlsfixture.ShuffleExtensions(spec, seed)

		infoA, errA := tlsparse.ParseClientHello(tlsfixture.Build(spec))
		infoB, errB := tlsparse.ParseClientHello(tlsfixture.Build(shuffledSpec))
		if errA != nil || errB != nil {
			t.Skip()
		}

		ja4A := tlsparse.ComputeJA4(infoA)
		ja4B := tlsparse.ComputeJA4(infoB)
		if ja4A != ja4B {
			t.Fatalf("Extension permutation mutated JA4: got %s vs %s", ja4A, ja4B)
		}
	})
}

func TestInvariant_TLS_GrammarAdherence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		spec := tlsfixture.GenSpec().Draw(t, "spec")
		info, err := tlsparse.ParseClientHello(tlsfixture.Build(spec))
		if err != nil {
			t.Skip()
		}
		ja4 := tlsparse.ComputeJA4(info)
		if !ja4Regex.MatchString(ja4) {
			t.Fatalf("JA4 %q violates canonical regex grammar", ja4)
		}
	})
}

func TestInvariant_TLS_ParserTotality(t *testing.T) {
	corpus := tlsfixture.Corpus(t)
	for _, entry := range corpus {
		for i := len(entry.Raw); i >= 0; i-- {
			truncated := entry.Raw[:i]
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("Panic on truncated ClientHello %s at len %d: %v", entry.Name, i, r)
					}
				}()
				_, _ = tlsparse.ParseClientHello(truncated)
			}()
		}
	}
}
```

---

## Make It Fail First

| Invariant ID | Temporary Code Mutation | Expected Test Failure |
|---|---|---|
| `INV-TLS-001` | Remove GREASE filtering from extension/cipher loop in `internal/tls/parser.go` | `TestInvariant_TLS_GREASEIndependence` fails with JA4 hash mismatch |
| `INV-TLS-002` | Disable sorting of extension types in `internal/tls/hello_info.go` | `TestInvariant_TLS_ExtensionPermutationInvariance` fails with mismatched extension hash |
| `INV-TLS-003` | Hardcode separator char as `-` instead of `_` in `hello_info.go` | `TestInvariant_TLS_GrammarAdherence` fails regex validation |
| `INV-TLS-004` | Remove slice length check before reading extension length byte in `parser.go` | `TestInvariant_TLS_ParserTotality` fails with index out of range panic |

---

## Test Commands

- **Run TLS Invariants:**
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./internal/tls -run '^TestInvariant_TLS_'`
- **Run Invariant Suite:**
  `make test-invariants`

---

## Coverage Target

- **Package `internal/tls` Baseline:** 88.8%
- **Target Coverage:** $\ge 95.0\%$

---

## Acceptance Criteria

- [ ] `internal/tls/invariant_test.go` created and all 4 invariants passing.
- [ ] Invariants registered in `docs/testing/invariants.yaml`.
- [ ] `make test-invariants` count increased by 4.
- [ ] Package coverage verified $\ge 95.0\%$.
- [ ] Mutation check table verified (each test proven capable of failing).
- [ ] News fragment created in `docs/fragments/phase-606a-tls-invariants.md`.
- [ ] `make preflight` passes 100% green.

---

## Out of Scope
- QUIC Initial parsing (covered in Phase 606h).
- Proxy transport splicing (covered in Phase 606b).
