# QUIC Initial Decoder Invariants & Coverage

## Goal
Implement property-based invariant test suites and expand statement coverage for JA4proxy's QUIC Initial packet decoding and fingerprinting engine (`internal/quic/`). Elevate package coverage from 55.5% to $\ge 85.0\%$.

---

## Read These First
- `internal/quic/decoder.go` (`Decoder`, `DecodeInitial`, LRU eviction)
- `internal/quic/crypto.go` (`ParseCRYPTOFrames`, `WrapInTLSRecord`)
- `internal/quic/ja4q.go` (`ComputeJA4Q`, `ParseClientHelloFeatures`)
- `internal/quic/keylog.go` (`KeyLog`, `DeriveInitialKey`, `DecryptInitial`)

---

## Verified API Surface
- `quic.NewDecoder(keyLog)` — `internal/quic/decoder.go`
- `(*Decoder).DecodeInitial(packet []byte)` — `internal/quic/decoder.go`
- `quic.ParseCRYPTOFrames(payload []byte)` — `internal/quic/crypto.go`
- `quic.ComputeJA4Q(version uint32, features *ClientHelloFeatures)` — `internal/quic/ja4q.go`

---

## Invariants

| ID | Plain-English Statement | Formal Statement | SecOps Rationale |
|---|---|---|---|
| `INV-QUIC-001` | CRYPTO Frame Reassembly Commutativity | $\text{ParseCRYPTO}(\pi(\text{Frames})) \equiv \text{ParseCRYPTO}(\text{Frames})$ | Prevents out-of-order QUIC frame arrivals from distorting extracted ClientHello payloads or JA4Q fingerprints. |
| `INV-QUIC-002` | Decoder LRU Cache Eviction Bound | $\text{ActiveCount}() \le \text{MaxStreams}$ | Ensures high-volume QUIC connection attempts do not exhaust memory in key decryption tables. |
| `INV-QUIC-003` | JA4Q Regex Grammar Adherence | $\forall H_{\text{quic}}, \quad \text{ComputeJA4Q}(v, H) \in \mathcal{L}(\text{JA4Q\_REGEX})$ | Guarantees all emitted QUIC fingerprints match the FoxIO standard format (`q[0-9]{2}...`). |
| `INV-QUIC-004` | Initial Decrypt Totality | $\forall b \in \{0,1\}^*, \quad \text{Panic}(\text{DecodeInitial}(b)) == \text{false}$ | Ensures corrupt or malformed QUIC Initial headers emit typed errors without crashing decoders. |

---

## Step-by-Step Implementation Guide

### Step 1: Create `internal/quic/quic_invariant_test.go`
```go
package quic_test

import (
	"regexp"
	"testing"

	"github.com/seanpor/ja4proxy/internal/quic"
	"pgregory.net/rapid"
)

var ja4qRegex = regexp.MustCompile(`^q[0-9]{2}[di][0-9]{2}[0-9]{2}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)

func TestInvariant_QUIC_DecoderTotality(t *testing.T) {
	decoder := quic.NewDecoder(nil)

	rapid.Check(t, func(t *rapid.T) {
		payload := rapid.SliceOf(rapid.Byte()).Draw(t, "payload")
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Panic during DecodeInitial: %v", r)
				}
			}()
			_, _ = decoder.DecodeInitial(payload)
		}()
	})
}
```

---

## Make It Fail First

| Invariant ID | Temporary Code Mutation | Expected Test Failure |
|---|---|---|
| `INV-QUIC-001` | Disable offset-sorting in `ParseCRYPTOFrames` | Frame reassembly test fails on permuted frames |
| `INV-QUIC-002` | Remove eviction call in `FlushEvicted` | LRU cache test detects active count exceeding bound |
| `INV-QUIC-003` | Hardcode `q` prefix to `x` in `ja4q.go` | JA4Q grammar test fails regex match |
| `INV-QUIC-004` | Remove slice length validation in `DecryptInitial` | Decoder totality test detects slice index out of bounds panic |

---

## Test Commands

- **Run QUIC Invariants:**
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./internal/quic -run '^TestInvariant_QUIC_'`
- **Run Invariant Suite:**
  `make test-invariants`

---

## Coverage Target

- **Package `internal/quic` Baseline:** 55.5%
- **Target Coverage:** $\ge 85.0\%$

---

## Acceptance Criteria

- [ ] `internal/quic/quic_invariant_test.go` created and all 4 invariants passing.
- [ ] Invariants registered in `docs/testing/invariants.yaml`.
- [ ] `make test-invariants` count increased by 4.
- [ ] Package `internal/quic` coverage verified $\ge 85.0\%$.
- [ ] Mutation check table verified.
- [ ] News fragment created in `docs/fragments/phase-606h-quic-invariants.md`.
- [ ] `make preflight` passes 100% green.

---

## Out of Scope
- TLS 1.3 TCP parsing (covered in Phase 606a).
