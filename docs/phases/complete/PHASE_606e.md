# Passive TAP & Flow Reassembly Invariants

## Goal
Implement property-based invariant test suites for JA4proxy's passive TAP and TCP stream reassembly engine (`internal/tap`). Establish formal guarantees that TCP stream buffers never exceed 16 KiB per direction, that exactly one HandshakeEvent is emitted per stream lifecycle, that expired or terminated streams are evicted cleanly from memory, and that the Redis circuit breaker trips deterministically under backend failures.

---

## Read These First
- `internal/tap/reassembler.go` (TCP stream reassembly and 16 KiB buffer cap)
- `internal/tap/sensor.go` (packet decoder and HandshakeEvent extraction)
- `internal/tap/circuit_breaker.go` (Redis circuit breaker implementation)
- `cmd/ja4-tap/operability_test.go` (TAP operability checks)

---

## Verified API Surface
- `NewRedisCircuitBreaker(inner)` — `internal/tap/circuit_breaker.go`
- `MarkGap()` — `internal/tap/reassembler.go`
- `github.com/gopacket/gopacket` — `go.mod`

---

## Invariants

| ID | Plain-English Statement | Formal Statement | SecOps Rationale |
|---|---|---|---|
| `INV-TAP-001` | 16 KiB Per-Direction Buffer Cap | $\forall \text{stream}, \quad \text{BufferLen}(\text{dir}) \le 16384$ | Prevents large network payload streams from exhausting memory on passive TAP sensor interfaces. |
| `INV-TAP-002` | Single HandshakeEvent Emission | $\forall \text{stream}, \quad \text{Count}(\text{HandshakeEvent}) \le 1$ | Guarantees fingerprint telemetry events are emitted idempotently without duplicate downstream signals. |
| `INV-TAP-003` | Active Stream Eviction | $\lim_{t \to t_{\text{expire}}} \text{ActiveStreams}(t) == 0$ | Ensures inactive or completed TCP streams are purged from state memory to prevent table memory leaks. |
| `INV-TAP-004` | Circuit Breaker Cooldown Exactness | $\text{Failures} \ge N \implies \text{Open} \land \text{ResetsAt}(t_{\text{cooldown}})$ | Prevents Redis degradation from blocking TAP packet capture loops while guaranteeing automatic recovery. |

---

## Step-by-Step Implementation Guide

### Step 1: Create `internal/tap/tap_invariant_test.go`
```go
package tap

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"pgregory.net/rapid"
)

func TestInvariant_Tap_BufferCap16KiB(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		chunkSize := rapid.IntRange(100, 4096).Draw(t, "chunkSize")
		numChunks := rapid.IntRange(5, 20).Draw(t, "numChunks")
		isClient := rapid.Bool().Draw(t, "isClient")

		s := &tlsStream{}
		data := make([]byte, chunkSize)
		for i := 0; i < len(data); i++ {
			data[i] = byte(i % 256)
		}

		for i := 0; i < numChunks; i++ {
			s.append(isClient, data)
		}

		bufLen := len(s.clientBuf)
		if !isClient {
			bufLen = len(s.serverBuf)
		}

		if bufLen > maxHandshakeBytes {
			t.Fatalf("Buffer cap exceeded: got %d bytes, max allowed is %d", bufLen, maxHandshakeBytes)
		}
	})
}
```

---

## Make It Fail First

| Invariant ID | Temporary Code Mutation | Expected Test Failure |
|---|---|---|
| `INV-TAP-001` | Increase buffer cap check from 16384 to 32768 in `reassembler.go` | Buffer cap test detects overflow |
| `INV-TAP-002` | Remove boolean `eventEmitted` flag check in `sensor.go` | Duplicate handshake event test fails |
| `INV-TAP-003` | Comment out map delete in stream eviction loop | Stream eviction test detects lingering entries |
| `INV-TAP-004` | Hardcode circuit breaker state to never reset | Cooldown exactness test fails recovery check |

---

## Test Commands

- **Run TAP Invariants:**
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./internal/tap -run '^TestInvariant_Tap_'`
- **Run Invariant Suite:**
  `make test-invariants`

---

## Coverage Target

- **Package `internal/tap` Baseline:** 79.9%
- **Target Coverage:** $\ge 85.0\%$

---

## Acceptance Criteria

- [x] `internal/tap/tap_invariant_test.go` created and all 4 invariants passing.
- [x] Invariants registered in `docs/testing/invariants.yaml`.
- [x] Package `internal/tap` coverage verified $\ge 85.0\%$.
- [x] Mutation check table verified.
- [x] News fragment created in `docs/fragments/phase-606e-tap-invariants.md`.
- [x] `make preflight` passes 100% green.

---

## Out of Scope
- Command-line flag parsing for `cmd/ja4-tap` (covered in Phase 606j).
- Active proxy splicing (covered in Phase 606b).
