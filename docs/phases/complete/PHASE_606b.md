# Transport Splice, Buffer Replay & Packet Slicing Invariants

## Goal
Implement property-based invariant test suites for JA4proxy's transport splice and data plane forwarding engine (`cmd/ja4pd`). Establish formal guarantees that arbitrary network packetization (1-byte TCP trickles, pathological segment boundaries, MTU variations) does not mutate upstream payload delivery, that pre-read ClientHello handshake buffers are replayed losslessly to upstream servers, and that streaming backpressure prevents unbounded memory growth.

---

## Read These First
- `cmd/ja4pd/main.go` (`handleConn`, `forward`, `reassembleClientHello`, non-TLS drop)
- `cmd/ja4pd/lifecycle_test.go` (`newTestProxy`, `startEchoServer`, `startDiscardServer`)
- `cmd/ja4pd/pentest_fragmentation_regression_test.go` (existing fragmentation tests)
- `cmd/ja4pd/pentest_pooled_buffer_alias_test.go` (existing buffer aliasing checks)
- `cmd/ja4pd/pentest_tls_protocol_lockdown_regression_test.go` (non-TLS lockdown behavior)

---

## Verified API Surface
- `newTestProxy(t *testing.T) (*proxy, *miniredis.Miniredis, *config.Config)` — `cmd/ja4pd/lifecycle_test.go:31`
- `startEchoServer(t *testing.T) (string, func())` — `cmd/ja4pd/lifecycle_test.go:81`
- `startDiscardServer(t *testing.T) (string, func())` — `cmd/ja4pd/lifecycle_test.go:105`
- `ja4proxy_connection_errors_total{reason="non_tls_dropped"}` — `cmd/ja4pd/main.go:652`
- `tlsfixture.Build(spec)` — `internal/testutil/tlsfixture/builder.go`

---

## Invariants

| ID | Plain-English Statement | Formal Statement | SecOps Rationale |
|---|---|---|---|
| `INV-SPLICE-001` | Homomorphic Packet Partitioning | $\forall S = H \circ P, \forall \{c_i\} \text{ s.t. } \sum c_i = S, \quad \mathcal{D}_{\text{upstream}}(\circ c_i) \equiv S$ | Prevents TCP segmentation trickles or fragmentation attacks from bypassing security inspection or corrupting proxy streams. |
| `INV-SPLICE-002` | Lossless ClientHello Replay | $\text{UpstreamReceived}[:\|H\|] \equiv \text{ClientSent}[:\|H\|]$ | Guarantees the pre-read TLS ClientHello is forwarded to the backend without missing or duplicated bytes. |
| `INV-SPLICE-003` | Backpressure Buffer Bounding | $R_{\text{upstream}} \to 0 \implies \text{BufferAllocated}_{\text{proxy}} \le 64\,\text{MiB}$ | Ensures slow or stalled backend servers trigger TCP window backpressure rather than consuming proxy memory. |
| `INV-SPLICE-004` | Non-TLS Lockdown Fail-Closed | $\text{ProtocolLockdown} \land \neg \text{IsTLS}(x) \implies \text{Forwarded}(x) == 0$ | Guarantees non-TLS traffic (HTTP/1.1, SSH, noise) is immediately terminated when protocol lockdown is active. |

---

## Step-by-Step Implementation Guide

### Step 1: Create `cmd/ja4pd/splice_invariant_test.go`
```go
package main

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"pgregory.net/rapid"
	"github.com/seanpor/ja4proxy/internal/testutil/tlsfixture"
)

func TestInvariant_Splice_HomomorphicChunkSlicingAndReplay(t *testing.T) {
	p, mr, cfg := newTestProxy(t)
	defer mr.Close()
	defer p.Stop()

	// Configure proxy to allow test JA4
	spec := tlsfixture.Spec{}
	hello := tlsfixture.Build(spec)

	echoAddr, cleanupEcho := startEchoServer(t)
	defer cleanupEcho()
	cfg.Proxy.Upstream = echoAddr

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	go p.serveOnListener(listener)

	rapid.Check(t, func(t *rapid.T) {
		appDataLen := rapid.IntRange(1024, 16384).Draw(t, "appDataLen")
		appData := make([]byte, appDataLen)
		_, _ = rand.Read(appData)
		fullPayload := append(hello, appData...)

		chunkSizes := []int{1, 7, 64, 512, 1460}
		chunkSize := rapid.SampledFrom(chunkSizes).Draw(t, "chunkSize")

		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("Dial failed: %v", err)
		}
		defer conn.Close()

		go func() {
			for i := 0; i < len(fullPayload); i += chunkSize {
				end := i + chunkSize
				if end > len(fullPayload) {
					end = len(fullPayload)
				}
				_, _ = conn.Write(fullPayload[i:end])
				time.Sleep(100 * time.Microsecond)
			}
		}()

		received := make([]byte, len(fullPayload))
		_, err = io.ReadFull(conn, received)
		if err != nil {
			t.Fatalf("Read failed for chunk size %d: %v", chunkSize, err)
		}

		if !bytes.Equal(received, fullPayload) {
			t.Fatalf("Stream corrupted for chunk size %d", chunkSize)
		}
	})
}
```

---

## Make It Fail First

| Invariant ID | Temporary Code Mutation | Expected Test Failure |
|---|---|---|
| `INV-SPLICE-001` | Skip first byte when reassembling initial data in `forward()` | `TestInvariant_Splice_HomomorphicChunkSlicingAndReplay` fails byte comparison |
| `INV-SPLICE-002` | Omit `initialData` prepend when initiating backend splice | `TestInvariant_Splice_HomomorphicChunkSlicingAndReplay` fails on prefix match |
| `INV-SPLICE-003` | Remove `SetReadDeadline` or window backpressure in splice loop | Backpressure test exceeds memory threshold |
| `INV-SPLICE-004` | Comment out non-TLS drop branch in `handleConn` | Non-TLS lockdown invariant test receives forwarded bytes |

---

## Test Commands

- **Run Splice Invariants:**
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./cmd/ja4pd -run '^TestInvariant_Splice_'`
- **Run Invariant Suite:**
  `make test-invariants`

---

## Coverage Target

- **Package `cmd/ja4pd` Baseline:** 80.1%
- **Target Coverage:** $\ge 85.0\%$

---

## Acceptance Criteria

- [ ] `cmd/ja4pd/splice_invariant_test.go` created and all 4 invariants passing.
- [ ] Invariants registered in `docs/testing/invariants.yaml`.
- [ ] `make test-invariants` count increased by 4.
- [ ] Package `cmd/ja4pd` coverage verified $\ge 85.0\%$.
- [ ] Mutation check table verified.
- [ ] News fragment created in `docs/fragments/phase-606b-splice-invariants.md`.
- [ ] `make preflight` passes 100% green.

---

## Out of Scope
- Server package extraction (covered in Phase 606s).
- TLS parsing internals (covered in Phase 606a).
