# Passive TAP & Flow Reassembly Invariants

## Goal
Implement property-based invariant test suites for JA4proxy's passive network tap and TCP stream reassembly engine (`cmd/ja4-tap/` and `internal/tap/`). Establish formal mathematical guarantees that out-of-order TCP segment arrivals reassemble into byte-identical streams (commutativity), that duplicate TCP retransmissions are idempotently filtered without byte duplication, that corrupt or out-of-window packets are safely rejected without state corruption, and that inactive/terminated flows are purged to guarantee zero memory growth in flow tracking tables.

---

## Scope
1. **Target Packages**:
   - `cmd/ja4-tap/` (Passive packet capture, TCP flow reassembly, JA4/JA4S/JA4Q extraction).
   - `internal/tap/` (Flow table state, segment queues, eviction policies).
2. **New Test Files**:
   - `cmd/ja4-tap/reassembly_invariant_test.go`
3. **Formal Invariants to Enforce**:
   - **Invariant 1 (TCP Reassembly Commutativity)**:
     Let $P = [p_1, p_2, \dots, p_k]$ be the sequence of TCP segments forming a TLS ClientHello, and $\pi(P)$ be any arbitrary permutation of $P$. If all packets arrive within the reassembly window:
     $$\text{Reassemble}(\pi(P)) \equiv \text{Reassemble}(P)$$
     The reassembled byte stream and resulting JA4 fingerprint must be identical regardless of packet arrival order.
   - **Invariant 2 (Idempotent Segment Deduplication)**:
     Injecting duplicate TCP segments (e.g. $[p_1, p_1, p_2, p_2, p_3]$) must yield the exact same byte stream as $[p_1, p_2, p_3]$ without double-counting bytes or shifting sequence offsets.
   - **Invariant 3 (Corrupt & Out-of-Window Safety)**:
     Segments with sequence numbers outside the valid reassembly window or with truncated IP/TCP headers must be safely discarded. The parser must never crash or corrupt existing flow state.
   - **Invariant 4 (Flow Table Bounding & Purge)**:
     Upon observing TCP FIN/RST or upon expiration of `FlowInactivityTimeout`, the flow tracking entry must be deleted from memory. $\Delta\text{Flows} = 0$ after flow completion.

---

## Junior Developer Implementation Guide

### Step 1: Set up Test Harness & Packet Generator
In `cmd/ja4-tap/reassembly_invariant_test.go`:
```go
package main_test

import (
	"bytes"
	"math/rand"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	// Import tap internal packages
)
```

Construct a helper `BuildTCPSegments(clientHello []byte, segmentSize int) []gopacket.Packet` that packages a ClientHello payload into simulated IPv4/TCP packets with proper sequence numbers (`SeqNum`, `AckNum`, SYN/ACK handshake setup).

### Step 2: Implement Invariant 1 Test (Commutativity under Permutation)
```go
func TestInvariant_TCPReassemblyCommutativity(t *testing.T) {
	baselineHello := getBaselineClientHello()
	segments := BuildTCPSegments(baselineHello, 64) // split into 64-byte TCP packets

	// Test 50 randomized permutations
	for iteration := 0; iteration < 50; iteration++ {
		shuffled := make([]gopacket.Packet, len(segments))
		copy(shuffled, segments)

		// Shuffle packets
		rand.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})

		// Feed shuffled packets to flow reassembler
		reassembler := newTestFlowReassembler()
		for _, pkt := range shuffled {
			reassembler.ProcessPacket(pkt)
		}

		// Assert reassembled stream matches baseline byte-for-byte
		reassembled := reassembler.GetStream()
		if !bytes.Equal(reassembled, baselineHello) {
			t.Fatalf("Permutation %d failed to reassemble correctly: got %d bytes, want %d",
				iteration, len(reassembled), len(baselineHello))
		}
	}
}
```

### Step 3: Implement Invariant 2 Test (Deduplication)
```go
func TestInvariant_SegmentDeduplication(t *testing.T) {
	baselineHello := getBaselineClientHello()
	segments := BuildTCPSegments(baselineHello, 128)

	// Interleave duplicates: [p0, p0, p1, p1, p2, p2...]
	var duplicated []gopacket.Packet
	for _, seg := range segments {
		duplicated = append(duplicated, seg, seg)
	}

	reassembler := newTestFlowReassembler()
	for _, pkt := range duplicated {
		reassembler.ProcessPacket(pkt)
	}

	if !bytes.Equal(reassembler.GetStream(), baselineHello) {
		t.Fatalf("Duplicate segments corrupted stream reassembly")
	}
}
```

### Step 4: Implement Invariant 3 Test (Out-of-Window Safety)
Inject packet with sequence number $+1,000,000$ beyond current window.
Verify packet is dropped, metric `tap_out_of_window_packets_total` increments, and flow continues reassembling valid in-window packets normally.

### Step 5: Implement Invariant 4 Test (Flow Table Bounding)
1. Check flow table count ($C_0$).
2. Inject 100 complete TLS handshakes followed by TCP FIN.
3. Advance mock clock beyond inactivity threshold.
4. Assert flow table count returns to $C_0$ (zero dangling memory).

---

## Test Strategy
- Run TAP invariant tests:
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./cmd/ja4-tap -run ReassemblyInvariant`
- Run with race detector:
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -race -v ./cmd/ja4-tap`

---

## Acceptance Criteria
- [ ] `cmd/ja4-tap/reassembly_invariant_test.go` implemented and passing.
- [ ] TCP segment reassembly proven commutative across 50+ random arrival permutations.
- [ ] Duplicate segment injection proven idempotent without byte drift.
- [ ] Out-of-window and corrupt packets dropped cleanly with metrics recorded.
- [ ] Flow table entries confirmed purged upon stream termination.
- [ ] `make test-unit` and `make preflight` pass 100% green.

---

## Out of Scope
- Active proxy forwarding (covered in 606b).
- Rate limiter state store (covered in 606d).
