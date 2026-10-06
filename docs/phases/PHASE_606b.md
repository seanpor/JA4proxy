# Transport Splice, Buffer Replay & Packet Slicing Invariants

## Goal
Implement property-based invariant test suites for JA4proxy's transport splice and data plane forwarding engines (`internal/proxy/`). Establish formal mathematical guarantees that arbitrary network packetization (such as 1-byte TCP window trickles, pathological segment boundaries, or varying MTUs) does not alter upstream payload delivery, that pre-read ClientHello handshake buffers are replayed losslessly without corruption or duplication, and that streaming backpressure is strictly enforced without unbounded memory growth.

---

## Scope
1. **Target Packages**:
   - `internal/proxy/` (TCP splice, handshake sniffing, connection piping, buffer pool recycling).
2. **New Test Files**:
   - `internal/proxy/splice_invariant_test.go`
3. **Formal Invariants to Enforce**:
   - **Invariant 1 (Homomorphic Packet Partitioning)**:
     For any valid connection stream $S$ composed of ClientHello $H$ followed by application payload $P$, splitting $S$ into arbitrary sequence of chunks $[c_1, c_2, \dots, c_k]$ where $\sum c_i = S$:
     - The proxy extracts the identical JA4 fingerprint regardless of chunk boundaries.
     - The upstream destination receives byte-identical stream $S' \equiv S$.
   - **Invariant 2 (Lossless ClientHello Replay)**:
     The initial bytes read by the proxy to extract TLS metadata must be prepended and forwarded to the upstream server upon splice initiation. The byte stream arriving at upstream must satisfy:
     $$\text{UpstreamReceived}[:|H|] == \text{ClientSent}[:|H|] \quad \land \quad \text{len}(\text{UpstreamReceived}) == \text{len}(\text{ClientSent})$$
     Zero bytes may be dropped, repeated, or corrupted.
   - **Invariant 3 (Streaming Backpressure & Memory Bounds)**:
     When an upstream server stalls reading from the proxy, downstream reading must stall once the internal buffer reaches `MaxBufferSize`. Memory allocation per connection must never exceed $O(\text{BufferCap})$.
   - **Invariant 4 (Buffer Recycling Cleanliness)**:
     Every buffer borrowed from `sync.Pool` during handshake inspection must be returned upon connection termination. Re-borrowed buffers must not leak data across distinct connections.

---

## Junior Developer Implementation Guide

### Step 1: Set up Mock Upstream and Proxy Loop
In `internal/proxy/splice_invariant_test.go`:
```go
package proxy_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/seanpor/ja4proxy/internal/config"
	"github.com/seanpor/ja4proxy/internal/proxy"
)
```

Create a helper `startEchoUpstream(t *testing.T) (net.Listener, <-chan []byte)` that listens on `127.0.0.1:0` and reads all incoming data until EOF into a buffer, returning the received byte channel.

### Step 2: Implement Invariant 1 & 2 Test (Chunk Slicing & Lossless Replay)
```go
func TestInvariant_HomomorphicChunkSlicingAndReplay(t *testing.T) {
	// 1. Start echo upstream server
	upstream, receivedCh := startEchoUpstream(t)
	defer upstream.Close()

	// 2. Start JA4proxy instance pointing to echo upstream
	proxyCfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Upstream:   upstream.Addr().String(),
		Timeout:    5 * time.Second,
	}
	p := proxy.New(proxyCfg)
	proxyListener, err := p.Start()
	if err != nil {
		t.Fatalf("Failed to start proxy: %v", err)
	}
	defer p.Stop()

	// 3. Prepare payload: ClientHello + random application data
	clientHello := getBaselineClientHello()
	appData := make([]byte, 16384)
	_, _ = rand.Read(appData)
	fullStream := append(clientHello, appData...)

	// 4. Test partition strategies: 1-byte trickles, 7-byte primes, 1024-byte chunks
	chunkSizes := []int{1, 7, 64, 512, 1460, 4096}

	for _, chunkSize := range chunkSizes {
		conn, err := net.Dial("tcp", proxyListener.Addr().String())
		if err != nil {
			t.Fatalf("Dial failed for chunk size %d: %v", chunkSize, err)
		}

		// Write in chunk increments
		go func(c net.Conn, size int) {
			defer c.Close()
			for i := 0; i < len(fullStream); i += size {
				end := i + size
				if end > len(fullStream) {
					end = len(fullStream)
				}
				_, _ = c.Write(fullStream[i:end])
				time.Sleep(1 * time.Millisecond) // Ensure individual network packetization
			}
		}(conn, chunkSize)

		// Assert received data matches original byte-for-byte
		received := <-receivedCh
		if !bytes.Equal(received, fullStream) {
			t.Fatalf("Chunk size %d corrupted stream: got %d bytes, want %d bytes", chunkSize, len(received), len(fullStream))
		}
	}
}
```

### Step 3: Implement Invariant 3 Test (Backpressure & Buffer Bounds)
Create a slow upstream reader that reads 1 byte per second.
Client attempts to write 10MB of data.
Verify that:
1. Client `Write()` blocks once the proxy's buffer fills.
2. Proxy process memory does not spike to 10MB.
3. Once upstream resumes normal reading, all data flows through accurately.

### Step 4: Implement Invariant 4 Test (Zero Buffer Leakage across Connections)
Create connection $A$ sending sensitive marker `SECRET_A`.
Close connection $A$.
Create connection $B$ sending short payload.
Verify that connection $B$'s upstream receive buffer contains zero trace of `SECRET_A` (buffers zeroed before pool return).

---

## Test Strategy
- Run with Go test runner:
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./internal/proxy -run SpliceInvariant`
- Run with race detector to catch any splice data races:
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -race ./internal/proxy -run SpliceInvariant`

---

## Acceptance Criteria
- [ ] `internal/proxy/splice_invariant_test.go` implemented and passing.
- [ ] 1-byte, prime-sized, and standard MTU packetization strategies verified lossless.
- [ ] Pre-read ClientHello verified byte-identical at upstream.
- [ ] Backpressure verified: slow upstream halts client reading without memory ballooning.
- [ ] Buffer recycling clean: no cross-connection data leakage.
- [ ] `make test-unit` and `make preflight` pass 100% green.

---

## Out of Scope
- TLS parsing internals (covered in 606a).
- Connection resource cleanup and FD leak bounds (covered in 606c).
