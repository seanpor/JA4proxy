# Resource Conservation & Concurrency Invariants

## Goal
Implement property-based invariant test suites for resource management and concurrency lifecycle across JA4proxy (`internal/proxy/` and `cmd/ja4pd/`). Establish formal mathematical guarantees that the proxy does not leak goroutines, file descriptors, memory buffers, or timers under high-concurrency client churn, slowloris attack profiles, or abrupt client/upstream network resets.

---

## Scope
1. **Target Packages**:
   - `internal/proxy/` (Connection lifecycle, goroutine coordination, timeout deadlines, socket closure).
2. **New Test Files**:
   - `internal/proxy/resource_invariant_test.go`
3. **Formal Invariants to Enforce**:
   - **Invariant 1 (Goroutine Conservation Law)**:
     Let $G_0$ be the number of running goroutines at idle. After establishing, transmitting through, and terminating $N$ concurrent client connections ($N \ge 500$), the system must return to steady state within a grace period:
     $$\lim_{t \to t_{\text{settle}}} |G(t) - G_0| == 0$$
   - **Invariant 2 (File Descriptor Conservation Law)**:
     Let $F_0$ be the number of open file descriptors (`/proc/self/fd` on Linux). After cycling $N$ connections across normal closes, client RSTs, and upstream drops:
     $$\lim_{t \to t_{\text{settle}}} |F(t) - F_0| == 0$$
   - **Invariant 3 (Slowloris & Incomplete Handshake Defense)**:
     A client that opens a TCP connection and trickles 1 byte every 500ms must be forcibly terminated when `HandshakeTimeout` expires. All associated goroutines and buffers must be released immediately.
   - **Invariant 4 (Abrupt Reset Resiliency)**:
     Injecting abrupt TCP RST packets (`SO_LINGER` set to 0) from either client or upstream at any point during handshake or splice must never cause unhandled panics, stuck channels, or orphaned goroutines.

---

## Junior Developer Implementation Guide

### Step 1: Set up Test Harness & Goroutine Leak Detection
In `internal/proxy/resource_invariant_test.go`:
```go
package proxy_test

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/seanpor/ja4proxy/internal/config"
	"github.com/seanpor/ja4proxy/internal/proxy"
)
```

Create helper functions to count active goroutines and open file descriptors:
```go
func countOpenFDs() (int, error) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

func waitForGoroutines(t *testing.T, expected int, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		runtime.GC()
		current := runtime.NumGoroutine()
		if current <= expected {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("Goroutine leak detected: want <= %d, got %d", expected, runtime.NumGoroutine())
}
```

### Step 2: Implement Invariant 1 Test (Goroutine Conservation)
```go
func TestInvariant_GoroutineConservation(t *testing.T) {
	// Baseline goroutine count
	runtime.GC()
	baselineGoroutines := runtime.NumGoroutine()

	// Start upstream and proxy
	upstream, _ := startEchoUpstream(t)
	defer upstream.Close()

	p := proxy.New(&config.Config{
		ListenAddr: "127.0.0.1:0",
		Upstream:   upstream.Addr().String(),
		Timeout:    2 * time.Second,
	})
	listener, err := p.Start()
	if err != nil {
		t.Fatalf("Start proxy failed: %v", err)
	}
	defer p.Stop()

	// Execute 500 concurrent connections
	const totalConnections = 500
	var wg sync.WaitGroup
	wg.Add(totalConnections)

	for i := 0; i < totalConnections; i++ {
		go func() {
			defer wg.Done()
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				return
			}
			_, _ = conn.Write(getBaselineClientHello())
			buf := make([]byte, 128)
			_, _ = conn.Read(buf)
			_ = conn.Close()
		}()
	}

	wg.Wait()

	// Verify goroutines return to baseline
	waitForGoroutines(t, baselineGoroutines+2, 3*time.Second) // +2 allowed for test runner overhead
}
```

### Step 3: Implement Invariant 2 Test (File Descriptor Conservation)
```go
func TestInvariant_FDConservation(t *testing.T) {
	initialFDs, err := countOpenFDs()
	if err != nil {
		t.Skip("FD inspection not available on this platform")
	}

	// Run 200 connection cycles with mixed close types (normal, client abort, timeout)
	// Assert countOpenFDs() returns to initialFDs within tolerance (+1 for dir read)
}
```

### Step 4: Implement Invariant 3 Test (Slowloris Bound)
Connect to proxy listener.
Send 1 byte every 300ms.
Assert connection is closed by proxy at `t == HandshakeTimeout` ($\pm 100\text{ms}$).
Assert goroutines return to baseline immediately after timeout.

### Step 5: Implement Invariant 4 Test (Abrupt TCP RST)
Open TCP connection.
Set `conn.(*net.TCPConn).SetLinger(0)` (forces RST on close).
Close immediately.
Verify proxy logs no unhandled panic and closes upstream socket cleanly.

---

## Test Strategy
- Run with race detector:
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -race -v ./internal/proxy -run ResourceInvariant`
- Run leak tests repeatedly to confirm zero flakes:
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -count=10 -v ./internal/proxy -run GoroutineConservation`

---

## Acceptance Criteria
- [ ] `internal/proxy/resource_invariant_test.go` implemented and passing.
- [ ] Goroutine conservation verified across 500 concurrent connections.
- [ ] File descriptor count verified neutral before and after client bursts.
- [ ] Slowloris connections terminated at `HandshakeTimeout` without dangling sockets.
- [ ] Abrupt client RSTs handled gracefully without goroutine leaks.
- [ ] `make test-unit` and `make preflight` pass 100% green.

---

## Out of Scope
- Distributed state store sync (covered in 606d).
- TCP packet reassembly for TAP (covered in 606e).
