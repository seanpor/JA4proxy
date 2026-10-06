# Resource Conservation & Concurrency Invariants

## Goal
Implement property-based invariant test suites for resource management and concurrency lifecycle across JA4proxy (`cmd/ja4pd`). Establish formal guarantees using `goleak` and Linux FD tracking that the proxy does not leak goroutines, file descriptors, memory buffers, or timers under connection churn, slowloris attack profiles, or abrupt client/upstream TCP resets.

---

## Read These First
- `cmd/ja4pd/main.go` (`handleConn`, socket deadline configuration)
- `cmd/ja4pd/lifecycle_test.go` (`newTestProxy`, `startEchoServer`)
- `cmd/ja4pd/pentest_goroutine_leak_regression_test.go` (`TestRegression_JA4PROXY_2026_0009_ForwardDoesNotLeakGoroutines`)
- `cmd/ja4pd/pentest_tarpit_slot_exhaustion_regression_test.go` (slot exhaustion checks)
- `cmd/ja4pd/pentest_accept_loop_semaphore_regression_test.go` (concurrency semaphore bounds)

---

## Verified API Surface
- `goleak.VerifyNone(t, goleak.IgnoreCurrent())` — `go.uber.org/goleak`
- `cfg.Proxy.ReadTimeout` — `internal/config/loader.go:505`
- `newTestProxy(t *testing.T)` — `cmd/ja4pd/lifecycle_test.go:31`

---

## Invariants

| ID | Plain-English Statement | Formal Statement | SecOps Rationale |
|---|---|---|---|
| `INV-RESOURCE-001` | Goroutine Conservation Law | $\lim_{t \to t_{\text{drain}}} \|G(t) - G_0\| == 0$ | Prevents connection worker goroutines from leaking under sustained traffic spikes or malicious connection churn. |
| `INV-RESOURCE-002` | File Descriptor Conservation Law | $\lim_{t \to t_{\text{drain}}} \|F(t) - F_0\| == 0$ | Guarantees socket file descriptors are cleanly closed on Linux systems, preventing socket exhaustion outages. |
| `INV-RESOURCE-003` | Slowloris Read Timeout Bound | $t_{\text{trickle}} \ge \text{ReadTimeout} \implies \text{ClosedByProxy}(conn)$ | Ensures slowloris attack connections trickling partial handshakes are forcibly terminated when `ReadTimeout` elapses. |
| `INV-RESOURCE-004` | Abrupt TCP RST Resiliency | $\text{InjectRST}(conn) \implies \text{PanicCount} == 0 \land \text{GoleakPassed}$ | Prevents abrupt client or upstream resets (`SO_LINGER=0`) from causing stuck channels or unhandled panics. |

---

## Step-by-Step Implementation Guide

### Step 1: Create `cmd/ja4pd/resource_invariant_test.go`
```go
package main

import (
	"net"
	"testing"
	"time"

	"go.uber.org/goleak"
	"github.com/seanpor/ja4proxy/internal/testutil/tlsfixture"
)

func TestInvariant_Resource_GoroutineConservation(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	p, mr, cfg := newTestProxy(t)
	defer mr.Close()
	defer p.Stop()

	echoAddr, cleanupEcho := startEchoServer(t)
	defer cleanupEcho()
	cfg.Proxy.Upstream = echoAddr

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	go p.serveOnListener(listener)

	// Run 100 client connection cycles with clean close, abrupt abort, and timeouts
	hello := tlsfixture.Build(tlsfixture.Spec{})
	for i := 0; i < 100; i++ {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			continue
		}
		_, _ = conn.Write(hello)
		if i%2 == 0 {
			_ = conn.(*net.TCPConn).SetLinger(0) // Abrupt RST
		}
		_ = conn.Close()
	}

	time.Sleep(200 * time.Millisecond) // Allow background cleanup
}

func TestInvariant_Resource_SlowlorisReadTimeout(t *testing.T) {
	p, mr, cfg := newTestProxy(t)
	defer mr.Close()
	defer p.Stop()

	cfg.Proxy.ReadTimeout = 1 // 1 second read timeout

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	go p.serveOnListener(listener)

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	start := time.Now()
	_, _ = conn.Write([]byte{0x16}) // partial record header byte

	buf := make([]byte, 10)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Read(buf)

	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("Expected slowloris connection to be closed by proxy")
	}
	if elapsed < 900*time.Millisecond || elapsed > 2500*time.Millisecond {
		t.Fatalf("Slowloris read timeout out of bounds: elapsed %v, want ~1s", elapsed)
	}
}
```

### Step 2: Create `cmd/ja4pd/fd_linux_test.go` (`//go:build linux`)
```go
//go:build linux

package main

import (
	"os"
	"testing"
)

func countOpenFDs(t *testing.T) int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("Failed to read /proc/self/fd: %v", err)
	}
	return len(entries)
}

func TestInvariant_Resource_FDConservationLinux(t *testing.T) {
	initialFDs := countOpenFDs(t)

	// Run connection churn loop...

	finalFDs := countOpenFDs(t)
	if finalFDs > initialFDs+1 { // +1 tolerance for dir handle
		t.Fatalf("File descriptor leak: initial %d, final %d", initialFDs, finalFDs)
	}
}
```

---

## Make It Fail First

| Invariant ID | Temporary Code Mutation | Expected Test Failure |
|---|---|---|
| `INV-RESOURCE-001` | Remove `defer conn.Close()` in worker loop in `cmd/ja4pd/main.go` | `TestInvariant_Resource_GoroutineConservation` fails with leaked goroutine stack |
| `INV-RESOURCE-002` | Omit `Close()` on upstream TCP socket on error | `TestInvariant_Resource_FDConservationLinux` fails with elevated FD count |
| `INV-RESOURCE-003` | Remove `SetReadDeadline(ReadTimeout)` call in `handleConn` | `TestInvariant_Resource_SlowlorisReadTimeout` times out after 3 seconds |
| `INV-RESOURCE-004` | Remove panic recovery defer in connection handler | Abrupt RST test causes unhandled runtime panic |

---

## Test Commands

- **Run Resource Invariants:**
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./cmd/ja4pd -run '^TestInvariant_Resource_'`
- **Run Invariant Suite:**
  `make test-invariants`

---

## Coverage Target

- **Package `cmd/ja4pd` Baseline:** 80.1%
- **Target Coverage:** $\ge 85.0\%$

---

## Acceptance Criteria

- [ ] `cmd/ja4pd/resource_invariant_test.go` and `fd_linux_test.go` created and passing.
- [ ] Invariants registered in `docs/testing/invariants.yaml`.
- [ ] `make test-invariants` count increased by 4.
- [ ] Package `cmd/ja4pd` coverage verified $\ge 85.0\%$.
- [ ] Mutation check table verified.
- [ ] News fragment created in `docs/fragments/phase-606c-resource-invariants.md`.
- [ ] `make preflight` passes 100% green.

---

## Out of Scope
- Server package extraction (covered in Phase 606s).
- Rate limiter state store (covered in Phase 606d).
