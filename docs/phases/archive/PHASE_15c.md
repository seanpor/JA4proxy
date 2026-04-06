# Phase 15c — Go Proxy Improvements

**Status:** OPEN
**Prerequisite:** Phase 15 complete (`docs/phases/PHASE_15.md`). All tasks here are
additive improvements — none are blockers to running the proxy.

Read this file top to bottom. Each task is self-contained and can be picked up by
a junior engineer independently. Tasks are ordered from simplest to most complex
within each section.

---

## Section A — Correctness fixes (do these first)

---

### A-1 · Replace runtime file-read with `//go:embed` for Lua script

**File:** `internal/redis/lua.go`
**Effort:** ~20 minutes
**Why:** The current code uses `runtime.Caller(0)` to find `scripts/sliding_window.lua`
on the filesystem at runtime. In the production Docker image `scripts/` is not present
in the container — the code silently falls back to an inline copy. If the two ever
diverge you get a silent correctness bug. `//go:embed` bakes the file into the binary
at compile time so there is only one copy.

**What to do:**

1. Open `internal/redis/lua.go`.

2. Add `"embed"` to the import block (use a blank import: `_ "embed"`).

3. Replace the entire `var SlidingWindowScript string` declaration and the `init()`
   function that reads the file with these two lines:
   ```go
   //go:embed ../../scripts/sliding_window.lua
   var SlidingWindowScript string
   ```

4. Delete the `slidingWindowLua` constant — it is no longer needed.

5. The embed path is relative to the source file. `../../internal/redis/lua.go` is at
   `internal/redis/lua.go` so `../../scripts/sliding_window.lua` points to the
   repo root `scripts/` directory. Verify the path is correct by running:
   ```bash
   GOROOT=/snap/go/current go build ./internal/redis/
   ```
   If the path is wrong, the compiler will say `pattern ... no matching files`.

6. Run the tests:
   ```bash
   GOROOT=/snap/go/current go test ./internal/redis/ -v
   ```
   All existing tests must pass.

**How to verify it worked:**
```bash
GOROOT=/snap/go/current go build -o /tmp/ja4proxy ./cmd/proxy
strings /tmp/ja4proxy | grep "ZADD\|sliding_window\|ZRANGEBYSCORE" | head -3
```
You should see Lua source lines embedded in the binary.

---

### A-2 · Tick the acceptance criteria checkboxes in PHASE_15.md

**File:** `docs/phases/PHASE_15.md`
**Effort:** ~20 minutes
**Why:** All 15 acceptance criteria boxes are unchecked even though the code for most
of them exists and works. Leaving them blank makes the phase look incomplete to anyone
reading the doc. Each box should be ticked with a brief evidence note.

**What to do:**

Open `docs/phases/PHASE_15.md` and find the `## Acceptance Criteria` section
(near the bottom). Change `- [ ]` to `- [x]` for each item that is done. Add a
short evidence line after each ticked item in parentheses. Use this mapping:

| Criterion | Evidence to add |
|-----------|----------------|
| `Dockerfile.go` multi-stage build | `(docker/Dockerfile.go-proxy exists; alpine runtime image)` |
| Go proxy reads same `config/proxy.yml` | `(internal/config/loader.go; 11 passing tests)` |
| JA4 fingerprint identical to Python | `(tests/fixtures/clienthello/known_ja4.json; verified Go==Python for all 4 fixtures)` |
| TLS ClientHello parser handles adversarial | `(internal/tls/parser.go never panics; fuzz-tested via go test -fuzz)` — leave unchecked until A-4 is done |
| All Lua scripts loaded via EVALSHA | `(internal/redis/lua.go + client.go LoadScript)` |
| Pub/Sub handles all message types | `(internal/redis/pubsub.go with reconnect loop)` |
| Prometheus metric names identical | `(internal/metrics/metrics.go; names match docs/OBSERVABILITY_STANDARDS.md after fix in f44214e)` |
| Python analytics run unchanged | leave unchecked — needs live Docker stack |
| All metric names verified | `(verified via grep vs OBSERVABILITY_STANDARDS.md; 4 names fixed in f44214e)` |
| JSON log schema | leave unchecked — see Section D task D-1 |
| JA4 fixture parity tests | `(tests/integration/test_go_python_parity.py; known_ja4.json)` |
| TLS parser adversarial no panic | `(tests/chaos/test_go_proxy_chaos.py::test_adversarial_corpus_no_panic)` |
| Go + Python parity | leave unchecked — needs live Docker stack |
| Throughput ≥ 5× | leave unchecked — needs live Docker stack |
| Load test 1,000 conn/s | leave unchecked — needs live Docker stack |

**How to verify it worked:**
Read the section. Every done item must have `[x]` and an evidence note.

---

## Section B — Test coverage

---

### B-1 · Add Go benchmarks for the TLS parser

**File:** `internal/tls/parser_test.go` (create it; the package already has `../../internal/tls/ja4_test.go`)
**Effort:** ~30 minutes
**Why:** There are no `BenchmarkXxx` functions in any Go test file. Without them you
cannot measure parser throughput or detect regressions. The TLS parser is the very
first thing that runs on every connection — it must be fast.

**What to do:**

Create `internal/tls/parser_test.go` with this content (fill in the `TODO` comments):

```go
package tls

import (
    "os"
    "path/filepath"
    "testing"
)

// BenchmarkParseTLS_Synthetic measures ClientHello parsing on a
// synthetic TLS 1.3 record (the same binary used in parity tests).
func BenchmarkParseTLS_Synthetic(b *testing.B) {
    // Load the synthetic fixture built by scripts/generate_synthetic_fixtures.py.
    // The file is at tests/fixtures/clienthello/synthetic_tls13_basic.bin
    // relative to the repo root.  Walk up from the test file's directory.
    data := loadFixture(b, "synthetic_tls13_basic.bin")
    b.ResetTimer()
    b.ReportAllocs()
    for i := 0; i < b.N; i++ {
        _, _ = ParseClientHello(data)
    }
}

// BenchmarkParseTLS_Empty measures parser behaviour on a zero-byte input.
// This is the fail-open path.
func BenchmarkParseTLS_Empty(b *testing.B) {
    b.ReportAllocs()
    for i := 0; i < b.N; i++ {
        _, _ = ParseClientHello(nil)
    }
}

// BenchmarkParseTLS_TLS12 measures parsing for a TLS 1.2 record.
func BenchmarkParseTLS_TLS12(b *testing.B) {
    data := loadFixture(b, "synthetic_tls12_basic.bin")
    b.ResetTimer()
    b.ReportAllocs()
    for i := 0; i < b.N; i++ {
        _, _ = ParseClientHello(data)
    }
}

// loadFixture reads a ClientHello fixture file from
// tests/fixtures/clienthello/<name> relative to the repo root.
// It skips the benchmark if the file does not exist.
func loadFixture(b *testing.B, name string) []byte {
    b.Helper()
    // Walk up from internal/tls/ to repo root.
    root := filepath.Join("..", "..", "tests", "fixtures", "clienthello", name)
    data, err := os.ReadFile(root)
    if err != nil {
        b.Skipf("fixture not found: %s", root)
    }
    return data
}
```

**Run the benchmarks:**
```bash
GOROOT=/snap/go/current go test ./internal/tls/ -bench=BenchmarkParseTLS -benchmem -benchtime=3s
```

Expected output (numbers will vary by machine):
```
BenchmarkParseTLS_Synthetic-8    500000    2400 ns/op    512 B/op    8 allocs/op
```

The target is under 5,000 ns/op for a well-formed ClientHello.

---

### B-2 · Add a Go benchmark for JA4 computation

**File:** `internal/tls/ja4_test.go` (already exists — add to it)
**Effort:** ~20 minutes
**Why:** JA4 computation includes sorting, SHA-256, and string building. These run on
every connection. A benchmark shows the baseline cost.

**What to do:**

Open `internal/tls/ja4_test.go` and add these functions at the end of the file:

```go
// BenchmarkComputeJA4 measures JA4 fingerprint generation from a parsed
// ClientHelloInfo.  The input is pre-parsed so only the hash/sort work
// is measured, not TLS parsing.
func BenchmarkComputeJA4(b *testing.B) {
    // Build a representative ClientHelloInfo matching a TLS 1.3 browser.
    info := &ClientHelloInfo{
        TLSVersion: 0x0304,
        CipherSuites: []uint16{
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f,
            0xc02c, 0xc030, 0xcca9, 0xcca8,
        },
        Extensions: []uint16{
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b,
            0x0023, 0x0010, 0x0005, 0x0013, 0x0012,
            0x002b, 0x0033, 0x002d,
        },
        SNI:  "example.com",
        ALPN: []string{"h2", "http/1.1"},
    }
    b.ResetTimer()
    b.ReportAllocs()
    for i := 0; i < b.N; i++ {
        _ = ComputeJA4(info)
    }
}

// BenchmarkComputeJA4_WithGREASE measures the GREASE-filter overhead.
func BenchmarkComputeJA4_WithGREASE(b *testing.B) {
    info := &ClientHelloInfo{
        TLSVersion: 0x0304,
        CipherSuites: []uint16{
            0x0a0a, // GREASE
            0x1301, 0x1302, 0x1303,
        },
        Extensions: []uint16{
            0x0a0a, // GREASE
            0x0000, 0x002b, 0x0033,
        },
        SNI: "example.com",
    }
    b.ResetTimer()
    b.ReportAllocs()
    for i := 0; i < b.N; i++ {
        _ = ComputeJA4(info)
    }
}
```

**Note:** Check the exact field names on `ClientHelloInfo` by reading
`internal/tls/hello_info.go` before writing the benchmark — use whatever field
names the struct actually has.

**Run:**
```bash
GOROOT=/snap/go/current go test ./internal/tls/ -bench=BenchmarkComputeJA4 -benchmem -benchtime=3s
```

---

### B-3 · Add a Go benchmark for the full pipeline

**File:** `internal/security/pipeline_test.go` (already exists — add to it)
**Effort:** ~45 minutes
**Why:** The pipeline benchmark is the most representative of real-world performance.
It measures the combined cost of all signal modules with mock Redis and is the number
that should be compared against the Python pipeline to verify the ≥5× claim.

**What to do:**

Open `internal/security/pipeline_test.go`. Find the `mockRedis` struct — you will
use it in the benchmark. Add this function at the end of the file:

```go
// BenchmarkPipelineProcess measures the full hot path: bypass checks + all
// signal modules + scoring + action decision.
// Uses a mock Redis so no network I/O is involved — this measures pure CPU cost.
func BenchmarkPipelineProcess(b *testing.B) {
    // Build a minimal but complete pipeline config.
    cfg := &PipelineConfig{
        BypassALPN:     true,
        JA4Whitelist:   []string{},
        JA4Blacklist:   []string{},
        StaticAllowlist: []string{},
        CountryBlacklist: []string{},
        // Leave all signal module configs at their zero values (disabled),
        // so only the bypass and scoring path runs.
    }
    log := logrus.New()
    log.SetLevel(logrus.ErrorLevel) // silence logs during benchmark
    mock := &mockRedis{}
    pipeline := NewPipeline(cfg, mock, log)

    conn := &ConnectionContext{
        ClientIP:   "1.2.3.4",
        JA4:        "t13d030500_55b375c5d22e_a80244f201c9",
        SNI:        "example.com",
        TLSVersion: 0x0304,
        ALPN:       []string{"http/1.1"},
    }
    ctx := context.Background()

    b.ResetTimer()
    b.ReportAllocs()
    for i := 0; i < b.N; i++ {
        _ = pipeline.Process(ctx, conn)
    }
}
```

**Note:** The exact field names in `PipelineConfig` and `ConnectionContext` must match
what is in `internal/security/pipeline.go` — read those structs before filling in
the fields. If `PipelineConfig` does not have a `BypassALPN` field, use whatever
boolean field enables the h2 ALPN bypass.

**Run:**
```bash
GOROOT=/snap/go/current go test ./internal/security/ -bench=BenchmarkPipeline -benchmem -benchtime=3s
```

Record the result as the baseline in a comment above the benchmark function.

---

### B-4 · Add a fuzz test for the TLS parser

**File:** `internal/tls/fuzz_test.go` (create it)
**Effort:** ~30 minutes
**Why:** The Go fuzzer generates novel malformed inputs that the adversarial corpus
never covered. Even running it for a few minutes regularly finds edge cases. The
parser is the highest-risk code in the proxy — it processes untrusted network bytes
before any authentication.

**What to do:**

Create `internal/tls/fuzz_test.go`:

```go
package tls

import "testing"

// FuzzParseTLS verifies that the TLS ClientHello parser never panics
// on any input.  Run with:
//
//	GOROOT=/snap/go/current go test ./internal/tls/ -fuzz=FuzzParseTLS -fuzztime=60s
//
// The fuzzer will generate random mutations of the seed corpus below and
// report any panic or crash.  Found crashes are saved in testdata/fuzz/.
func FuzzParseTLS(f *testing.F) {
    // Seed corpus: known-good and known-bad inputs.
    // The fuzzer mutates these to find new paths.
    seeds := [][]byte{
        // Empty input
        {},
        // Single byte
        {0x16},
        // Valid TLS 1.3 record header, no body
        {0x16, 0x03, 0x01, 0x00, 0x01},
        // Wrong content type (not handshake)
        {0x17, 0x03, 0x03, 0x00, 0x00},
        // Zero-length record
        {0x16, 0x03, 0x01, 0x00, 0x00},
        // Handshake type = ServerHello (not ClientHello)
        {0x16, 0x03, 0x01, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00},
        // Length overflow (record length > actual data)
        {0x16, 0x03, 0x01, 0xff, 0xff, 0x01, 0x00, 0x00, 0x01, 0x00},
        // All zeros
        make([]byte, 100),
        // All 0xff
        func() []byte { b := make([]byte, 100); for i := range b { b[i] = 0xff }; return b }(),
    }

    for _, seed := range seeds {
        f.Add(seed)
    }

    // Add the synthetic fixtures as seeds if they exist.
    // This gives the fuzzer a head start with well-formed inputs to mutate.
    // (If the files don't exist the fuzzer still runs with the seeds above.)
    for _, name := range []string{
        "../../tests/fixtures/clienthello/synthetic_tls13_basic.bin",
        "../../tests/fixtures/clienthello/synthetic_tls12_basic.bin",
        "../../tests/fixtures/clienthello/synthetic_grease.bin",
    } {
        import_os_readfile_if_exists_add_to_f(f, name) // see note below
    }

    f.Fuzz(func(t *testing.T, data []byte) {
        // The only requirement: ParseClientHello must not panic.
        // It may return any error or a valid result.
        defer func() {
            if r := recover(); r != nil {
                t.Errorf("ParseClientHello panicked on input %x: %v", data, r)
            }
        }()
        _, _ = ParseClientHello(data)
    })
}
```

**Note on the fixture loading:** Replace the `import_os_readfile_if_exists_add_to_f`
placeholder with real code. Use `os.ReadFile` and skip silently if the file does not
exist:

```go
import "os"

for _, name := range fixtureNames {
    data, err := os.ReadFile(name)
    if err == nil {
        f.Add(data)
    }
}
```

**Run the fuzzer for 60 seconds:**
```bash
GOROOT=/snap/go/current go test ./internal/tls/ -fuzz=FuzzParseTLS -fuzztime=60s
```

Run it for longer (10 minutes or more) when you have time — it gets more interesting
the longer it runs. Any crash it finds is saved to `internal/tls/testdata/fuzz/`.

**Make the fuzz seed corpus run as a regular unit test too:**
```bash
GOROOT=/snap/go/current go test ./internal/tls/ -run=FuzzParseTLS
```
This runs the seeds without fuzzing — it will be part of the normal `go test ./...` run.

---

### B-5 · Run the Docker test harness and tick the remaining acceptance criteria

**Files:** `docs/phases/PHASE_15.md`
**Effort:** ~1–2 hours (mostly waiting for Docker)
**Why:** Several acceptance criteria can only be verified with a live stack. The harness
already exists — it just needs to be run.

**What to do:**

```bash
# Build everything first
make go-build
make go-build-ja4check
make capture-fixtures

# Start the full test stack
docker compose -f docker-compose.test.yml up --build \
  --abort-on-container-exit --exit-code-from test-runner

# If you want to see which tests pass/fail:
docker compose -f docker-compose.test.yml logs test-runner
```

For each passing test, tick the corresponding box in `docs/phases/PHASE_15.md`
and add an evidence note matching the test name. For example:
```
- [x] Throughput: ≥ 5× connections/second versus Python proxy
      (test_go_throughput_vs_python: Go=8,240 conn/s, Python=1,105 conn/s, ratio=7.5×)
```

Also check the Docker image size:
```bash
docker build -f docker/Dockerfile.go-proxy -t ja4proxy-go:check .
docker image inspect ja4proxy-go:check --format '{{.Size}}' | numfmt --to=iec
```
If ≤ 10MB, tick that box too.

---

## Section C — Performance improvements

---

### C-1 · Add `GOMEMLIMIT` to `docker/Dockerfile.go-proxy`

**File:** `docker/Dockerfile.go-proxy`
**Effort:** ~10 minutes
**Why:** By default the Go runtime grows heap until the OS OOM-kills the process.
`GOMEMLIMIT` gives the GC a soft ceiling and triggers earlier, more frequent GC
cycles that keep resident memory bounded. This prevents the sudden memory spike +
OOM-kill pattern under sustained load.

**What to do:**

1. Open `docker/Dockerfile.go-proxy`.

2. Find the `CMD` or `ENTRYPOINT` line in the final stage (the runtime stage, not
   the build stage).

3. Add `GOMEMLIMIT` as an environment variable in the final stage, before `CMD`:
   ```dockerfile
   # Give the GC a memory target. 450MiB leaves headroom below a typical 512MiB
   # container limit. Adjust to match your actual container memory limit.
   ENV GOMEMLIMIT=450MiB
   ```

4. Also add `GOGC` to reduce GC frequency under normal load (optional but recommended):
   ```dockerfile
   ENV GOGC=100
   ```
   `GOGC=100` is the default. Set it to `200` to run GC half as often (uses more
   memory but fewer pauses). Only do this if your container has ≥ 512MiB.

5. Rebuild:
   ```bash
   docker build -f docker/Dockerfile.go-proxy -t ja4proxy-go:test .
   ```

**How to verify it worked:**
```bash
docker run --rm ja4proxy-go:test env | grep -E "GOMEMLIMIT|GOGC"
```

---

### C-2 · Add a `pprof` HTTP endpoint

**File:** `cmd/proxy/main.go`
**Effort:** ~30 minutes
**Why:** The ops runbook says "attach pprof" but there is no pprof endpoint in the
binary. Without it, profiling a running production instance requires restarting with
a debug build. Adding pprof behind a flag means it is always available when needed.

**What to do:**

1. Open `cmd/proxy/main.go`.

2. Add `net/http/pprof` to the imports (blank import — the package registers its
   handlers in `init()`):
   ```go
   _ "net/http/pprof"
   ```

3. Find the `serve()` function that starts the metrics HTTP server (the one serving
   `/metrics` and `/health`). It already has an `http.ServeMux`. Add the pprof
   routes to the same mux:
   ```go
   // pprof endpoints — available on the same metrics port.
   // Access via: go tool pprof http://host:9090/debug/pprof/profile?seconds=30
   mux.HandleFunc("/debug/pprof/", http.DefaultServeMux.ServeHTTP)
   ```

   Alternatively, since `net/http/pprof` registers on `http.DefaultServeMux`, you
   can simply route `/debug/` to the default mux:
   ```go
   mux.Handle("/debug/", http.DefaultServeMux)
   ```

4. Update `docs/runbooks/go_proxy_operations.md` to show the pprof URL:
   ```
   go tool pprof http://localhost:9090/debug/pprof/profile?seconds=30
   go tool pprof http://localhost:9090/debug/pprof/heap
   ```

5. Build and verify:
   ```bash
   GOROOT=/snap/go/current go build -o /tmp/ja4proxy-pprof ./cmd/proxy
   # Start it, then:
   curl -s http://localhost:9090/debug/pprof/ | grep -o 'href="[^"]*"' | head -5
   ```

**Security note:** The metrics port (9090) should never be exposed publicly. It is
already documented as internal-only in the ops runbook. pprof on the same port
inherits that restriction.

---

### C-3 · Pre-size the signal slice to avoid repeated `append` reallocations

**File:** `internal/security/pipeline.go`
**Effort:** ~20 minutes
**Why:** The pipeline currently declares `var signals []RiskSignal` with no initial
capacity. Each `append` that exceeds capacity allocates a new backing array and copies.
With ~10 signal modules, this means several reallocs per connection. Pre-sizing with
`make([]RiskSignal, 0, 16)` eliminates all reallocs for typical traffic.

**What to do:**

1. Open `internal/security/pipeline.go`.

2. Find the line:
   ```go
   var signals []RiskSignal
   ```

3. Replace it with:
   ```go
   // Pre-size for the expected number of signals (one per module, plus some
   // buffer). This eliminates append reallocs for typical traffic.
   signals := make([]RiskSignal, 0, 16)
   ```

4. Run the full test suite to confirm nothing broke:
   ```bash
   GOROOT=/snap/go/current go test ./internal/security/ -v
   ```

5. Run the pipeline benchmark (from task B-3) before and after to see the allocation
   reduction:
   ```bash
   GOROOT=/snap/go/current go test ./internal/security/ -bench=BenchmarkPipeline -benchmem
   ```
   The `allocs/op` number should drop by 3–6 allocations.

---

### C-4 · Pool the TLS read buffer

**File:** `cmd/proxy/main.go`
**Effort:** ~45 minutes
**Why:** Each connection allocates a `[]byte` to read the TLS ClientHello from the
socket. At 10,000 conn/s that is 10,000 allocations/second for this buffer alone.
A `sync.Pool` hands the same buffers to new connections, removing those allocations
from the GC entirely.

**What to do:**

1. Open `cmd/proxy/main.go`.

2. Add a package-level pool for read buffers. Place it near the top of the file,
   after the `import` block:
   ```go
   // helloPool provides reusable buffers for reading TLS ClientHello records.
   // 16 KiB is large enough for any valid ClientHello.
   var helloPool = sync.Pool{
       New: func() interface{} {
           buf := make([]byte, 16*1024)
           return &buf
       },
   }
   ```

3. Find the `handleConn` function. Locate the line where it reads the ClientHello
   from the connection — it will look something like:
   ```go
   buf := make([]byte, 16384)
   n, err := conn.Read(buf)
   ```

4. Replace that allocation with a pool get/put:
   ```go
   bufPtr := helloPool.Get().(*[]byte)
   buf := *bufPtr
   defer helloPool.Put(bufPtr)

   n, err := clientConn.Read(buf)
   ```

5. Make sure the pool buffer is only read up to `n` bytes everywhere after:
   `buf[:n]` not `buf`.

6. Add `"sync"` to the import block if it is not already there.

7. Build and run tests:
   ```bash
   GOROOT=/snap/go/current go build ./cmd/proxy/
   GOROOT=/snap/go/current go test ./... -count=1
   ```

---

## Section D — Observability improvements

---

### D-1 · Align Go log field names to the Python schema

**Files:** `cmd/proxy/main.go`, `internal/security/pipeline.go`
**Effort:** ~1 hour
**Why:** Python logs use field names `client_ip`, `ja4`, `action`, `score`,
`bypass_reason`, `signal`. The Go proxy uses `ip`, `ja4`, `addr`, `signal`.
Log aggregation tools (Loki, Elasticsearch) need identical field names for shared
dashboards and alerts to work across both proxy implementations.

**What to do:**

1. Read `docs/OBSERVABILITY_STANDARDS.md` — find the "Log Schema" or "JSON log
   fields" section. Note the exact field names required.

2. Open `cmd/proxy/main.go` and `internal/security/pipeline.go`.

3. Search for all `WithField(` and `WithFields(logrus.Fields{` calls.

4. Rename fields to match the standard. Common changes expected:
   - `"ip"` → `"client_ip"`
   - `"addr"` → `"client_ip"` or `"remote_addr"` (check the standard)
   - `"bypass"` → `"bypass_reason"`

5. Run the tests:
   ```bash
   GOROOT=/snap/go/current go test ./... -count=1
   ```

6. Tick the JSON log schema checkbox in `docs/phases/PHASE_15.md`.

---

### D-2 · Add signal-level Prometheus metrics

**File:** `internal/metrics/metrics.go`, then update each signal module
**Effort:** ~2 hours
**Why:** The Go proxy currently emits no signal-level metrics. When debugging a
traffic anomaly you cannot tell from Prometheus whether the AbuseIPDB module is
firing, what the beaconing detector is seeing, or how many blocklist matches are
happening. The `docs/OBSERVABILITY_STANDARDS.md` defines these metrics; they just
need to be wired in.

**What to do:**

This task has two parts.

**Part 1: Define the metrics in `internal/metrics/metrics.go`**

Add these metric declarations (check `docs/OBSERVABILITY_STANDARDS.md` for the exact
names and labels — use those, not invented ones):

```go
// AbuseIPDBLookupTotal counts AbuseIPDB lookups by result.
AbuseIPDBLookupTotal = prometheus.NewCounterVec(
    prometheus.CounterOpts{Name: "ja4proxy_abuseipdb_lookup_total", Help: "AbuseIPDB lookups by result"},
    []string{"result"}, // "hit", "miss", "error", "disabled"
)

// DNSEnrichmentTotal counts DNS enrichment lookups by result.
DNSEnrichmentTotal = prometheus.NewCounterVec(
    prometheus.CounterOpts{Name: "ja4proxy_dns_enrichment_total", Help: "DNS enrichment lookups"},
    []string{"result"}, // "hit", "miss", "error"
)

// BlocklistMatchesTotal counts blocklist matches by feed name.
BlocklistMatchesTotal = prometheus.NewCounterVec(
    prometheus.CounterOpts{Name: "ja4proxy_blocklist_matches_total", Help: "Blocklist matches by feed"},
    []string{"feed"},
)

// BeaconingScore is a gauge tracking the most recent beaconing CV score observed.
BeaconingScore = prometheus.NewGauge(
    prometheus.GaugeOpts{Name: "ja4proxy_beaconing_score", Help: "Most recent beaconing CV score"},
)
```

Add all new metrics to the `Register()` call at the bottom.

**Part 2: Increment the metrics in the signal modules**

- `internal/security/abuseipdb.go`: call `metrics.AbuseIPDBLookupTotal.WithLabelValues("hit").Inc()` etc.
- `internal/security/dns_enrichment.go`: call `metrics.DNSEnrichmentTotal.WithLabelValues(...).Inc()`
- `internal/security/blocklists.go`: call `metrics.BlocklistMatchesTotal.WithLabelValues(feedName).Inc()`
- `internal/security/beaconing_detector.go`: call `metrics.BeaconingScore.Set(cvScore)`

**Important:** Do not import `internal/metrics` from `internal/security/` — this
creates an import cycle (security → metrics → prometheus, but metrics has no
dependency on security, so this should be fine). Verify with `go build ./...`.

Run the tests:
```bash
GOROOT=/snap/go/current go test ./... -count=1
```

---

## Section E — Capture real browser fixtures (requires Docker)

---

### E-1 · Capture Chrome and Firefox ClientHello fixtures

**Files created:** `tests/fixtures/clienthello/chrome_tls13.bin`,
`tests/fixtures/clienthello/firefox_tls13.bin`
**Effort:** ~30 minutes (mostly Docker pull time)
**Why:** The 4 synthetic fixtures verify correctness for controlled inputs. Real browser
captures verify the parser handles the full complexity of browser-generated ClientHellos
(many extensions, GREASE values, real cipher ordering). These are the gold-standard
fixtures for the JA4 parity test.

**What to do:**

```bash
# Start the recorder service
docker compose -f docker-compose.test.yml up -d recorder

# Wait a few seconds for it to start
sleep 3

# Run the browser fixture generator
docker compose -f docker-compose.test.yml run --rm browser \
  python3 scripts/generate_fixtures_browser.py --recorder-host recorder

# Stop the recorder
docker compose -f docker-compose.test.yml stop recorder
```

Or use the Makefile target:
```bash
make capture-fixtures-browser
```

**Verify the fixtures were created:**
```bash
ls -la tests/fixtures/clienthello/*.bin
```

**Compute the expected JA4 for each new fixture:**
```bash
for f in tests/fixtures/clienthello/chrome_tls13.bin tests/fixtures/clienthello/firefox_tls13.bin; do
  echo -n "$f: Go="
  bin/ja4check "$f"
  echo -n "     Py="
  python3 scripts/compute_ja4.py "$f"
done
```

Both lines for each fixture must match.

**Add the new fixtures to `../../tests/fixtures/clienthello/known_ja4.json`:**

Run `scripts/generate_synthetic_fixtures.py` — it will append the new fixtures if
you add them to its `KNOWN_FIXTURES` list at the top of that script. Or update
`tests/fixtures/clienthello/known_ja4.json` manually with the verified JA4 values.

**Update `tests/fixtures/clienthello/README.md`** with the new fixture names,
tool used, and verified JA4 fingerprint.

---

## Section F — Known limitations (document, don't fix yet)

These items are out of scope for Phase 15 but should be documented so future engineers
understand the gaps.

---

### F-1 · Document JA4T limitation

**File:** `internal/tls/ja4t.go`
**Effort:** ~10 minutes
**Why:** `ComputeJA4T` currently returns `""` always. Anyone reading the code needs
to understand why and what it would take to fix it.

**What to do:**

Open `internal/tls/ja4t.go` and expand the comment on `ComputeJA4T` to explain:
1. What JA4T is (alert-based fingerprint from RFC 8701 extension)
2. Why it returns `""` — capturing TLS alerts requires intercepting the Go `crypto/tls`
   package's state machine, which would mean not using the standard library TLS
   parser for the forward path
3. What the correct fix would be: use `tls.Config.VerifyConnection` callback to
   observe the negotiated session state and alert codes
4. Link to the JA4 spec for the alert format

Add a `// TODO(phase16):` comment so future phases can search for it.

---

### F-2 · Document QUIC / JA4Q limitation

**File:** `internal/tls/ja4.go`
**Effort:** ~10 minutes
**Why:** The JA4 spec defines `'q'` for QUIC fingerprints (`JA4Q`). The current code
has a comment saying it always uses `'t'`. This should be a documented limitation.

**What to do:**

Find the comment in `internal/tls/ja4.go` near the prefix character (`'t'`/`'q'`)
and expand it to explain:
1. QUIC connections arrive on UDP, not TCP — the current proxy only handles TCP
2. JA4Q would require a QUIC listener (different goroutine model, different library)
3. `'t'` is always correct for the current TCP-only proxy
4. Add a `// TODO(phase16):` if QUIC support is planned

---

## Completion checklist

Work through sections in order. Each task is independent — you can pick any task
within a section without doing the others first, except:

- Do **A-1** (embed fix) before anything that rebuilds the Docker image
- Do **B-1**, **B-2**, **B-3** before **B-5** (you want benchmarks as a baseline)
- Do **B-4** before claiming the adversarial criterion in **A-2**/**B-5**

After completing all tasks in a section, run:
```bash
GOROOT=/snap/go/current go test ./... -count=1
GOROOT=/snap/go/current go vet ./...
```

Both must be clean before moving to the next section.
