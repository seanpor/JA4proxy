# Phase 15b — Go Rewrite Supplement

## Status: OPEN

## Purpose

This document supplements `PHASE_15.md` and `PHASE_15_subplan.md`. Read both of those
documents first. This supplement adds:

1. Full TDD category checklist with file names and minimum counts
2. Go-Python parity test specification (binary, metric schema, log schema)
3. Grafana dashboard verification specification
4. ADR-015: Why Go not Rust (promoted from inline table to proper ADR)
5. Operator migration runbook (validation procedure and rollback plan)
6. Go dependency vulnerability scanning requirements
7. GC tuning guidance for production
8. End-user documentation for the Go proxy

---

## 1. TDD Category Checklist

Phase 15 must satisfy all seven test categories. Write tests in this order: they define
correctness before the implementation and provide a regression baseline at each phase of
the subplan.

### 1a. Unit Tests (`internal/*/**_test.go`)

Go unit tests live alongside the code they test, per Go convention.

**TLS / JA4 (`internal/tls/`)**

Minimum 25 tests across these files:

```
internal/tls/parser_test.go
  TestParseClientHello_ValidFixtures        — parametrized over tests/fixtures/clienthello/*.bin
  TestParseClientHello_TruncatedBeforeCipher
  TestParseClientHello_ZeroLengthRecord
  TestParseClientHello_WrongRecordType
  TestParseClientHello_OversizeExtensionLength
  TestParseClientHello_AllGREASECiphers
  TestParseClientHello_DuplicateExtensions
  TestParseClientHello_MaxSNILength

internal/tls/ja4_test.go
  TestJA4_FixturesParity                   — byte-for-byte vs Python for all fixtures
  TestJA4_EmptyCipherList
  TestJA4_AllGREASE
  TestJA4_NilSNI
  TestJA4_TLS12vsT13
  TestJA4_ALPNExtraction

internal/tls/ja4t_test.go
  TestJA4T_AlertCodes
  TestJA4T_NoAlerts
```

**Security modules (`internal/security/`)**

Each module must have a Go test file with at minimum:
- Happy-path test (correctly classifies known input)
- Fail-open test (returns nil signal when dependency fails)
- Redis unavailable test (same fail-open behaviour as Python)

Minimum 1 unit test per public function in each of the 14 security modules.

### 1b. Integration Tests (`tests/integration/`)

These cross-language tests run the Go proxy alongside the Python analytics node and
verify that both produce identical actions for identical inputs.

```
tests/integration/test_go_python_parity.py
  test_allow_bypass_identical                 — h2 ALPN: Go and Python both allow
  test_block_identical                        — known-bad JA4: both block
  test_score_within_tolerance                 — score ± 1 for 1000 random connections
  test_redis_keys_identical                   — same Redis keys written; same values
  test_stream_events_identical                — same ja4proxy:events entries emitted
  test_dial_propagation_go                    — dial change via Redis; Go proxy honours it
  test_pub_sub_invalidation_go               — JA4 blacklist add; Go proxy picks up within 1s
```

### 1c. Chaos Tests (`tests/chaos/test_go_proxy_chaos.py`)

Minimum 5 tests.

```python
def test_go_proxy_crash_haproxy_routes_to_python():
    """HAProxy detects Go proxy down; routes to Python instance within 2s."""

def test_go_proxy_adversarial_clienthello_no_panic():
    """Every adversarial corpus file: Go proxy handles without goroutine panic."""

def test_go_proxy_redis_fail_open():
    """Redis unavailable: Go proxy allows connections (same fail-open as Python)."""

def test_go_proxy_config_unknown_keys_ignored():
    """proxy.yml with extra unknown keys: Go proxy starts; unknown keys logged DEBUG."""

def test_go_proxy_sigterm_drains_connections():
    """SIGTERM during 50 active connections: all drain within timeout; no hung goroutines."""
```

### 1d. Adversarial Tests (`tests/adversarial/test_go_tls_adversarial.py`)

These run every file in `tests/adversarial/corpus/*.bin` against the Go parser:

```python
@pytest.mark.parametrize("corpus_file", list(CORPUS_DIR.glob("*.bin")))
def test_go_parser_does_not_panic(corpus_file):
    """Every corpus file: Go binary handles without panic or non-zero exit."""
    result = subprocess.run(
        ["./bin/ja4proxy-test-parser", corpus_file],
        capture_output=True, timeout=5
    )
    assert result.returncode in (0, 1)  # 0=parsed, 1=rejected; never panic(2)
    assert b"panic" not in result.stderr
    assert b"runtime error" not in result.stderr
```

### 1e. FP Corpus Tests (`tests/fp_corpus/test_go_fp_parity.py`)

Minimum 3 tests. These verify the Go proxy has identical false-positive rates to Python.

```python
def test_go_dga_fp_rate_matches_python():
    """Go proxy DGA false-positive rate ≤ 1% (same threshold as Python)."""

def test_go_beaconing_guard_zero_fp_h2():
    """Go proxy: h2 ALPN connections never recorded for beaconing."""

def test_go_asn_fp_rate_matches_python():
    """Go residential IP FP rate ≤ 2% (same threshold as Python)."""
```

### 1f. Performance Tests (`tests/performance/test_bench_go_proxy.py`)

- [ ] `test_go_throughput_5x_python` — Go processes ≥ 5× conn/s vs Python at equivalent Redis load
- [ ] `test_go_sustained_load_1000_conns_per_sec` — 1,000 conn/s sustained 60s; FP rate < 0.1%
- [ ] `test_go_allow_bypass_latency` — h2 ALPN bypass: p99 < 100µs (10× faster than Python 500µs target)
- [ ] `test_go_gc_pause_under_load` — GC pauses measured during 1,000 conn/s; p99 < 1ms

### 1g. E2E Tests (Docker required)

- [ ] `test_e2e_go_proxy_full_pipeline` — end-to-end: client → HAProxy → Go proxy → backend; connection
      allowed; correct headers
- [ ] `test_e2e_go_proxy_block_known_bad_ja4` — known-bad JA4 in blacklist → RST; no data forwarded

---

## 2. Go-Python Parity Test Specification

**This is the single most important test category for Phase 15.** The Go proxy is
correct if and only if it produces identical results to the Python proxy for all inputs.

### 2a. Binary JA4 Parity

Every fixture in `tests/fixtures/clienthello/*.bin` must produce byte-for-byte identical
JA4 fingerprints in Python and Go.

```python
# tests/integration/test_go_python_parity.py

FIXTURES_DIR = Path("tests/fixtures/clienthello")

@pytest.mark.parametrize("fixture", list(FIXTURES_DIR.glob("*.bin")))
def test_ja4_binary_parity(fixture, go_proxy_process):
    """Go JA4 output must be byte-for-byte identical to Python for every fixture."""
    raw = fixture.read_bytes()

    # Python reference
    python_result = TLSParser.parse_client_hello(raw)
    python_ja4 = JA4Generator.generate(python_result)

    # Go implementation via subprocess test binary
    go_result = subprocess.run(
        ["./bin/ja4-compute", "-"],
        input=raw, capture_output=True, timeout=2
    )
    go_ja4 = go_result.stdout.strip().decode()

    assert python_ja4 == go_ja4, (
        f"JA4 mismatch for {fixture.name}:\n"
        f"  Python: {python_ja4}\n"
        f"  Go:     {go_ja4}"
    )
```

All fixtures must pass. Zero tolerance. No "close enough".

### 2b. Prometheus Metric Schema Parity

After processing 100 identical connections through Python and Go proxies:

```python
def test_metric_schema_parity(python_proxy, go_proxy):
    """All metric names, label names, and label value cardinalities must match."""
    python_metrics = parse_prometheus_text(requests.get("http://localhost:8080/metrics").text)
    go_metrics = parse_prometheus_text(requests.get("http://localhost:8082/metrics").text)

    python_names = {m.name for m in python_metrics}
    go_names = {m.name for m in go_metrics}

    # Every Python metric must exist in Go
    missing_in_go = python_names - go_names
    assert not missing_in_go, f"Metrics in Python but not Go: {missing_in_go}"

    # Every Go metric must exist in Python (no new metrics added in Go)
    extra_in_go = go_names - python_names
    assert not extra_in_go, f"Metrics in Go but not Python: {extra_in_go}"

    # For each shared metric, verify label sets are identical
    for name in python_names & go_names:
        python_labels = {frozenset(s.labels.keys()) for s in python_metrics[name].samples}
        go_labels = {frozenset(s.labels.keys()) for s in go_metrics[name].samples}
        assert python_labels == go_labels, (
            f"Label set mismatch for {name}:\n"
            f"  Python: {python_labels}\n"
            f"  Go:     {go_labels}"
        )
```

### 2c. Structured Log Schema Parity

After processing 10 connections of each action type (allow, block, flag, tarpit):

```python
def test_log_schema_parity(python_proxy, go_proxy):
    """Go structured log field names and types must be identical to Python."""
    python_logs = [json.loads(l) for l in get_connection_logs(python_proxy)]
    go_logs = [json.loads(l) for l in get_connection_logs(go_proxy)]

    required_fields = {"type", "level", "subsystem", "event", "client_ip",
                       "ja4", "score", "action", "timestamp"}

    for log in python_logs + go_logs:
        missing = required_fields - set(log.keys())
        assert not missing, f"Log entry missing fields: {missing}\nEntry: {log}"

    # Type consistency: score must be integer in both
    for log in go_logs:
        assert isinstance(log["score"], int), f"Go log score is not int: {type(log['score'])}"
```

### 2d. Decision Parity

For 10,000 randomly-generated `ConnectionContext` objects (no external calls):

```python
def test_decision_parity_random_inputs(python_pipeline, go_pipeline):
    """Go and Python must produce identical action for identical inputs."""
    rng = random.Random(42)  # Deterministic seed
    mismatches = []

    for _ in range(10_000):
        ctx = _random_connection_context(rng)
        python_action = python_pipeline.decide(ctx)
        go_action = go_pipeline.decide(ctx)

        if python_action != go_action:
            mismatches.append((ctx, python_action, go_action))

    assert not mismatches, (
        f"{len(mismatches)}/10000 decisions differ.\n"
        f"First mismatch: {mismatches[0]}"
    )
```

Score is allowed to differ by ± 1 (floating-point accumulation). Action must be
identical (action boundaries are at integer thresholds).

---

## 3. Grafana Dashboard Verification

The Go proxy must produce identical metric values for identical workloads as the Python
proxy. The Grafana dashboard does not need to change — verify it works with Go metrics.

Add to acceptance criteria:

- [ ] Run Python proxy for 60s at 100 conn/s; record all metric values
- [ ] Run Go proxy for 60s at 100 conn/s with identical inputs; record all metric values
- [ ] For each metric: Go value is within 5% of Python value (allowing for timing jitter)
- [ ] No Grafana panels show "No Data" after switching to Go proxy
- [ ] All AlertManager alerts fire identically for Go and Python proxy under test conditions

**New Grafana panel: Python vs Go Throughput**

Add during validation phase only (remove before production):

```
Title: Python vs Go Throughput Comparison
Type: Time series
Queries:
  - rate(ja4proxy_connections_total{proxy_type="python"}[1m])  label="Python"
  - rate(ja4proxy_connections_total{proxy_type="go"}[1m])      label="Go"
```

This panel is used during parallel validation. Remove it once Go is the only proxy.

---

## 4. ADR-015: Why Go Not Rust

**File:** `docs/decisions/ADR-015.md`

```markdown
# ADR-015: Go for the Proxy Rewrite, Not Rust

## Status: Accepted

## Context

The Python proxy is GIL-limited to ~350 conn/s on a single core. Phase 15 rewrites the
proxy core in a compiled language. The two candidates evaluated were Go and Rust.

The Python analytics node and management UI stay in Python — they are not
performance-critical and rely on scipy/FastAPI ecosystems.

## Options Evaluated

### Go 1.22+

| Factor | Assessment |
|--------|------------|
| Throughput vs Python | 10–50× (empirical: 5,000–15,000 conn/s per core, warm cache) |
| GC pauses at this scale | < 1ms p99; tunable with GOGC |
| Time to rewrite vs Python | ~2× — familiar syntax, similar concurrency model |
| Redis client | go-redis/v9: well-maintained, async pipelining, Lua scripts |
| MaxMind GeoIP | oschwald/geoip2-golang: official MaxMind library |
| TLS parsing | crypto/tls: standard library; raw ClientHello via net.Conn |
| Concurrency model | goroutines + channels — direct analogue of Python asyncio tasks |
| Error handling | Explicit return values — matches project's fail-open philosophy |
| Ecosystem | Mature, stable, large standard library |

### Rust

| Factor | Assessment |
|--------|------------|
| Throughput vs Python | 15–70× — marginally higher ceiling than Go |
| GC pauses | None — no GC; deterministic memory management |
| Time to rewrite vs Python | ~4–5× — ownership/borrow checker learning curve |
| Redis client | redis-rs: good, but async API is less ergonomic than go-redis |
| Concurrency model | Tokio async — powerful but more complex than goroutines |
| Error handling | Result<T, E> — excellent; better than Go for error propagation |

## Decision

**Go.**

The throughput ceiling difference (10–50× vs 15–70×) does not matter at our scale.
We need ~5,000 conn/s per instance; both languages deliver this comfortably.

The deciding factor is development velocity:
- Rewriting 2,096 lines of Python security logic in Rust would take ~4–5× as long
  as Go
- The proxy design is proven in Python — the Go rewrite translates a working design,
  it does not explore new design space. Speed of translation matters.
- Goroutines map directly to Python asyncio tasks; the concurrency model is familiar.
- go-redis/v9 supports all patterns used by the Python proxy (Lua EVALSHA, pub/sub,
  streams, pipelining) with identical semantics.

GC pauses in Go at our scale are < 1ms p99. This is negligible compared to Redis
RTT (~0.5ms) and TLS handshake parsing (~0.1ms).

## Consequences

1. **GC tuning may be needed**: Under heavy DDoS load with many short-lived
   allocations (connection contexts), GC pressure increases. Tune `GOGC` if p99 GC
   pauses exceed 1ms. Document tuning in the production runbook.

2. **Goroutine leak risk**: Goroutines that do not exit cleanly accumulate. Every
   goroutine started with `go func()` must have a shutdown path. Use context
   cancellation. Test with `goleak` in integration tests.

3. **Dependency surface**: Go modules introduce a supply chain dependency. Run
   `govulncheck` in CI on every merge.

4. **No SIMD TLS parsing**: Go's `crypto/tls` does not expose SIMD-optimised parsing.
   JA4 computation is sequential. This is acceptable — JA4 is fast enough in Go even
   without SIMD. Revisit only if profiling shows TLS parsing as bottleneck.

## Revisit If

- Throughput requirements exceed 50,000 conn/s per instance (Rust may be needed)
- GC pauses under DDoS load consistently exceed 5ms
- A critical dependency does not have a maintained Go library
```

---

## 5. Operator Migration Runbook

**File:** `docs/runbooks/go_proxy_migration.md`

```markdown
# Go Proxy Migration Runbook

## Overview

Phase 15 replaces `proxy.py` (Python) with `cmd/proxy/main.go` (Go). The migration
is zero-downtime: Python and Go proxies run in parallel on different ports; HAProxy
switches upstream after validation.

## Prerequisites

- Go ≥ 1.22 installed on build host
- Python proxy running and healthy
- All Phase 0–14 tests passing
- `reports/benchmark_baseline.txt` exists (Python benchmark recorded)

## Step-by-Step Migration

### Step 1: Build the Go Binary

```bash
cd /opt/ja4proxy
go build -o bin/ja4proxy ./cmd/proxy/
./bin/ja4proxy --version   # Must print version and exit cleanly
```

### Step 2: Start Go Proxy on a Different Port

```bash
# Start Go proxy on port 8082 (Python runs on 8080)
UI_API_KEY=<key> REDIS_URL=<url> ./bin/ja4proxy --port 8082 --config config/proxy.yml
```

Verify it starts without errors:
- No FATAL log lines
- Redis connection confirmed: `{"event":"redis_connected",...}` in log
- Prometheus metrics available: `curl localhost:8082/metrics | head -20`

### Step 3: Run Parity Tests

```bash
# Both proxies must be running
python3 -m pytest tests/integration/test_go_python_parity.py -v
```

All 7 parity tests must pass. If any fail, do not proceed.

Record Go benchmark:
```bash
python3 -m pytest tests/performance/test_bench_go_proxy.py -v
```

Go throughput must be ≥ 5× Python (check `reports/benchmark_baseline.txt`).

### Step 4: Run Chaos Tests Against Go Proxy

```bash
python3 -m pytest tests/chaos/test_go_proxy_chaos.py -v
```

All 5 chaos tests must pass.

### Step 5: Parallel Traffic Validation (24 hours)

Point 5% of HAProxy traffic to the Go proxy:

```haproxy
# haproxy.cfg — add to backend block
backend proxy_backend
    server python-proxy proxy:8080 weight 95
    server go-proxy proxy:8082 weight 5
```

Monitor for 24 hours:
- Compare action distributions in Grafana (Python vs Go throughput panel)
- Verify no increase in false positive rate (check `ja4proxy_fp_rate` if tracked)
- Verify no unhandled errors in Go proxy logs: `grep '"level":"ERROR"' go-proxy.log | wc -l`

If no anomalies after 24h, proceed.

### Step 6: Full Traffic Cutover

```haproxy
backend proxy_backend
    server go-proxy proxy:8082 weight 100
    # server python-proxy proxy:8080 weight 0   # Keep configured for rollback
```

Reload HAProxy: `haproxy -sf $(cat /run/haproxy.pid) -f /etc/haproxy/haproxy.cfg`

### Step 7: Monitor for 48 Hours

Watch in Grafana:
- `ja4proxy_connections_total` — should be identical rate to pre-migration
- `ja4proxy_tarpit_concurrent` — should behave identically
- Error rates — must not increase

### Step 8: Archive Python Proxy

After 30 days of stable Go proxy operation:

```bash
mv proxy.py legacy/proxy.py.archive
mv src/ legacy/src.archive/
git commit -m "Archive Python proxy after 30 days stable Go operation"
```

Keep `legacy/` in repo for reference. Do not delete.

## Rollback Procedure

If anomalies are detected after cutover:

### Immediate Rollback (< 2 minutes)

```haproxy
backend proxy_backend
    server python-proxy proxy:8080 weight 100
    # server go-proxy proxy:8082 weight 0
```

Reload HAProxy. Python proxy takes 100% of traffic immediately.

Python proxy has been running throughout (just receiving 0% weight) so it has
warm caches and active Redis connections. No warmup required.

### Post-Rollback

1. Capture Go proxy logs: `cp go-proxy.log incident-$(date +%Y%m%d).log`
2. File issue with observed anomaly and log evidence
3. Do not retry migration until root cause is identified and fixed

## Validation Commands

```bash
# Verify Go proxy is alive
curl -s http://localhost:8082/health | jq .

# Verify Redis connection
ja4proxy-admin --proxy-url http://localhost:8082 status

# Verify metrics
curl -s http://localhost:8082/metrics | grep ja4proxy_connections_total

# Check for goroutine leaks (requires debug port)
curl http://localhost:8083/debug/pprof/goroutine?debug=1 | head -50
```
```

---

## 6. Go Dependency Vulnerability Scanning

The Python proxy uses `safety check` in CI (Phase 16f). The Go proxy must have
equivalent coverage.

### Add to CI Pipeline (runs before tests, blocks on failures)

```bash
# Vulnerability scan
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...   # Fail on any known vulnerability in dependencies

# Goroutine leak detection in integration tests
go install go.uber.org/goleak@latest
# Tests use goleak.VerifyNone(t) in TestMain
```

### Add to `go.mod` Toolchain Requirements

```
// go.mod
require (
    go.uber.org/goleak v1.3.0    // goroutine leak detection in tests
)
```

### CI Cadence

- `govulncheck` runs on every PR merge
- Weekly scheduled `govulncheck` run (catches new CVEs for unchanged code)
- If a CVE is found: create issue; if severity HIGH+, block next deployment

### Acceptance Criteria

- [ ] `govulncheck ./...` passes with zero known vulnerabilities at time of release
- [ ] `goleak.VerifyNone(t)` added to `TestMain` in each `*_test.go` package
- [ ] No goroutine leaks detected in any integration or chaos test
- [ ] `govulncheck` added to CI; failure blocks merge

---

## 7. GC Tuning Guidance

**File:** Add to `docs/runbooks/go_proxy_operations.md`

```markdown
## GC Tuning

Go's garbage collector is tuned via the `GOGC` environment variable. Default is 100
(GC runs when heap grows 100% above baseline).

### Baseline

At 1,000 conn/s mixed traffic:
- Each connection allocates ~2KB (ConnectionContext + TLS parser result)
- Allocation rate: ~2MB/s
- GC frequency at GOGC=100: every ~50ms
- GC pause p99: < 1ms (typically 200–400µs)

### Tuning for High Load

Under DDoS (>10,000 conn/s):
- Allocation rate: ~20MB/s
- GC frequency at GOGC=100: every ~5ms
- GC pause p99 may increase to 1–3ms

If GC pauses exceed 1ms p99 under DDoS load:

```bash
# Increase GOGC to reduce GC frequency at cost of higher peak memory
GOGC=200 ./bin/ja4proxy ...
```

With GOGC=200, GC runs at 200% heap growth. At 20MB/s allocation rate, GC runs
every ~10ms. Peak memory increases by ~40MB (acceptable on 4GB container).

### Monitoring GC

```bash
# Print GC stats every 10s during load test
GODEBUG=gctrace=1 ./bin/ja4proxy 2>&1 | grep "^gc "
```

Output format:
```
gc 1 @0.042s 1%: 0.23+1.5+0.047 ms clock, ...
          ^ pause ms
```

### GOMEMLIMIT

For containers with strict memory limits, set GOMEMLIMIT to prevent OOM:

```bash
# Container memory limit is 512MB; set GOMEMLIMIT to 90% of limit
GOMEMLIMIT=460MiB ./bin/ja4proxy
```

GOMEMLIMIT triggers more aggressive GC before the OOM killer fires.
```

---

## 8. Acceptance Criteria (Supplement)

These extend the acceptance criteria in `PHASE_15.md`. Both sets must pass.

### TDD Process

- [ ] All 7 test categories present (unit, integration, chaos, adversarial, FP corpus, performance, E2E)
- [ ] Go unit tests written before Go implementation (test commit precedes implementation commit per git history)
- [ ] Zero goroutine leaks in any test (verified by `goleak.VerifyNone`)

### Parity Tests

- [ ] JA4 binary parity: 100% of fixture files produce identical output (zero tolerance)
- [ ] Prometheus metric schema parity: all metric names and label sets identical
- [ ] Structured log schema parity: all required fields present with correct types
- [ ] Decision parity: ≤ 0 mismatches in 10,000 random inputs (identical actions)

### Migration

- [ ] Parallel validation: Go proxy receives 5% of live traffic for 24h with no anomalies
- [ ] Rollback tested in staging: switching HAProxy back to Python takes < 2 minutes
- [ ] `docs/runbooks/go_proxy_migration.md` exists with complete step-by-step procedure

### Security

- [ ] `govulncheck ./...` passes at time of release
- [ ] `govulncheck` added to CI with merge-blocking failure
- [ ] GC pause p99 < 1ms at 1,000 conn/s sustained load (verified in performance tests)

### Documentation

- [ ] `docs/decisions/ADR-015.md` exists and covers Go vs Rust trade-offs
- [ ] `docs/runbooks/go_proxy_migration.md` exists with migration, validation, and rollback
- [ ] `docs/runbooks/go_proxy_operations.md` exists with GC tuning guidance
- [ ] `CHANGELOG.md` entry notes the language change and throughput improvement achieved
