# JA4proxy — Testing Strategy

> This document defines the full testing methodology for the project.
>
> | Document | Covers |
> |----------|--------|
> | This document | What to test: categories, CI gates, FP monitoring, phase completion gate |
> | `docs/TEST_ORGANIZATION.md` | How to structure tests: file layout, conftest, fixtures, parametrize patterns |
> | `docs/OBSERVABILITY_STANDARDS.md` | What to instrument: metric names, log schema, dashboards, alerts |
>
> The per-phase acceptance criteria in `docs/phases/` reference all three.

---

## Testing Principles

**1. Tests define correctness, not the code.**
The Python implementation's test suite is the specification. When Phase 15 rewrites
in Go, the Go implementation must pass equivalent tests — not the other way around.

**2. The false-positive asymmetry applies to tests too.**
When writing threshold tests, test both sides: that the action *does* trigger at the
threshold, and that it *does not* trigger below it. A test that only checks "bad
traffic gets blocked" is half a test. Always add "good traffic gets through."

**3. Every failure mode must have a test.**
If a module documents "fails open when Redis is unavailable", there must be a test
that verifies this by simulating Redis unavailability. Documentation without a test
is a promise, not a guarantee.

**4. External services are always mocked in tests.**
AbuseIPDB, Spamhaus, RDAP registries, DNS servers — none of these are called in
tests. Use mock servers (see §4 below). This makes tests fast, deterministic, and
safe to run in CI without API keys.

---

## §1. Test Categories

### 1a. Unit Tests (`tests/unit/`)

Scope: individual functions and classes in isolation. No Redis, no network.

Requirements:
- Every public function has at least one unit test
- Every branch in security logic has a test (true and false path)
- All threshold boundaries tested explicitly (at, above, below)
- All signal modules tested against: correct signal detected, correct signal not
  triggered for benign input, correct `RiskSignal` output structure
- Score calculations: exact expected values, not just "greater than zero"

Naming convention: `tests/unit/test_{module_name}.py`

### 1b. Integration Tests (`tests/integration/`)

Scope: multiple modules working together, with real Redis (test instance).

Requirements:
- Full pipeline tests: inject a known ClientHello → verify correct action taken
- Cache hierarchy tests: verify in-process → Redis → API fallback chain
- Pub/sub tests: verify dial change propagates to all consumers
- Hot reload tests: SIGHUP reloads config, new values apply to next connection

Naming convention: `tests/integration/test_{scenario}.py`

### 1c. Chaos / Resilience Tests (`tests/chaos/`)

Scope: system behaviour when dependencies fail. These are the tests most commonly
skipped and most commonly where real outages come from.

**Required chaos scenarios:**

| Scenario | Expected behaviour | Must verify |
|----------|-------------------|-------------|
| Redis unreachable | Fail open; browser traffic passes | No false positives during outage |
| Redis slow (>500ms RTT) | Fall back to local cache | Throughput degraded but not zero |
| Analytics node down | Proxy continues on stale data | No scoring errors logged |
| AbuseIPDB API unreachable | Fail open; score=0 for affected IPs | Error counter incremented |
| Spamhaus download fails | Keep last known list | Stale-list metric incremented |
| RDAP registry unreachable | Fail open; enrichment skipped | Queue depth does not grow unboundedly |
| Redis OOM / maxmemory hit | `allkeys-lru` evicts; hot keys survive | Whitelist decisions still cached |
| Proxy instance crash mid-connection | HAProxy routes to other instances | No hung connections on backend |
| Dial change during high traffic | No traffic gap; immediate threshold update | Zero connections dropped on dial change |

Implementation: use `pytest` with `unittest.mock` to simulate failures. For Redis,
use `fakeredis` for unit tests and a real Redis with `SHUTDOWN NOSAVE` (restart after)
for chaos tests.

### 1d. Adversarial / Fuzzing Tests (`tests/adversarial/`)

Scope: malformed, truncated, and maliciously crafted inputs to the TLS ClientHello
parser. This is the most security-critical test category.

**Required adversarial test cases for TLS parser:**

- Empty ClientHello (0 bytes)
- Truncated at each field boundary (length fields lie about content)
- Oversized extensions (length > actual data)
- Extension count > 65535
- Cipher suite list claiming 0 suites
- Cipher suite list claiming 10,000 suites (overflow check)
- SNI extension with empty hostname
- SNI extension with hostname > 253 characters
- SNI extension containing null bytes
- SNI extension with non-ASCII characters
- ALPN extension with empty protocol list
- ALPN extension with protocol length > actual data
- Duplicate extension types (RFC violation)
- Valid TLS record wrapper around garbage body
- TLS version 0x0000 (invalid)
- TLS version 0xFFFF (invalid)
- All-zero session ID (valid)
- Session ID length > 32 (invalid)

**Required adversarial test cases for JA4 computation:**

- ClientHello with no cipher suites (should not crash)
- ClientHello with only GREASE values (all should be stripped)
- ClientHello with duplicate cipher suites (dedup before hashing)
- Very long SNI (should be truncated/handled gracefully)

**Fuzzer integration:**

Use `atheris` (Python) or `go-fuzz` / `go test -fuzz` (Go Phase 15) to run
property-based fuzzing against the TLS parser. The invariant: parsing any byte
sequence must not panic, must not block indefinitely, must return in < 1ms.

Add to CI: `make fuzz-quick` runs 30 seconds of fuzzing on every PR. Save any
corpus entries that find crashes to `tests/adversarial/corpus/`.

### 1e. False-Positive Rate Tests (`tests/fp_corpus/`)

Scope: verify signal modules do not over-trigger on real-world benign data.

**Required corpus tests:**

| Module | Corpus | Required FP rate |
|--------|--------|-----------------|
| DGA scorer (Phase 4) | Tranco top 10k domains | < 1% |
| SNI missing detection | Known-good browser traffic capture | 0% |
| Beaconing detector | Real browser keep-alive patterns | 0% |
| JA4T mismatch (Phase 5) | Known-good browser JA4/JA4T pairs | 0% |
| ASN datacenter classifier | Residential ISP IP list | < 2% |

Corpus data lives in `tests/fp_corpus/data/`. It is checked into the repository
as static fixtures. It does not call external services.

The Tranco top 10k list is downloaded once and committed. Refresh annually or when
the DGA scorer algorithm changes.

### 1f. Performance / Throughput Tests (`tests/performance/`)

Scope: measure throughput and latency before and after each phase. Catch performance
regressions before they reach production.

**Required benchmarks (run with `make benchmark`):**

| Benchmark | What it measures | Threshold |
|-----------|-----------------|-----------|
| `bench_pipeline_lookup` | Redis pipeline RTT | < 2ms p99 |
| `bench_ja4_compute` | JA4 fingerprint from raw bytes | < 100µs p99 |
| `bench_cidr_lookup` | Spamhaus CIDR trie lookup | < 10µs p99 |
| `bench_full_pipeline` | End-to-end: accept → decision | < 5ms p99 |
| `bench_whitelist_fast_path` | h2/h1 ALPN bypass | < 200µs p99 |
| `bench_local_cache_hit` | In-process LRU hit | < 1µs p99 |
| `bench_throughput_single` | Connections/sec single instance | > 200 conn/s (Python) |
| `bench_throughput_go` | Connections/sec Go (Phase 15) | > 2000 conn/s |

Record benchmark results in `docs/performance/BENCHMARK_HISTORY.md` after each
phase. Format: date, phase, metric, value, git commit hash. This creates a visible
regression history.

**Load test (`make load-test`):**

Uses the existing `../scripts/generate-tls-traffic.sh` with standardised parameters:
- Duration: 300 seconds
- Workers: 50
- Legitimate traffic: 15%

Pass criteria:
- False positive rate: 0% (no browser connections blocked)
- False negative rate: < 5% (≥ 95% of malicious traffic blocked or tarpitted)
- p99 latency added by proxy: < 10ms

Run before and after each phase. Record results in benchmark history.

### 1g. End-to-End Pipeline Tests (`tests/e2e/`)

Scope: full stack from HAProxy through proxy to mock backend. Verifies the complete
system works together, not just individual components.

**Required E2E scenarios:**

- Chrome browser fingerprint (h2 ALPN) → always ALLOWED regardless of dial
- Firefox browser fingerprint (h2 ALPN) → always ALLOWED regardless of dial
- Known-bad JA4 fingerprint → BLOCKED regardless of dial
- Sliver C2 fingerprint → BLOCKED (JA4 blacklist bypass)
- Missing SNI at dial=0 → ALLOWED (monitor mode)
- Missing SNI at dial=100 → TARPITTED (scored + threshold applied)
- Beaconing pattern over 30 seconds → escalation from ALLOWED to TARPITTED to BLOCKED
- Dial change mid-test → new thresholds apply within 100ms
- Redis failure during test → browser traffic continues; block decisions fail open
- mTLS client cert → ALLOWED regardless of score (Phase 5+)

E2E tests use Docker Compose test environment (`docker-compose.test.yml`).
They take longer to run — separate CI step, not on every commit.

---

## §2. Test Infrastructure

### Redis for Tests

- **Unit tests:** use `fakeredis` (in-process mock, no Docker required)
- **Integration tests:** use real Redis Stack in Docker (`docker-compose.test.yml`)
- **Chaos tests:** use real Redis with controlled failure injection

Never run tests against the production or development Redis instance.

### Mock External Services

All external services have mock servers in `tests/mocks/`:

```
tests/mocks/
  abuseipdb_mock.py       # FastAPI app mimicking AbuseIPDB v2 API
  spamhaus_mock.py        # HTTP server serving DROP/EDROP format
  rdap_mock.py            # RDAP server per registry (ARIN, RIPE, APNIC, LACNIC, AFRINIC)
  dns_mock.py             # Async DNS server for FCrDNS tests
```

Mock servers are configurable:
- Return specific scores/data for specific IPs
- Simulate rate limiting (429 responses)
- Simulate timeouts (delayed responses)
- Simulate network failure (connection refused)

### TLS ClientHello Fixtures

Real captured ClientHello packets in `tests/fixtures/clienthello/`:

```
tests/fixtures/clienthello/
  chrome_121_windows.bin      # Chrome 121 on Windows 11
  firefox_121_linux.bin       # Firefox 121 on Linux
  safari_17_macos.bin         # Safari 17 on macOS
  curl_8_ubuntu.bin           # curl 8.x on Ubuntu
  python_requests_2_31.bin    # Python requests library
  sliver_c2.bin               # Sliver C2 framework
  cobalt_strike.bin           # Cobalt Strike
  scanner_masscan.bin         # masscan
  adversarial_truncated.bin   # Truncated mid-extension (adversarial)
  adversarial_garbage.bin     # Valid TLS wrapper, garbage body
```

These are captured from real traffic or generated from known implementations.
They are the ground truth for JA4 computation parity tests.

---

## §3. CI/CD Pipeline

### On Every Commit (fast, < 2 minutes)

```
make test-unit          # Unit tests only
make lint               # ruff + mypy (Python), golangci-lint (Go Phase 15)
make fuzz-quick         # 30 seconds of TLS parser fuzzing
```

### On Every Pull Request (medium, < 10 minutes)

```
make test-unit
make test-integration   # Requires Redis Stack Docker
make test-adversarial   # Full adversarial corpus
make test-fp-corpus     # False positive rate validation
make benchmark          # Performance regression check (fail if > 20% degradation)
```

### On Merge to Main (slow, < 30 minutes)

```
make test-all           # All of the above
make test-e2e           # Full E2E test suite
make load-test          # 5-minute load test
make test-chaos         # Chaos test suite
```

### Enforcing the Test Ratio

Add to CI:

```python
# scripts/check_test_ratio.py
# Fails if test-to-code ratio falls below 1.2
import subprocess, sys
code_lines = int(subprocess.check_output(
    "find src -name '*.py' | xargs wc -l | tail -1", shell=True
).split()[0])
test_lines = int(subprocess.check_output(
    "find tests -name '*.py' | xargs wc -l | tail -1", shell=True
).split()[0])
ratio = test_lines / code_lines
print(f"Test ratio: {ratio:.2f} ({test_lines} test lines / {code_lines} code lines)")
if ratio < 1.2:
    print("FAIL: ratio below 1.2")
    sys.exit(1)
```

---

## §4. Production False Positive Monitoring

This is distinct from test-time FP measurement. Once deployed at any dial > 0, you
need to know your live FP rate.

### The "Would Block" Metric as FP Proxy

At any dial setting, the `ja4proxy_monitor_would_block_total{dial="100"}` metric
tells you how much traffic would be blocked at full aggression. Plot this over time.
A sudden spike that correlates with no known attack = likely a miscalibrated signal.

### Whitelist Traffic Score Distribution

Connections from h2/h1 ALPN browser traffic (always allowed, never scored) are a
natural control group. However: record their JA4T, ASN, and return-visitor signals
and compare against what their score *would be* if they weren't bypassed. If your
"known-good browser" traffic is suddenly scoring > 20 on average, something changed
— either the traffic changed (new browser fingerprint) or a signal module is
miscalibrated.

Add Grafana panel: **"Known-good browser shadow score"** — the risk score
distribution for h2/h1 ALPN traffic, computed but not acted upon. Should be stable
and low. Alert if p95 rises above 15.

### Score Drift Alert

In `docs/phases/PHASE_12.md` (analytics node), add:

> The analytics node computes a rolling 1-hour baseline of the median risk score
> for all traffic. If the current 1-hour median deviates from the 7-day median by
> more than 2 standard deviations, write an alert to `analytics:alerts:score_drift`
> and emit `ja4proxy_analytics_score_drift_detected` Prometheus gauge = 1.
>
> This catches: newly deployed signal module with miscalibrated scores, sudden
> change in traffic composition (attack starting or ending), accidental config
> change that affects scoring.

---

## §5. Phase Completion Gate

A phase is not complete until all of the following pass:

```
[ ] make test-unit          — all unit tests pass
[ ] make test-integration   — all integration tests pass
[ ] make test-fp-corpus     — FP rates within spec
[ ] make benchmark          — no performance regression > 20%
[ ] make load-test          — FP rate 0%, FN rate < 5% (if phase affects pipeline)
[ ] docs/performance/BENCHMARK_HISTORY.md updated
[ ] docs/REDIS_SCHEMA.md updated (if phase adds Redis keys)
[ ] CHANGELOG.md updated (see DOCUMENTATION_STANDARDS.md)
[ ] All new module paths in README.md security pipeline table
```

This gate is checked by the agent before declaring a phase done and before
starting the next phase.
