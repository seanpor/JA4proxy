<!--
title: Testing_Strategy
audience: Developers
last_reviewed: 2026-04-25
phase: 105
-->

# JA4proxy — Testing Strategy

> This document is the **single canonical reference** for testing in JA4proxy.
> Phase 105 consolidated the previously separate testing documents
> (`TEST_ORGANIZATION.md`, `TEST_SUITE.md`, `TESTING_GO.md`, `TESTING.md`) into
> the appendices below. Those four files are now redirect stubs.
>
> | Section | Covers |
> |---------|--------|
> | §1–§6 | What to test: categories, CI gates, FP monitoring, phase completion gate, regression tests |
> | Appendix A | How to structure tests: file layout, conftest, fixtures, parametrize patterns |
> | Appendix B | Test categories by container layer (Layers 1–8) |
> | Appendix C | Go-specific testing: differences from Python, table-driven tests, fuzz |
>
> See also `docs/OBSERVABILITY_STANDARDS.md` for what to instrument (metric
> names, log schema, dashboards, alerts) and `docs/SECURITY_TESTING.md` for
> JA4-fingerprint blocking and rate-limit validation procedures (kept separate
> due to its unique scope).
>
> The per-phase acceptance criteria in `docs/phases/` reference this document
> and `OBSERVABILITY_STANDARDS.md`.

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

E2E tests use Docker Compose test environment (`deploy/docker/docker-compose.test.yml`).
They take longer to run — separate CI step, not on every commit.

---

## §2. Test Infrastructure

### Redis for Tests

- **Unit tests:** use `fakeredis` (in-process mock, no Docker required)
- **Integration tests:** use real Redis Stack in Docker (`deploy/docker/docker-compose.test.yml`)
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

---

## §6. Regression Tests Per Security Finding (Phase 121d)

Every canonical finding in `docs/security/findings.yaml` that has reached
status `FIXED`, `VERIFIED`, or `CLOSED` **must** have a dedicated regression
test. `scripts/findings_register.py validate` fails if this is violated, and
`make verify-findings` is wired into the phase-completion gate above via
`make verify-findings-green` (see §6.3).

### §6.1 File and test naming

Python regression tests live under `tests/pentest/` in files named after the
canonical ID:

```
tests/pentest/test_ja4proxy_2026_0001_proxy_v2_spoofing.py
tests/pentest/test_ja4proxy_2026_0014_xff_precedence.py
```

Go regression tests live under `internal/security/pentest/` using the same
pattern:

```
internal/security/pentest/ja4proxy_2026_0001_proxy_v2_spoofing_test.go
```

The `regression_test` field in `findings.yaml` stores a pytest nodeid
(`tests/pentest/test_foo.py::test_name`) or a Go test path
(`internal/security/pentest/foo_test.go::TestName`). One nodeid per finding.

### §6.2 Required docstring citation

Every regression test function must begin with a docstring block that cites:

- The canonical finding ID (`JA4PROXY-YYYY-NNNN`).
- The original source ID(s) — e.g. `PHASE_108 L1-001`, `RED_TEAM_AUDIT R-017`.
- The CVSS v3.1 vector if one is recorded on the finding.
- A one-line summary of the vulnerable behaviour being guarded against.

Example:

```python
def test_untrusted_source_rejected(proxy):
    """JA4PROXY-2026-0001 — PROXY v2 spoofing from untrusted source.

    Sources: PHASE_108 L1-001, PHASE_109 109a
    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (9.1)

    Vulnerable behaviour: ignoring PROXY v2 headers from IPs outside
    trusted_cidrs left the attacker's spoofed header in the buffer for the
    backend to mis-trust. Fix: reject (or strip) before any scoring.
    """
    ...
```

The docstring is consumed by the scripts/findings_register.py output for
human review; PRs that change security-sensitive code should reference the
docstring when justifying a test change.

### §6.3 The `verify-findings-green` gate

`make verify-findings-green` runs only the regression tests listed in
`findings.yaml` — not the full suite. It is fast by design (seconds, not
minutes) so that a triager can confirm a new report does not regress any
previously-fixed finding before running the full gate.

```bash
# Validate schema + referential integrity:
make verify-findings

# Run only the regression tests that back existing findings:
make verify-findings-green
```

Both must pass before a finding is permitted to transition from `FIXED` to
`VERIFIED`. See `docs/security/CLOSURE_VERIFICATION.md` for the full state
machine.

### §6.4 Red-green requirement

A regression test **must** have been observed to fail against the unfixed
code at least once. This is how we guard against "tests that pass because
they assert nothing". The closure protocol (Phase 121h) records the commit
at which the test was observed red; `closed_commit` then records the commit
at which it was made green. Both are preserved in the register.

If a finding is reported against code that never shipped (a pre-merge review
finding), the "red" commit can be the branch tip at time of discovery. If
the finding cannot be reproduced at all, it is classified `DUPLICATE` of the
earlier finding it subsumes, or — if genuinely spurious — closed with
`status: CLOSED` and a `notes` entry explaining, without a regression test.
The latter path requires security-lead sign-off and is expected to be rare.

### §6.5 Cross-cutting findings

A handful of findings map to multiple code paths (e.g. PROXY protocol
handling lives in both the Go proxy and the Python proxy prototype). In this
case, prefer a single regression test in the production lane (Go) and link
it from `regression_test`. Cross-implementation parity is separately covered
by the Phase 15 parity test suite (`tests/parity/`) — do not duplicate a
parity test as a pentest regression unless the finding is genuinely
implementation-specific.

---

## Appendix A: Test File Organisation

> Folded in from `docs/TEST_ORGANIZATION.md` during Phase 105 consolidation;
> original was written in Phase 21. This appendix defines the canonical test
> file layout, pytest infrastructure, fixture factories, and per-module test
> mapping — the **how to structure** companion to §1's **what to test**.

### A.1 Current Implementation Status

The test suite targets a **1.3× test-to-code ratio** (lines of test code ÷
lines of production code). Run `make test-ratio` to check the current ratio.

The current test count can be verified with:

```bash
python3 -m pytest tests/ --collect-only -q 2>/dev/null | tail -1
```

Phases completed through 21. The sections below are a mix of **implemented**
(what exists today) and **planned** (design for future phases). Each section
is labelled.

| Category | Status |
|----------|--------|
| `tests/unit/` | **Implemented** |
| `tests/unit/security/` | **Implemented** |
| `tests/integration/` | **Implemented** |
| `tests/chaos/` | **Implemented** |
| `tests/fuzz/` | **Implemented** |
| `tests/security/` | **Implemented** |
| `tests/compliance/` | **Implemented** |
| `tests/test_proxy.py` | **Implemented** |
| `tests/adversarial/` | **Implemented** |
| `tests/fp_corpus/` | **Implemented** |

### A.2 Repository Test Layout

#### Implemented

```
tests/
├── conftest.py                    # Root: shared fixtures, network isolation, Prometheus cleanup
│
├── unit/                          # Fast, isolated, no network. 907 tests total.
│   ├── security/                  # Security module unit tests (299 tests)
│   │   ├── test_action_enforcer.py
│   │   ├── test_action_types.py
│   │   ├── test_asn_classifier.py
│   │   ├── test_beaconing_detector.py
│   │   ├── test_coverage_extras.py
│   │   ├── test_dns_enrichment.py
│   │   ├── test_mtls.py
│   │   ├── test_rate_strategy.py
│   │   ├── test_rate_tracker.py
│   │   ├── test_rate_tracker_extra.py
│   │   ├── test_sni_analyzer.py
│   │   ├── test_tcp_analyzer.py
│   │   ├── test_threat_evaluator.py
│   │   └── test_threat_tier.py
│   ├── test_action_decider.py
│   ├── test_blocklists.py
│   ├── test_bloom.py
│   ├── test_config_loader.py
│   ├── test_config_loader_extra.py
│   ├── test_gdpr_storage.py
│   ├── test_ip_utils.py
│   ├── test_local_cache.py
│   ├── test_pipeline.py
│   ├── test_pipeline_extra.py
│   ├── test_proxy_remaining.py    # proxy.py: ProxyServer, DialManager, main()
│   ├── test_proxy_server.py
│   ├── test_proxy_utils.py
│   ├── test_pubsub.py
│   ├── test_pubsub_extra.py
│   ├── test_risk_scorer.py
│   ├── test_security_manager.py
│   └── test_tls_enforcer.py
│
├── integration/                   # Mocked Redis (MagicMock), no external network. 126 tests.
│   ├── test_asn_pipeline.py       # ASN classification in pipeline
│   ├── test_beaconing_pipeline.py # Beaconing signal accumulates across connections
│   ├── test_bypass_rules.py       # Each bypass condition, enabled and disabled
│   ├── test_cache_hierarchy.py    # In-process cache behaviour
│   ├── test_dial_propagation.py   # Dial change via pub/sub across instances
│   ├── test_docker_stack.py       # Real HTTP to running containers (excluded from CI)
│   ├── test_end_to_end.py         # End-to-end pipeline scenarios
│   ├── test_hot_reload.py         # SIGHUP / pub/sub config reload
│   ├── test_pipeline.py           # Full pipeline: ConnectionContext → action
│   ├── test_rate_tracker_integration.py
│   ├── test_sni_pipeline.py
│   └── test_tcp_pipeline.py
│
├── chaos/                         # Dependency failures and resilience. 71 tests.
│   ├── test_asn_chaos.py          # ASN classifier chaos (bad DB, Redis down, invalid IP)
│   ├── test_dial_change_chaos.py  # Dial changes under concurrent traffic
│   ├── test_dns_chaos.py          # DNS enrichment chaos (lookup failure, timeout)
│   ├── test_feed_staleness.py     # Spamhaus, Tor list download failures
│   ├── test_redis_failure.py      # Redis unreachable, slow, evicted keys; Phase 0–9
│   ├── test_sni_chaos.py          # SNI analyzer chaos
│   └── test_tcp_chaos.py          # TCP analyzer chaos
│
├── fuzz/
│   └── test_properties.py         # Hypothesis property-based tests (13 tests)
│
├── security/
│   └── test_owasp_top10.py        # OWASP Top 10 security posture (23 tests)
│
├── compliance/
│   ├── gdpr_validator.py          # GDPR validation helpers
│   └── test_gdpr_retention.py     # GDPR data retention policies (24 tests)
│
├── performance/
│   ├── bench_pipeline.py          # Pipeline latency benchmarks (run manually)
│   └── bench_cidr_lookup.py       # CIDR trie lookup benchmarks (run manually)
│
└── test_proxy.py                  # Legacy root-level proxy tests (21 tests)
```

> **Note:** `tests/integration/test_docker_stack.py` is excluded from
> `make test` because it makes real HTTP calls to running containers. Run it
> manually with a live stack:
> `docker compose -f deploy/docker/docker-compose.poc.yml up -d && pytest tests/integration/test_docker_stack.py`.

> **Note:** `tests/performance/bench_*.py` files are not named `test_*.py` so
> pytest does not collect them automatically. Run manually:
> `python3 tests/performance/bench_pipeline.py`.

#### Planned (not yet implemented)

```
tests/
├── adversarial/                   # Malformed inputs. Target: Phase 15+.
│   ├── test_tls_parser_adversarial.py  # Malformed ClientHello corpus
│   ├── test_ja4_adversarial.py         # JA4 computation on edge-case inputs
│   └── corpus/                         # Byte sequences that triggered issues
│
├── fp_corpus/                     # False positive rates. Target: Phase 15+.
│   ├── test_dga_fp_rate.py        # DGA FP rate < 1% against Tranco top 10k
│   ├── test_beaconing_fp_rate.py  # Beaconing FP rate against real browser timing
│   ├── test_asn_fp_rate.py        # ASN FP rate against known residential IPs
│   └── data/                      # Static fixture data (committed, no network)
│
└── mocks/                         # Shared mock HTTP servers for integration tests.
    ├── abuseipdb_mock.py           # Needed for Phase 10 integration tests
    ├── rdap_mock.py                # Needed for Phase 11 integration tests
    └── spamhaus_mock.py
```

### A.3 Root `tests/conftest.py` — As Implemented

The root `tests/conftest.py` provides three categories of infrastructure:

#### A.3a Async helper

All non-async test functions that need to drive async code use `asyncio.run()`:

```python
def _run(coro):
    """Run a coroutine from a sync test. asyncio.run() cancels pending tasks
    on exit, preventing orphaned background tasks from hanging the container."""
    return asyncio.run(coro)
```

**Why `asyncio.run()` and not `asyncio.new_event_loop().run_until_complete()`:**
The old pattern left background tasks (e.g. `_tor_refresh_loop` sleeping
3600s) orphaned in unclosed event loops. In Python 3.11, GC cleanup of these
loops hangs ~264s per loop, causing the Docker 300s timeout to fire even
after pytest finishes. `asyncio.run()` cancels all pending tasks before
closing, keeping container shutdown under 1s.

#### A.3b Session-scoped network isolation

```python
@pytest.fixture(autouse=True, scope="session")
def _no_real_network():
    """Prevent real HTTP downloads during the test session.

    ASNClassifier._refresh_tor_list downloads from torproject.org (~4s) on every
    test that creates a Pipeline with a MagicMock Redis (because set() returns a
    truthy MagicMock, so the classifier always thinks it is the download leader).
    Patching to an async no-op at session scope eliminates all real network traffic
    and keeps the full test suite under 60s.

    Tests that specifically need real Tor exit IPs pre-populate _tor_exit_ips
    directly. Tests that need the real download logic capture the method reference
    at module import time (before the session fixture patches it) and restore it
    via patch.object on the instance.
    """
    async def _noop(*args, **kwargs):
        pass

    with patch(
        "src.security.asn_classifier.ASNClassifier._refresh_tor_list",
        new=_noop,
    ):
        yield
```

**Pattern for chaos tests that need the real download logic:**

```python
# Capture real method at module import time (before session fixture patches it)
_REAL_REFRESH_TOR_LIST = ASNClassifier._refresh_tor_list

def test_redis_leader_election_failure_uses_cached():
    classifier = ASNClassifier(config, mock_redis)
    with patch.object(classifier, "_refresh_tor_list",
                      _REAL_REFRESH_TOR_LIST.__get__(classifier)):
        asyncio.run(classifier._refresh_tor_list())
```

#### A.3c Redis fixtures

```python
@pytest.fixture
def mock_redis():
    """MagicMock Redis for unit tests with basic method stubs."""
    ...

@pytest.fixture
def redis_client():
    """Real Redis if available on localhost:6379, else a stateful mock.
    Integration tests use this; mocked version tracks sadd/smembers/delete."""
    ...
```

### A.4 Unit Test `tests/unit/conftest.py`

```python
# tests/unit/conftest.py
import pytest
from unittest.mock import patch
from src.cache.local_cache import LocalCache
from src.config.loader import ConfigLoader


@pytest.fixture
def local_cache():
    """Fresh LocalCache instance. No Redis, no TTL expiry during test."""
    return LocalCache(max_size=100, ttls={
        "whitelist_decisions": 1800,
        "block_decisions": 30,
        "abuseipdb_scores": 14400,
        "asn_class": 3600,
    })


@pytest.fixture
def loaded_config(base_config):
    """ConfigLoader pre-loaded with base_config. No file I/O."""
    loader = ConfigLoader.__new__(ConfigLoader)
    loader._config = base_config
    return loader


@pytest.fixture
def null_metrics():
    """Metrics sink that discards all calls. Prevents test output pollution."""
    with patch("src.security.metrics") as m:
        m.increment = lambda *a, **kw: None
        m.set_gauge = lambda *a, **kw: None
        m.observe = lambda *a, **kw: None
        yield m
```

### A.5 Per-Module Test File Structure

Every test file follows this internal structure. Sections are separated by
`# ── Section Name ──` comments and occur in this fixed order.

```python
# tests/unit/test_{module_name}.py
"""
Unit tests for src/security/{module_name}.py

Tests are grouped into sections:
  1. Construction / initialisation
  2. Happy path — correct signal detection
  3. Negative path — signal NOT triggered for benign input
  4. Boundary conditions — at, above, and below every threshold
  5. Edge cases — empty input, None, IPv6, max values
  6. Output structure — RiskSignal fields correct
  7. Config toggles — enabled/disabled behaviour
  8. Error handling — exceptions, malformed input
"""

import pytest
from unittest.mock import AsyncMock, patch
# ... imports


# ── Construction ───────────────────────────────────────────────────────────

class TestModuleNameInit:
    def test_loads_from_config(self, loaded_config): ...
    def test_defaults_applied_when_key_absent(self, loaded_config): ...
    def test_invalid_config_raises_on_load(self): ...


# ── Happy Path ─────────────────────────────────────────────────────────────

class TestModuleNameDetection:
    def test_{signal_name}_detected(self, ...): ...
    def test_{signal_name}_returns_correct_risk_signal(self, ...): ...
    def test_{signal_name}_score_matches_config(self, ...): ...


# ── Negative Path ──────────────────────────────────────────────────────────

class TestModuleNameNegative:
    def test_benign_input_produces_no_signal(self, ...): ...
    def test_browser_traffic_not_flagged(self, browser_connection, ...): ...


# ── Boundary Conditions ────────────────────────────────────────────────────

class TestModuleNameBoundaries:
    @pytest.mark.parametrize("value,expected_signal", [
        (THRESHOLD - 1, False),
        (THRESHOLD,     True),
        (THRESHOLD + 1, True),
    ])
    def test_threshold_boundary(self, value, expected_signal, ...): ...


# ── Edge Cases ─────────────────────────────────────────────────────────────

class TestModuleNameEdgeCases:
    def test_ipv4_address(self, ...): ...
    def test_ipv6_address(self, ...): ...
    def test_none_input(self, ...): ...
    def test_empty_string(self, ...): ...
    def test_maximum_valid_value(self, ...): ...


# ── Output Structure ───────────────────────────────────────────────────────

class TestModuleNameOutput:
    def test_risk_signal_has_correct_name(self, ...): ...
    def test_risk_signal_score_clamped_0_to_100(self, ...): ...
    def test_risk_signal_reason_is_non_empty_string(self, ...): ...


# ── Config Toggles ─────────────────────────────────────────────────────────

class TestModuleNameConfig:
    def test_module_disabled_produces_no_signals(self, ...): ...
    def test_signal_disabled_independently(self, ...): ...
    def test_score_value_read_from_config(self, ...): ...


# ── Error Handling ─────────────────────────────────────────────────────────

class TestModuleNameErrors:
    def test_malformed_input_does_not_raise(self, ...): ...
    def test_redis_unavailable_returns_none_not_raises(self, ...): ...
    def test_external_service_timeout_fails_open(self, ...): ...
```

### A.6 Chaos Test `tests/chaos/conftest.py`

```python
# tests/chaos/conftest.py
import pytest
import asyncio
import subprocess
import time


@pytest.fixture
def real_redis_container():
    """
    Starts a real Redis Stack container for chaos tests.
    Yields the container ID so tests can kill/restart it.
    """
    result = subprocess.run(
        ["docker", "run", "-d", "--rm", "-p", "16379:6379",
         "redis/redis-stack:latest"],
        capture_output=True, text=True
    )
    container_id = result.stdout.strip()
    time.sleep(1)  # Let Redis start
    yield container_id
    subprocess.run(["docker", "kill", container_id])


@pytest.fixture
def kill_redis(real_redis_container):
    """Context manager that kills Redis and restarts it after the test."""
    class RedisKiller:
        def __enter__(self):
            subprocess.run(["docker", "kill", real_redis_container])
            time.sleep(0.1)
        def __exit__(self, *args):
            subprocess.run(
                ["docker", "start", real_redis_container],
                capture_output=True
            )
            time.sleep(0.5)  # Let Redis restart
    return RedisKiller()


@pytest.fixture
def slow_redis(real_redis_container):
    """Uses tc netem to add 600ms latency to Redis traffic."""
    class SlowRedis:
        def __enter__(self):
            subprocess.run(
                ["docker", "exec", real_redis_container,
                 "tc", "qdisc", "add", "dev", "eth0", "root",
                 "netem", "delay", "600ms"]
            )
        def __exit__(self, *args):
            subprocess.run(
                ["docker", "exec", real_redis_container,
                 "tc", "qdisc", "del", "dev", "eth0", "root"]
            )
    return SlowRedis()
```

### A.7 Integration Test `tests/integration/conftest.py`

```python
# tests/integration/conftest.py
import pytest
import redis.asyncio as aioredis
import subprocess
import time


INTEGRATION_REDIS_PORT = 16380


@pytest.fixture(scope="session")
def redis_container():
    """
    Session-scoped Redis Stack container for all integration tests.
    One container shared across the session — faster than per-test.
    """
    result = subprocess.run(
        ["docker", "run", "-d", "--rm",
         "-p", f"{INTEGRATION_REDIS_PORT}:6379",
         "redis/redis-stack:latest"],
        capture_output=True, text=True
    )
    container_id = result.stdout.strip()
    time.sleep(1)
    yield container_id
    subprocess.run(["docker", "kill", container_id])


@pytest.fixture
async def redis_client(redis_container):
    """Per-test Redis client. FLUSHALL after each test."""
    r = aioredis.Redis(host="localhost", port=INTEGRATION_REDIS_PORT)
    yield r
    await r.flushall()
    await r.aclose()


@pytest.fixture
async def full_pipeline(redis_client, base_config):
    """
    Full proxy pipeline wired together with real Redis.
    Returns a callable: pipeline(connection) → action_string.
    """
    from src.security.pipeline import SecurityPipeline
    pipeline = SecurityPipeline(config=base_config, redis=redis_client)
    await pipeline.start()
    yield pipeline
    await pipeline.stop()
```

### A.8 Standard Parametrize Patterns

Use `@pytest.mark.parametrize` consistently. These patterns appear throughout
the codebase:

#### Threshold boundary testing (all modules with configurable scores)

```python
@pytest.mark.parametrize("score,dial,expected_action", [
    (19,  100, "allow"),      # Below flag threshold
    (20,  100, "flag"),       # At flag threshold (inclusive)
    (34,  100, "flag"),       # Below rate_limit threshold
    (35,  100, "rate_limit"), # At rate_limit threshold
    (69,  100, "rate_limit"), # Below block threshold  ← most important boundary
    (70,  100, "block"),      # At block threshold
    (84,  100, "block"),      # Below ban threshold
    (85,  100, "ban"),        # At ban threshold
    (100, 100, "ban"),        # Maximum score
    (100, 0,   "allow"),      # dial=0 always allows regardless of score
    (100, 50,  "block"),      # Effective threshold at dial=50 with block=70: ~86
])
def test_action_decision(score, dial, expected_action, action_decider):
    assessment = RiskAssessment(total_score=score, signals=[], recommended_action="")
    assert action_decider.decide(assessment, dial=dial) == expected_action
```

#### IPv4/IPv6 parity (all modules touching IPs)

```python
@pytest.mark.parametrize("ip,subnet", [
    ("1.2.3.4",          "1.2.3.0/24"),      # IPv4 → /24
    ("185.220.101.5",    "185.220.101.0/24"),
    ("2001:db8::1",      "2001:db8::/48"),    # IPv6 → /48
    ("::1",              "::/48"),
    ("2606:4700:4700::1111", "2606:4700:4700::/48"),
])
def test_subnet_extraction(ip, subnet):
    assert get_analysis_subnet(ip) == subnet
```

#### Bypass conditions (all enabled/disabled states)

```python
@pytest.mark.parametrize("bypass_name,connection_attr,bypass_value", [
    ("alpn_browser_bypass",    "alpn",                  "h2"),
    ("alpn_browser_bypass",    "alpn",                  "h1"),
    ("ja4_whitelist_bypass",   "ja4",                   "t13d1516h2_8daaf6_abc"),
    ("ja4_blacklist_bypass",   "ja4",                   "t13d190900_9dc94_known_bad"),
    ("country_blacklist_bypass", "country",             "CN"),
    ("static_ip_allowlist",    "ip",                    "203.0.113.10"),
    ("mtls_bypass",            "has_valid_client_cert", True),
])
def test_bypass_enabled(bypass_name, connection_attr, bypass_value, pipeline):
    conn = make_connection(**{connection_attr: bypass_value})
    action = pipeline.apply_bypasses(conn, bypasses_enabled={bypass_name: True})
    assert action in ("allow", "block")  # Bypass fired (not scored)

def test_bypass_disabled_routes_to_scorer(bypass_name, ...):
    # Same connection, bypass disabled → reaches scorer
    ...
```

#### Signal enable/disable (all configurable signal modules)

```python
@pytest.mark.parametrize("enabled", [True, False])
def test_module_respects_enabled_flag(enabled, sni_analyzer, config_with_dial_100):
    config_with_dial_100["sni_analysis"]["enabled"] = enabled
    signals = sni_analyzer.analyze(sni=None)  # Would trigger missing_sni
    if enabled:
        assert any(s.name == "missing_sni" for s in signals)
    else:
        assert signals == []
```

### A.9 Mock Usage Patterns

#### Mocking external services in unit tests

```python
# ✓ CORRECT — patch at the call site, not the definition site
@patch("src.security.abuseipdb.aiohttp.ClientSession")
async def test_api_lookup(mock_session_cls):
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.json.return_value = {"data": {"abuseConfidenceScore": 75}}
    mock_session_cls.return_value.__aenter__.return_value.get \
        .return_value.__aenter__.return_value = mock_response

    client = AbuseIPDBClient(api_key="test-key", redis=fake_redis)
    score = await client._api_lookup("185.220.101.5")
    assert score == 75
```

#### Using `tests/mocks/` servers in integration tests

```python
# tests/integration/test_abuseipdb_integration.py
import pytest
from tests.mocks.abuseipdb_mock import AbuseIPDBMockServer

@pytest.fixture
async def abuseipdb_mock():
    server = AbuseIPDBMockServer()
    server.add_response("185.220.101.5", confidence=95)
    server.add_response("1.1.1.1", confidence=0)
    server.set_rate_limit_after(n=5)   # Return 429 after 5 requests
    async with server.running() as base_url:
        yield base_url, server


async def test_high_confidence_ip_scores_high(abuseipdb_mock, redis_client):
    base_url, _ = abuseipdb_mock
    client = AbuseIPDBClient(api_key="test", redis=redis_client,
                              base_url=base_url)
    await client._api_lookup("185.220.101.5")

    # Score should now be in Redis
    cached = await redis_client.get("abuseipdb:score:185.220.101.5")
    assert int(cached) == 95
```

### A.10 Async Test Configuration

All async tests use `pytest-asyncio`. Configure in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"         # All async test functions run automatically
testpaths = ["tests"]
markers = [
    "unit: fast, isolated, no I/O",
    "integration: requires Redis",
    "chaos: destructive, requires Docker",
    "adversarial: malformed input tests",
    "fp_corpus: false-positive rate tests",
    "performance: benchmarks",
    "e2e: full stack, requires docker-compose",
    "slow: takes > 5 seconds",
]
filterwarnings = [
    "error",                          # Treat all warnings as errors
    "ignore::DeprecationWarning",     # Except deprecation warnings from dependencies
]
```

Mark tests appropriately:

```python
@pytest.mark.unit
async def test_something_fast(): ...

@pytest.mark.integration
async def test_something_with_redis(): ...

@pytest.mark.chaos
@pytest.mark.slow
async def test_redis_failure(): ...
```

### A.11 Module-to-Test-File Mapping

Every source module has a corresponding unit test file. Additional test files
cover cross-module scenarios. ✓ = implemented, — = planned/not yet needed.

| Source module | Unit test file | Integration test | Chaos test | Coverage |
|--------------|---------------|-----------------|-----------|----------|
| `src/security/risk_scorer.py` | `tests/unit/test_risk_scorer.py` ✓ | `test_pipeline.py` ✓ | — | 96% |
| `src/security/action_decider.py` | `tests/unit/test_action_decider.py` ✓ | `tests/integration/test_dial_propagation.py` ✓ | `tests/chaos/test_dial_change_chaos.py` ✓ | ~95% |
| `src/security/tls_enforcer.py` | `tests/unit/test_tls_enforcer.py` ✓ | `test_pipeline.py` ✓ | `tests/chaos/test_redis_failure.py` ✓ | ~95% |
| `src/security/sni_analyzer.py` | `tests/unit/security/test_sni_analyzer.py` ✓ | `tests/integration/test_sni_pipeline.py` ✓ | `tests/chaos/test_sni_chaos.py` ✓ | 92% |
| `src/security/tcp_analyzer.py` | `tests/unit/security/test_tcp_analyzer.py` ✓ | `tests/integration/test_tcp_pipeline.py` ✓ | `tests/chaos/test_tcp_chaos.py` ✓ | 82% |
| `src/security/mtls.py` | `tests/unit/security/test_mtls.py` ✓ | `tests/integration/test_bypass_rules.py` ✓ | — | 80% |
| `src/security/asn_classifier.py` | `tests/unit/security/test_asn_classifier.py` ✓ | `tests/integration/test_asn_pipeline.py` ✓ | `tests/chaos/test_asn_chaos.py` ✓ | 70% |
| `src/security/dns_enrichment.py` | `tests/unit/security/test_dns_enrichment.py` ✓ | `test_pipeline.py` ✓ | `tests/chaos/test_dns_chaos.py` ✓ | 70% |
| `src/security/blocklists.py` | `tests/unit/test_blocklists.py` ✓ | `tests/integration/test_bypass_rules.py` ✓ | `tests/chaos/test_feed_staleness.py` ✓ | 69% |
| `src/security/beaconing_detector.py` | `tests/unit/security/test_beaconing_detector.py` ✓ | `tests/integration/test_beaconing_pipeline.py` ✓ | `tests/chaos/test_redis_failure.py` ✓ | 94% |
| `src/security/abuseipdb.py` | `tests/unit/test_abuseipdb.py` ✓ | `test_abuseipdb_integration.py` ✓ | `test_abuseipdb_chaos.py` ✓ | 92% |
| `src/security/rdap_enrichment.py` | `tests/unit/test_rdap_enrichment.py` ✓ | `test_rdap_pipeline.py` ✓ | `test_rdap_chaos.py` ✓ | 88% |
| `src/analytics/main.py` | `test_analytics_node.py` ✓ | `test_analytics_pipeline.py` ✓ | `test_analytics_chaos.py` ✓ | 90% |
| `src/cache/local_cache.py` | `tests/unit/test_local_cache.py` ✓ | `tests/integration/test_cache_hierarchy.py` ✓ | `tests/chaos/test_redis_failure.py` ✓ | ~95% |
| `config_loader.py` | `tests/unit/test_config_loader.py` ✓ | `tests/integration/test_hot_reload.py` ✓ | — | 98% |

#### Coverage gaps (as of Phase 9)

| Module | Coverage | Uncovered area |
|--------|----------|---------------|
| `src/security/asn_classifier.py` | 70% | MaxMind actual IP lookup (requires real .mmdb + real IPs), Tor list leader election when Redis is available |
| `src/security/blocklists.py` | 69% | Live feed download HTTP paths, FeedManager ETag logic, leader election success path |
| `src/security/dns_enrichment.py` | 70% | Real async PTR lookup (requires live DNS), worker restart loop, passive DNS log |
| `src/security/tcp_analyzer.py` | 82% | Some edge cases in connection timing analysis |
| `proxy.py` | 92% | Error paths in `_forward_to_backend`, `handle_connection` edge cases |

The 69–70% modules are intentionally low: the uncovered lines require real
external services (MaxMind DB, live DNS, live HTTP servers) that we don't
spin up in unit or chaos tests. The important failure modes are covered via
mock-based chaos tests.

### A.12 `Makefile` Targets

```makefile
test-unit:
	pytest tests/unit/ -m unit -x --tb=short

test-integration:
	pytest tests/integration/ -m integration --tb=short

test-chaos:
	pytest tests/chaos/ -m chaos --tb=long -s

test-adversarial:
	pytest tests/adversarial/ -m adversarial --tb=short

test-fp-corpus:
	pytest tests/fp_corpus/ -m fp_corpus --tb=short

test-performance:
	pytest tests/performance/ -m performance --tb=short

test-e2e:
	pytest tests/e2e/ -m e2e --tb=long -s

test-all:
	pytest tests/ --ignore=tests/e2e --ignore=tests/chaos -x --tb=short

check-style:
	python3 scripts/check_style.py docs/phases/

check-test-ratio:
	python3 scripts/check_test_ratio.py

lint:
	ruff check src/ tests/
	mypy src/ --ignore-missing-imports

fuzz-quick:
	python3 -m atheris tests/adversarial/fuzz_tls_parser.py -- -max_total_time=30
```

---

## Appendix B: Test Categories (Container Layer Model)

> Folded in from `docs/TEST_SUITE.md` during Phase 105 consolidation; original
> was written in Phase 21 and codifies the eight-layer container test taxonomy
> from `docs/docker_container_test_layers_expanded.md`. This view groups tests
> by where they fit in a containerised release pipeline; §1 above groups them
> by the kind of behaviour they exercise. The two models are complementary.
>
> Note: this appendix mixes Phase-0-style "writing genuine tests" guidance
> (originally in `docs/TESTING.md`) with the layered model (originally in
> `docs/TEST_SUITE.md`); both have been retained verbatim where they did not
> overlap.

### B.1 Overview

JA4proxy uses a comprehensive multi-layer testing approach following the
practices in `docs/docker_container_test_layers_expanded.md`.

### B.2 Running Tests

#### Quick Start

```bash
# Run all tests (static + dynamic)
./run-all-tests.sh

# Run only static tests (no services needed)
./run-all-tests.sh --static

# Run only dynamic tests (requires services)
./run-all-tests.sh --dynamic

# Run specific layer
./run-all-tests.sh --layer 1

# Run linting only
./run-all-tests.sh --lint
```

### B.3 Test Layers

#### Layer 1: Code-Level and Build-Time Tests (Static Analysis)

**Purpose:** Validate correctness and security before containerization.

**Tests:**
- **Unit tests** (`tests/unit/`) - Individual function/class/module validation
- **Fuzz/Property tests** (`tests/fuzz/`) - Hypothesis-based property testing
- **Linting (Ruff)** - Code style and syntax checking
- **Type Checking (MyPy)** - Static type analysis
- **Code Formatting (Black)** - Code style enforcement
- **Import Sorting (Isort)** - Import organization
- **SAST (Bandit)** - Security vulnerability scanning
- **SAST (Semgrep)** - Advanced pattern matching
- **Dependency Scanning (Safety)** - Known vulnerability detection

**Run:** `./run-all-tests.sh --static` or `./run-all-tests.sh -s`

#### Layer 2: Image-Level Tests

**Purpose:** Validate Docker image as a build artifact.

**Tests:**
- **Dockerfile Linting (Hadolint)** - Best practices for Dockerfiles
- **Image Vulnerability Scanning (Trivy)** - CVE detection
- **Secrets Scanning** - Credential detection in images

**Run:** Part of static tests (`./run-all-tests.sh --static`)

#### Layer 3: Container-Level Tests

**Purpose:** Validate runtime behavior when executed as a container.

**Tests:**
- **Health Check Validation** - Container health status
- **Runtime Configuration** - User, capabilities, read-only filesystem
- **Resource Limits** - Memory and CPU constraints

**Run:** Part of dynamic tests (`./run-all-tests.sh --dynamic`)

#### Layer 4: Integration and Service-Level Tests

**Purpose:** Validate container interactions with each other and external systems.

**Tests:**
- **Integration Tests** (`tests/integration/`) - Redis, pipeline, caching
- **Service Health Validation** - All services running correctly
- **Redis Connectivity** - Cache and state management

**Run:** `./run-all-tests.sh --layer 4` or `./run-all-tests.sh --dynamic`

#### Layer 5: Orchestration and Deployment Tests

**Purpose:** Validate behavior under Docker Compose orchestration.

**Tests:**
- **Docker Compose Validation** - Configuration correctness
- **Network Isolation** - Proper network segmentation
- **Volume Mounts** - Config and data persistence

**Run:** `./run-all-tests.sh --layer 5` or `./run-all-tests.sh --dynamic`

#### Layer 6: Security and Compliance Tests

**Purpose:** Validate security posture.

**Tests:**
- **OWASP Security Tests** (`tests/security/`) - Common vulnerability tests
- **GDPR Compliance Tests** (`tests/compliance/`) - Data retention policies

**Run:** `./run-all-tests.sh --layer 6` or `./run-all-tests.sh --dynamic`

#### Layer 7: Performance, Resilience, and Operational Tests

**Purpose:** Validate behavior under load and failure conditions.

**Tests:**
- **Chaos Tests** (`tests/chaos/`) - Redis failure, network partition simulation
- **Performance Benchmarks** (`tests/performance/`) - Latency/throughput validation
- **Load Testing (Locust)** - High concurrency simulation (optional)

**Run:** `./run-all-tests.sh --layer 7` or `./run-all-tests.sh --dynamic`

#### Layer 8: End-to-End and User-Journey Tests

**Purpose:** Validate complete workflows from user perspective.

**Tests:**
- **E2E Tests** (`tests/integration/test_end_to_end.py`) - Full proxy workflows
- **Docker Stack Tests** (`tests/integration/test_docker_stack.py`) - Service integration

**Run:** `./run-all-tests.sh --layer 8` or `./run-all-tests.sh --dynamic`

### B.4 TLS Traffic Generator

The `scripts/generate-tls-traffic.sh` script generates real TLS connections
through the proxy to validate:

- JA4 fingerprinting accuracy
- Security blocking effectiveness
- Metrics collection
- Rate limiting behavior

**Run:**

```bash
# Short test (10 seconds)
./generate-tls-traffic.sh 10 50 10

# Full test (60 seconds)
./generate-tls-traffic.sh 60 15 50
```

### B.5 Test Organisation Snapshot

```
tests/
├── unit/                    # Unit tests (fast, isolated)
│   ├── test_*.py           # Core functionality
│   └── security/           # Security module tests
├── integration/             # Integration tests (require services)
│   ├── test_pipeline.py
│   ├── test_end_to_end.py
│   ├── test_cache_hierarchy.py
│   └── ...
├── chaos/                   # Resilience/failure testing
├── compliance/              # GDPR/compliance tests
├── fuzz/                   # Hypothesis-based property tests
├── performance/            # Benchmarks
└── security/               # OWASP-style security tests
```

### B.6 Test Requirements

#### Python Dependencies

- pytest==7.4.3
- pytest-asyncio==0.21.1
- pytest-cov==4.1.0
- hypothesis==6.88.1
- bandit==1.7.5
- ruff (linting)
- black (formatting)
- mypy (type checking)

#### External Services

- Redis (running on ja4proxy-redis)
- Backend service (for E2E tests)
- HAProxy (for full stack tests)

### B.7 CI/CD Integration

The test suite is designed to run in CI pipelines:

```bash
# Full test suite with coverage
docker compose -f deploy/docker/docker-compose.poc.yml run --rm test \
    pytest /app/tests -v --cov=proxy \
    --cov-report=xml --cov-report=term

# Quick smoke test
docker compose -f deploy/docker/docker-compose.poc.yml run --rm test \
    pytest /app/tests/integration/ -v
```

### B.8 Adding New Tests

1. **Unit tests:** Add to `tests/unit/` or `tests/unit/security/`
2. **Integration tests:** Add to `tests/integration/`
3. **Chaos tests:** Add to `tests/chaos/`
4. **Follow existing patterns:** Use fixtures from `tests/conftest.py`

### B.9 Coverage Goals (originally in `docs/TESTING.md`, Phase 0)

#### Overall Coverage

- **Target:** 80% minimum for all modules.
- **Current:** 84% overall (11570 statements, 1870 missed) — 3124 tests collected.

#### Module-Specific Goals

- **High Coverage (90%+):** Core security modules (e.g., `src/security/`).
- **Moderate Coverage (80-90%):** Utility modules (e.g., `src/utils/`).
- **Low Coverage (<80%):** TAP and export modules (e.g., `src/tap/tap_pipeline.py`
  at 44%, `src/tap/export/export_manager.py` at 44%);
  `src/utils/logging_config.py` currently at 0%.

#### Coverage Reporting

- **Tool:** `pytest-cov`.
- **Command:**

  ```bash
  python3 -m pytest tests/ --cov=src --cov-report=term-missing
  ```

- **Output:** HTML report in `reports/coverage/html`.

### B.10 Writing Genuine Tests (originally in `docs/TESTING.md`, Phase 0)

#### Do's

- **Do** write meaningful assertions:

  ```python
  def test_dial_zero_score_0_allows(self, decider):
      assert decider.decide(score=0, dial=0) == "allow"
  ```

- **Do** cover edge cases:

  ```python
  @pytest.mark.parametrize("cipher_list,ext_list,sni", [
      ([], [], None),  # All empty
      ([0x0A0A], [], "example.com"),  # Single GREASE cipher
  ])
  def test_ja4_does_not_crash(cipher_list, ext_list, sni):
      result = generator.generate_ja4(client_hello_fields)
      assert isinstance(result, str)
  ```

- **Do** test adversarial inputs:

  ```python
  @pytest.mark.parametrize("malicious_input", [
      "<script>alert('XSS')</script>",
      "'; DROP TABLE users--",
  ])
  def test_adversarial_input_blocked(self, evaluator, malicious_input):
      result = evaluator.evaluate_input(malicious_input)
      assert result.is_malicious
  ```

- **Do** use fixtures for setup:

  ```python
  @pytest.fixture
  def decider():
      return ActionDecider(thresholds=THRESHOLDS, ban_duration_seconds=300)
  ```

#### Don'ts

- **Don't** write placeholder tests:

  ```python
  def test_placeholder():
      pass  # No assertions
  ```

- **Don't** ignore edge cases:

  ```python
  def test_ja4_normal_input():
      # Missing tests for empty lists, max-length fields, etc.
      result = generator.generate_ja4(normal_fields)
      assert isinstance(result, str)
  ```

- **Don't** rely on external state:

  ```python
  def test_redis_dependent():
      # Fails if Redis is not running
      result = pipeline.execute(ctx)
      assert result.action == "allow"
  ```

### B.11 Test Maintenance

#### Regular Audits

- **Frequency:** Quarterly.
- **Goal:** Ensure tests remain genuine and relevant.
- **Steps:**
  1. Run `make test` and review coverage.
  2. Audit test files for meaningful assertions.
  3. Update this document (the testing strategy reference).

#### Automated Checks

- **Tool:** `pytest-cov`.
- **Integration:** CI/CD pipelines.
- **Command:**

  ```bash
  make test  # Runs all tests with coverage
  ```

### B.12 Troubleshooting

#### Tests fail with import errors

- Ensure PYTHONPATH includes `/app`
- Check that all `src/` modules are properly structured

#### Redis connection errors

- Ensure Redis container is running: `docker compose ps`
- Check Redis logs: `docker compose logs redis`

#### Flaky tests

- Check for race conditions in async code
- Ensure proper mocking of external services
- Review test isolation

### B.13 Reports

Test reports are generated in `reports/`:

- `junit-*.xml` - JUnit format for CI
- `coverage/` - HTML coverage reports
- `benchmark.txt` - Performance benchmarks
- `tls-traffic.txt` - TLS generator output

---

## Appendix C: Go-Specific Testing

> Folded in from `docs/TESTING_GO.md` during Phase 105 consolidation; original
> was written in Phase 21 to document how the Go proxy test suite differs
> from the Python one. The Go proxy is the production runtime (Phase 15);
> Python remains experimental. Both must pass equivalent behavioural tests.

### C.1 Where Tests Live

| Layer | Python | Go |
|-------|--------|----|
| Unit tests | `tests/unit/test_*.py` | `internal/*/`_`*_test.go` (alongside source) |
| Integration | `tests/integration/test_*.py` | `tests/integration/test_go_python_parity.py` (Python) |
| Chaos / resilience | `tests/chaos/test_*.py` | `tests/chaos/test_go_proxy_chaos.py` (Python) |
| Performance | `tests/performance/test_bench_pipeline.py` | `tests/performance/test_bench_go_proxy.py` (Python) |
| Adversarial | `tests/adversarial/` | Go parser fuzz via `go test -fuzz` |

The Python integration, chaos, and performance tests run against the **live
binary** in Docker. This is why they are Python even for the Go proxy — they
exercise the running system, not individual packages.

### C.2 Unit Tests: Go vs Python

#### What is the same

Both test suites verify **identical behaviour** for each signal module:

- Same signal names (`rate_limit_ban`, `sni_missing`, `tls_weak_cipher`, etc.)
- Same score values (matching the subplan spec)
- Same fail-open contract: disabled module → nil/empty signal; Redis error → nil signal

#### What is different

##### Test location

Python unit tests are in a separate `tests/unit/` directory. Go unit tests
live in the same package directory as the code they test (`_test.go` suffix).
This is idiomatic Go and avoids import cycles.

```
Python: tests/unit/test_rate_limiter.py   ← tests src/security/rate_limiter.py
Go:     internal/security/rate_limiter_test.go  ← tests internal/security/rate_limiter.go
```

##### Test structure

Python uses `pytest` with fixtures and parametrize decorators:

```python
@pytest.mark.parametrize("tls_version,expected_block", [
    (0x0300, True),   # SSLv3
    (0x0301, True),   # TLS 1.0
    (0x0304, False),  # TLS 1.3
])
def test_tls_version_block(tls_version, expected_block):
    enforcer = TLSEnforcer(cfg=TLSEnforcerConfig(block_old_tls=True))
    _, hard_block = enforcer.check(tls_version=tls_version, ciphers=[])
    assert hard_block == expected_block
```

Go uses table-driven tests with `t.Run`:

```go
func TestTLSEnforcer_VersionBlock(t *testing.T) {
    cases := []struct {
        name      string
        version   uint16
        wantBlock bool
    }{
        {"SSLv3",  0x0300, true},
        {"TLS1.0", 0x0301, true},
        {"TLS1.3", 0x0304, false},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            enforcer := NewTLSEnforcer(&TLSEnforcerConfig{BlockOldTLS: true}, logrus.New())
            _, block := enforcer.Check(tc.version, nil)
            if block != tc.wantBlock {
                t.Errorf("got block=%v, want %v", block, tc.wantBlock)
            }
        })
    }
}
```

##### Mocking dependencies

Python uses `unittest.mock` or `pytest-mock`:

```python
def test_rate_limiter_ban(mocker):
    mock_redis = mocker.MagicMock()
    mock_redis.sliding_window_count.return_value = 200
    limiter = RateLimiter(cfg=..., redis=mock_redis)
    signals = limiter.check(ip="1.2.3.4", ja4="t13d...")
    assert any(s.name == "rate_limit_ban" for s in signals)
```

Go uses interface injection with hand-written mock structs:

```go
type mockRedis struct {
    slidingWindowCounts map[string]int
}

func (m *mockRedis) SlidingWindowCount(_ context.Context, key string, _, _ float64) int {
    return m.slidingWindowCounts[key]
}

func TestRateLimiter_BanThreshold(t *testing.T) {
    mock := &mockRedis{slidingWindowCounts: map[string]int{"ratelimit:ip:1.2.3.4": 200}}
    limiter := NewRateLimiter(&RateLimiterConfig{Enabled: true, ByIP: StrategyConfig{Enabled: true, Ban: 100}}, mock, nil)
    sigs := limiter.Check(context.Background(), "1.2.3.4", "")
    if len(sigs) == 0 || sigs[0].Name != "rate_limit_ban" {
        t.Fatalf("expected rate_limit_ban signal")
    }
}
```

The `mockRedis` struct in `internal/security/pipeline_test.go` implements the
full `RedisReader` interface. All individual module tests that need Redis use
the same mock.

##### Async behaviour

Python tests can `await` coroutines directly. Go tests use synchronous calls;
background goroutines are tested indirectly by checking their side effects
(Redis writes) after a brief `time.Sleep` or by draining a channel:

```go
// Trigger background lookup
abuseipdb.GetSignal("1.2.3.4")
// Drain the lookup channel
select {
case ip := <-capturedLookups:
    if ip != "1.2.3.4" { t.Fatal("wrong IP") }
case <-time.After(100 * time.Millisecond):
    t.Fatal("lookup not enqueued")
}
```

##### No conftest.py

Python tests share fixtures through `tests/conftest.py`. Go has no
equivalent. Shared test helpers are plain functions in the `_test.go` file or
a `testutil_test.go` in the same package.

### C.3 Running Tests

#### Go unit tests (fast, no Docker)

```bash
# All packages
GOROOT=/snap/go/current go test ./...

# Single package
GOROOT=/snap/go/current go test -v ./internal/security/

# Single test
GOROOT=/snap/go/current go test -v -run TestRateLimiter_BanThreshold ./internal/security/

# Race detector (slow, use in CI)
GOROOT=/snap/go/current go test -race ./...

# Via Makefile
make go-test
```

#### Python unit tests (fast, no Docker)

```bash
python3 -m pytest tests/unit/ -n auto --dist=loadfile
make test-unit
```

#### Cross-language parity tests (requires both proxies running)

```bash
make go-start                                # start Go proxy on :8082
# wait ~10s for startup
make go-parity                               # runs test_go_python_parity.py
```

#### Chaos tests for Go proxy (requires running Docker stack)

```bash
python3 -m pytest tests/chaos/test_go_proxy_chaos.py -v
```

### C.4 Coverage Responsibility

| Scenario | Python test? | Go test? |
|----------|-------------|----------|
| Signal names and scores match spec | ✓ | ✓ |
| Fail-open on Redis error | ✓ | ✓ |
| Fail-open on GeoIP DB absent | ✓ | ✓ |
| JA4 byte-for-byte parity with Python | ✓ parity test | ✓ unit vectors |
| PROXY protocol parsing | — | ✓ |
| Prometheus metric registration | — | ✓ |
| Full pipeline with real Redis | ✓ integration | — (parity test covers) |
| Docker stack health check | ✓ integration | ✓ chaos |
| Redis failure mid-traffic | ✓ chaos | ✓ go_proxy_chaos |
| Throughput ≥ 5× Python | — | ✓ bench_go_proxy.py |

### C.5 What "Almost Identical, But Not Quite" Means

The Go and Python test suites cover the same *behaviour* but differ in:

1. **Location**: Go tests are colocated with source; Python tests are in `tests/`.
2. **Fixtures**: Python uses pytest fixtures and conftest; Go uses
   table-driven tests and inline construction.
3. **Async**: Python tests await coroutines; Go tests check
   channel/side-effect outputs.
4. **Infrastructure tests**: Docker stack tests (health check, parity, chaos)
   are Python even for the Go proxy, because they test the deployed binary,
   not the library.
5. **Fuzz tests**: Go has a native fuzzer (`go test -fuzz`). The TLS parser
   adversarial test in `tests/adversarial/` is Python; the Go equivalent uses
   `go test -fuzz=FuzzParseTLS`.
