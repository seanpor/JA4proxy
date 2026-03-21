# Phase 16 — Test Suite Hardening, Extended Fingerprinting & Operational Excellence

## Goal

Close the test coverage and quality gaps carried forward from Phases 0–15. Add
JA4X extended fingerprinting, adaptive rate limiting, Kubernetes deployment support,
and OpenTelemetry tracing. These items are prerequisites for enterprise production
readiness beyond the baseline established in Phase 14.

**Read `docs/TEST_ORGANIZATION.md §10` (coverage gap table) before starting.**

Sections 16a–16e address the test gaps identified during the Phase 9 review.
Sections 16f–16k address operational and feature improvements from the broader
roadmap. Do 16a–16e first — they have no external dependencies and unblock
accurate coverage measurement for everything else.

---

## 16a. Adversarial Input Corpus (`tests/adversarial/`)

**Problem:** A crafted ClientHello that triggers an unhandled exception in the TLS
parser causes a proxy process crash — a trivially accessible denial-of-service vector.
The existing `tests/fuzz/test_properties.py` uses Hypothesis-generated inputs but
does not commit a reproducible corpus of byte sequences that previously triggered bugs.

**Implementation:**

```
tests/adversarial/
├── corpus/
│   ├── README.md                      # Source and edge case for each file
│   ├── truncated_before_cipher_list.bin
│   ├── truncated_mid_extension.bin
│   ├── empty_cipher_list.bin
│   ├── all_grease_ciphers.bin
│   ├── max_length_sni_255_chars.bin
│   ├── sni_with_null_byte.bin
│   ├── overflow_extension_length.bin
│   ├── duplicate_extension_types.bin
│   ├── zero_length_clienthello.bin
│   └── random_garbage_512_bytes.bin
├── test_tls_parser_adversarial.py
└── test_ja4_adversarial.py
```

`test_tls_parser_adversarial.py` — parametrized over every `corpus/*.bin`:

```python
@pytest.mark.parametrize("corpus_file", list(CORPUS_DIR.glob("*.bin")))
def test_parser_does_not_crash(corpus_file):
    """Every corpus file must parse without raising an uncaught exception."""
    raw = corpus_file.read_bytes()
    try:
        result = TLSParser.parse_client_hello(raw)
        # Either a valid parse result or None — both acceptable
        assert result is None or isinstance(result, ClientHello)
    except (ValueError, struct.error):
        pass  # Expected parse failures are fine
    # Uncaught exceptions (AttributeError, IndexError, etc.) fail the test
```

`test_ja4_adversarial.py` — JA4 computation on degenerate inputs:

```python
@pytest.mark.parametrize("cipher_list,ext_list,sni", [
    ([], [], None),                    # All empty
    ([0x0A0A], [], "example.com"),     # All-GREASE ciphers
    (list(range(256)), [], ""),        # Max cipher list
    ([0xC02B], [0x0A0A, 0x0A0A], "a" * 255),  # Max SNI
    ([0xC02B], list(range(65)), None), # 65 extension types
])
def test_ja4_does_not_crash(cipher_list, ext_list, sni):
    result = JA4Generator.generate(cipher_list, ext_list, sni, tls_version=0x0304)
    assert isinstance(result, str)
    assert len(result) > 0
```

### Corpus maintenance

Every time a fuzzer finds a new crash, the input is committed to `corpus/` with a
description in `corpus/README.md`. The `tests/fuzz/test_properties.py` Hypothesis
database is also checked into `tests/fuzz/.hypothesis/examples/`.

---

## 16b. False-Positive Rate Corpus (`tests/fp_corpus/`)

**Problem:** The core asymmetry of this project is that false positives cost more than
false negatives. Without FP rate tests against real-world traffic patterns, a signal
threshold change in any phase could silently begin blocking a fraction of legitimate
users with no automated detection.

**Implementation:**

```
tests/fp_corpus/
├── data/
│   ├── README.md                      # Source and collection method for each dataset
│   ├── tranco_top_10k.txt             # Top 10k domains (committed, no network)
│   ├── residential_ips.txt            # 1000 known residential IPs (anonymised)
│   ├── browser_keepalive_timestamps.csv   # Real Chrome/Firefox/Safari timing
│   └── known_good_ja4_fingerprints.txt    # Browser fingerprints from JA4+ DB
├── test_dga_fp_rate.py
├── test_beaconing_fp_rate.py
└── test_asn_fp_rate.py
```

`test_dga_fp_rate.py`:

```python
MAX_DGA_FP_RATE = 0.01  # 1% — no more than 100 of top 10k flagged as DGA

def test_sni_dga_fp_rate_below_threshold():
    """Tranco top 10k must not be flagged as DGA above 1% FP rate."""
    domains = (FP_DATA_DIR / "tranco_top_10k.txt").read_text().splitlines()
    analyzer = SNIAnalyzer(config={"sni_analysis": {"enabled": True, "score": 40}})
    flagged = sum(
        1 for d in domains
        if any(s.name == "dga_sni" for s in analyzer.analyze(sni=d))
    )
    fp_rate = flagged / len(domains)
    assert fp_rate <= MAX_DGA_FP_RATE, (
        f"DGA FP rate {fp_rate:.2%} exceeds {MAX_DGA_FP_RATE:.0%} threshold "
        f"({flagged}/{len(domains)} Tranco top-10k domains flagged)"
    )
```

`test_beaconing_fp_rate.py`:

```python
def test_browser_alpn_guard_ensures_zero_fp():
    """Browser ALPN guard must produce exactly 0% FP rate on h2/h1 connections."""
    timestamps = load_browser_keepalive_timestamps()  # Real Chrome/Firefox timing
    for browser, ts_list in timestamps.items():
        iats = compute_iats(ts_list)
        # With h2/h1 ALPN guard in place, detector never reaches IAT computation
        # This test verifies the guard fires before any scoring
        detector = _make_detector()
        asyncio.run(detector.maybe_record("1.2.3.4", "t13d...", "h2", "allow"))
        # No timestamps should have been recorded
        assert len(detector._test_recorded) == 0, f"Browser timing ({browser}) was recorded"

def test_irregular_human_timing_scores_zero():
    """Real browser keep-alive timing must score 0.0 (no beacon signal)."""
    timestamps = load_browser_keepalive_timestamps()
    for browser, ts_list in timestamps.items():
        iats = compute_iats(ts_list)
        score = beacon_score(iats)
        assert score == 0.0, f"{browser} keep-alive scored {score} (expected 0.0)"
```

`test_asn_fp_rate.py`:

```python
MAX_ASN_FP_RATE = 0.02  # 2% — residential IPs misclassified as datacenter/tor/vpn

def test_residential_ip_fp_rate_below_threshold():
    """Known residential IPs must not be classified as datacenter/tor/vpn above 2%."""
    ips = (FP_DATA_DIR / "residential_ips.txt").read_text().splitlines()
    classifier = ASNClassifier(config_with_maxmind, mock_redis)
    flagged = sum(
        1 for ip in ips
        if classifier.classify(ip).category in ("datacenter", "tor", "vpn")
    )
    fp_rate = flagged / len(ips)
    assert fp_rate <= MAX_ASN_FP_RATE, (
        f"ASN FP rate {fp_rate:.2%} exceeds {MAX_ASN_FP_RATE:.0%} threshold"
    )
```

---

## 16c. Coverage Gates (≥ 80% All Modules)

**Problem:** Three modules sit at 69–70% line coverage because the uncovered paths
require real external services (MaxMind .mmdb, live DNS, live HTTP). These paths are
not tested at all today — not even with mocks — leaving real bug surface exposed.

**Target:** every `src/security/*.py` module ≥ 80%, `proxy.py` ≥ 95%.

### `asn_classifier.py` (currently 70%)

Uncovered: MaxMind actual IP lookup (lines 220–265), Tor leader election success path
(lines 273–300), ASN datacenter list loading (lines 354–357).

Approach:
- Commit a minimal 10-entry test MaxMind database (`tests/fixtures/GeoLite2-ASN-test.mmdb`)
  generated with `mmdbwriter`. Tests that need IP lookup use this fixture.
- Mock `aiohttp.ClientSession` for the download path; verify ETag 304 handling.
- Test leader election success: `mock_redis.set.return_value = True` (leader wins).

```python
@pytest.fixture
def test_mmdb():
    """10-entry MaxMind test database covering: residential, datacenter, Tor ASNs."""
    return Path("tests/fixtures/GeoLite2-ASN-test.mmdb")

def test_classify_datacenter_ip_with_real_mmdb(test_mmdb):
    config = {"asn_classifier": {"maxmind_db_path": str(test_mmdb), ...}}
    classifier = ASNClassifier(config, MagicMock())
    result = classifier.classify("1.2.3.4")  # IP in test DB as AS14618 (AWS)
    assert result.category == "datacenter"
```

### `blocklists.py` (currently 69%)

Uncovered: feed download HTTP paths (lines 190–265), ETag 304 handling (lines
310–341), FeedManager leader election success (lines 382–452).

Approach:
- Mock `aiohttp.ClientSession` with fixtures for: 200 OK with content, 304 Not
  Modified, 429 Rate Limited, connection timeout, malformed response body.
- Test the full leader-election→download→parse→load sequence end-to-end with mocks.

### `dns_enrichment.py` (currently 70%)

Uncovered: async PTR lookup (lines 179–222), worker restart loop (lines 293–358),
passive DNS startup log (lines 407–443).

Approach:
- Mock `asyncio.get_event_loop().run_in_executor` or use `unittest.mock.patch`
  on `socket.gethostbyaddr` to return controlled PTR results.
- Test the worker task restart: inject a one-shot exception then normal operation.

### Coverage CI gate

Add to `scripts/run-tests.sh` (or a separate `make coverage` target):

```bash
python3 -m pytest tests/ --ignore=tests/integration/test_docker_stack.py \
    --cov=src --cov=proxy \
    --cov-fail-under=80 \
    --cov-report=term-missing \
    --cov-report=html:reports/coverage/
```

The `--cov-fail-under=80` flag fails the build if any module drops below threshold.

---

## 16d. External API Failure Chaos Tests (`tests/chaos/test_external_api_failure.py`)

**Problem:** When Phase 10 (AbuseIPDB) and Phase 11 (RDAP) are built, their failure
modes must be tested. These chaos tests should be written alongside those phases, but
their structure is defined here to avoid drift between the phase implementation and
the test design.

**Scenarios to cover:**

```python
class TestAbuseIPDBDown:
    def test_api_down_returns_none_silently(self): ...
        # aiohttp raises ConnectionError → get_signal() returns None
        # Prometheus: ja4proxy_abuseipdb_lookups_total{result="error"} += 1
        # Pipeline: connection allowed (fail open)

    def test_api_rate_limited_uses_cache(self): ...
        # 429 response → fall back to cached score; no crash
        # If no cache: returns None (fail open)

    def test_api_timeout_respects_hot_path(self): ...
        # AbuseIPDB lookup is fire-and-forget; timeout never blocks pipeline

    def test_api_returns_malformed_json(self): ...
        # JSON parse error → logged + None returned; no crash


class TestRDAPDown:
    def test_rdap_unavailable_returns_no_signal(self): ...
    def test_rdap_iana_bootstrap_fails_gracefully(self): ...
    def test_block_expansion_skipped_when_rdap_unreachable(self): ...


class TestAllExternalAPIsDown:
    def test_pipeline_allows_when_all_apis_down(self): ...
        # AbuseIPDB + RDAP + Spamhaus all return errors
        # Pipeline falls through to scoring with 0 external signals
        # Action: allow (fail open; dial governs)

    def test_error_counters_all_incremented(self): ...
        # Each failing API increments its own Prometheus error counter
```

---

## 16e. Performance Benchmark CI Gate (`tests/performance/`)

**Problem:** `tests/performance/bench_*.py` files are not collected by pytest (not
named `test_*.py`) and have no CI gate. Performance regressions are currently
invisible.

**Implementation:**

Rename to `test_bench_*.py` and add assertions:

```python
# tests/performance/test_bench_pipeline.py

ALLOW_BYPASS_P99_MS = 0.5    # Bypass path (ALPN/whitelist): < 500µs
SCORING_PATH_P99_MS = 1.0    # Full scoring path at dial=100: < 1ms

def test_allow_bypass_latency():
    """Bypass decisions (h2 ALPN) must complete in < 500µs p99."""
    pipeline = _make_pipeline(dial=100)
    ctx = ConnectionContext(client_ip="1.2.3.4", ja4="t13d1516h2_abc", alpn="h2")
    latencies = []
    for _ in range(1000):
        t0 = time.perf_counter()
        asyncio.run(pipeline.process(ctx))
        latencies.append((time.perf_counter() - t0) * 1000)
    p99 = statistics.quantiles(latencies, n=100)[98]
    assert p99 < ALLOW_BYPASS_P99_MS, f"Bypass p99={p99:.2f}ms exceeds {ALLOW_BYPASS_P99_MS}ms"

def test_scoring_path_latency():
    """Full scoring path must complete in < 1ms p99 (mocked Redis, no I/O)."""
    ...

def test_cidr_trie_lookup_latency():
    """pytricia trie with 100k entries: lookup < 10µs p99."""
    ...
```

Benchmark results written to `reports/benchmark_latest.txt` on every CI run.
Regression detection: compare against `reports/benchmark_baseline.txt`; fail if
any metric regresses by > 20%.

---

## 16f. Static Analysis CI Gates

**Problem:** Type errors, security antipatterns, and known-vulnerable dependencies
are currently caught only by code review. Automated gates are needed before Phase 15
(Go rewrite) to establish a correctness baseline.

**Add to CI (sequential, before pytest):**

```bash
# Type checking — zero errors required
mypy src/ proxy.py --ignore-missing-imports --strict-optional

# Security vulnerability scan
bandit -r src/ proxy.py -ll --exclude tests/

# Advanced pattern matching (supply chain, injection, crypto)
semgrep --config=p/python --config=p/secrets --error src/ proxy.py

# Dependency vulnerability scan
safety check --full-report

# Code formatting (non-blocking in CI, just report)
ruff check src/ tests/ proxy.py
```

`mypy` is the hardest gate to add to an existing codebase. Strategy: start with
`--ignore-missing-imports` and `--no-strict-optional` (Phase 16a), then tighten to
`--strict` (Phase 16b, before Go rewrite so type specs are precise for translation).

---

## 16g. JA4X Extended Fingerprinting

**Problem:** JA4 covers the TLS handshake. JA4X covers the X.509 certificates
presented in the handshake — primarily useful for detecting mTLS clients and
certificate-based C2 frameworks that share infrastructure certificates.

**Scope:** JA4X analysis on the server certificate (seen by the proxy in passthrough
mode) and on client certificates (when `mtls.enabled = true`).

**JA4X fields:**
```
ja4x = {issuer_hash}_{subject_hash}_{san_hash}
```

Each hash is the SHA-256 truncated to 12 hex chars of the sorted, comma-joined field
values (same approach as JA4 cipher/extension hashes).

**Integration:**
- Add `ja4x` field to `ConnectionContext`
- `TLSEnforcer` populates `ja4x` from the server cert during passthrough (via SNI
  inspection of the raw TLS record — no decryption needed for the cert chain)
- `ja4x` emitted in Prometheus labels (same `fingerprint` label as `ja4`) and
  structured JSON log
- JA4X blacklist/whitelist parallel to JA4 lists (same Redis SET structure)

**Config:**
```yaml
fingerprinting:
  ja4x:
    enabled: true              # Default: true. Populate ja4x from cert chain.
    blacklist_score: 80        # Score contribution if ja4x in blacklist
    emit_in_logs: true         # Include ja4x in structured log output
```

---

## 16h. Adaptive Rate Limiting

**Problem:** The current sliding-window rate limiter uses static thresholds. During a
DDoS burst, the effective threshold is too permissive; during normal traffic it is
unnecessarily aggressive for outlier legitimate clients.

**Implementation:** Exponential weighted moving average (EWMA) of observed traffic
rate, adjusted per /24 subnet, updated every 60 seconds by the analytics node.

```python
# Analytics computes adaptive thresholds every 60s
# Writes to: rate:adaptive:{subnet} → {threshold_rps, confidence}
# TTL: 120s (two analytics cycles)

# Proxy reads adaptive threshold if available, falls back to static config
async def get_rate_threshold(ip: str) -> int:
    subnet = get_analysis_subnet(ip)
    adaptive = await redis.hgetall(f"rate:adaptive:{subnet}")
    if adaptive and float(adaptive[b"confidence"]) > 0.7:
        return int(adaptive[b"threshold_rps"])
    return config["rate_limiter"]["requests_per_second"]  # Static fallback
```

**Config:**
```yaml
rate_limiter:
  adaptive:
    enabled: false              # Default: false. Enable only with analytics node running.
    min_threshold_rps: 5        # Never adapt below 5 req/s regardless of EWMA
    max_threshold_rps: 1000     # Never adapt above 1000 req/s
    confidence_minimum: 0.7     # Use adaptive threshold only if analytics confidence ≥ 0.7
    fallback_to_static: true    # Default: true. Fall back to static if no adaptive data.
```

**Redis Key Schema additions:**

| Key | Type | TTL | Written by | Notes |
|-----|------|-----|------------|-------|
| `rate:adaptive:{subnet}` | Hash (`threshold_rps`, `confidence`) | 120s | Analytics node | Per-subnet adaptive threshold; proxy reads as rate limit override |

---

## 16i. Kubernetes / Helm Deployment

**Problem:** The Docker Compose deployment in Phase 14 targets a single-host DMZ.
Enterprise environments require Kubernetes for horizontal scaling, rolling updates,
pod disruption budgets, and secrets management via Kubernetes Secrets or Vault.

**Deliverables:**

```
deploy/helm/ja4proxy/
├── Chart.yaml
├── values.yaml             # Default values matching docker-compose.poc.yml
├── templates/
│   ├── deployment.yaml     # proxy + anti-affinity for multi-node spread
│   ├── service.yaml        # ClusterIP for HAProxy upstream
│   ├── redis.yaml          # StatefulSet (or external Redis reference)
│   ├── configmap.yaml      # proxy.yml mounted as ConfigMap
│   ├── secret.yaml         # API keys, Redis password (templated only; use Vault)
│   ├── hpa.yaml            # HorizontalPodAutoscaler based on connection count metric
│   ├── pdb.yaml            # PodDisruptionBudget: minAvailable=1
│   └── servicemonitor.yaml # Prometheus Operator ServiceMonitor
```

**Scaling policy:**
- Scale out on `ja4proxy_connections_active > 500` per pod
- Scale in when `ja4proxy_connections_active < 100` per pod for 5 minutes
- Min replicas: 2 (redundancy). Max replicas: 20.
- Anti-affinity: spread pods across nodes (no two replicas on same host)

**Config:**
```yaml
# values.yaml (key entries)
replicaCount: 2
image:
  repository: ja4proxy
  tag: latest
  pullPolicy: IfNotPresent
resources:
  limits:
    cpu: "2"
    memory: "512Mi"
  requests:
    cpu: "500m"
    memory: "128Mi"
hpa:
  enabled: true
  minReplicas: 2
  maxReplicas: 20
  targetConnectionCount: 500
redis:
  external: true             # Use external Redis (required for multi-pod)
  url: ""                    # Set via REDIS_URL secret
```

---

## 16j. OpenTelemetry Distributed Tracing

**Problem:** When a connection is blocked or tarpitted, there is no way to trace
which signal fired, which Redis call was slow, or which external API contributed to
the decision. Structured JSON logs capture the decision but not the timing breakdown.

**Implementation:** Optional OpenTelemetry instrumentation. Off by default. No
performance impact when disabled (zero-cost with OTEL SDK's noop provider).

```python
# src/telemetry/tracing.py
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

def init_tracing(endpoint: str | None = None):
    if not endpoint:
        return  # Noop provider — zero overhead

    provider = TracerProvider()
    exporter = OTLPSpanExporter(endpoint=endpoint)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
```

Each pipeline stage becomes a span:
```python
with tracer.start_as_current_span("pipeline.process") as span:
    span.set_attribute("client.ip", ctx.client_ip)
    span.set_attribute("ja4", ctx.ja4)
    ...
    with tracer.start_as_current_span("pipeline.collect_signals"):
        signals = await self._collect_signals(ctx)
    span.set_attribute("risk.score", score)
    span.set_attribute("action", action)
```

**Config:**
```yaml
telemetry:
  tracing:
    enabled: false              # Default: false. Zero-cost when disabled.
    endpoint: ""                # OTLP gRPC endpoint (e.g. http://jaeger:4317)
    service_name: ja4proxy
    sample_rate: 0.01           # Default: 1% sampling. At 1000 conn/s → 10 traces/s.
```

---

## 16k. Python CLI for Admin Operations

**Problem:** Admin operations (ban an IP, adjust dial, inspect a JA4 fingerprint,
flush a specific cache key) are done through Redis CLI or curl. This requires knowing
the internal key schema and is error-prone.

**Implementation:** `ja4proxy-admin` CLI using `click`:

```
scripts/ja4proxy_admin.py:
  ban <ip> [--ttl 3600]
  unban <ip>
  dial get
  dial set <value> [--acknowledge-blocking]
  whitelist add <ja4>
  whitelist remove <ja4>
  blacklist add <ja4>
  blacklist remove <ja4>
  suspect list [--top 20]
  inspect ip <ip>          # All Redis keys for an IP
  inspect ja4 <ja4>        # Whitelist/blacklist/suspect status
  flush abuseipdb <ip>     # Clear cached AbuseIPDB score
  flush beaconing <ip>     # Clear beacon timing history
  status                   # Proxy instances, Redis memory, dial value, event stream lag
```

All commands read `REDIS_URL` from environment. Output is JSON (`--format json`) or
human-readable table (default). Every destructive command requires `--confirm` flag.

```bash
# Usage examples
ja4proxy-admin ban 185.220.101.5 --ttl 86400
ja4proxy-admin dial set 75 --acknowledge-blocking
ja4proxy-admin suspect list --top 10 --format json
ja4proxy-admin inspect ip 1.2.3.4
```

---

## Redis Key Schema

Phase 16 adds one new key (16h adaptive rate limiting). All others use existing schema.

| Key | Type | TTL | Written by | Notes |
|-----|------|-----|------------|-------|
| `rate:adaptive:{subnet}` | Hash (`threshold_rps`, `confidence`) | 120s | Analytics node | Per-subnet adaptive rate limit; read by proxy |

---

## Config

All new `config/proxy.yml` keys introduced in this phase:

```yaml
fingerprinting:
  ja4x:
    enabled: true
    blacklist_score: 80
    emit_in_logs: true

rate_limiter:
  adaptive:
    enabled: false
    min_threshold_rps: 5
    max_threshold_rps: 1000
    confidence_minimum: 0.7
    fallback_to_static: true

telemetry:
  tracing:
    enabled: false
    endpoint: ""
    service_name: ja4proxy
    sample_rate: 0.01
```

---

## Chaos Scenarios

| Scenario | Expected behaviour |
|----------|--------------------|
| Adversarial ClientHello (all corpus files) | Parser returns None or raises ValueError; no panic; no crash; pipeline allows (fail open) |
| AbuseIPDB down | `get_signal()` returns None; Prometheus error counter incremented; connection scored without AbuseIPDB contribution |
| RDAP down | Same as above for RDAP |
| All external APIs simultaneously down | Pipeline allows all connections; every error counter incremented; no score contribution from any external API |
| Analytics node produces no adaptive rate data | Proxy falls back to static rate limit thresholds; no degradation |
| Adaptive threshold key evicted from Redis | Same fallback to static; MISS logged at DEBUG |
| OpenTelemetry endpoint unreachable | Tracing silently drops spans; proxy performance unaffected; WARN logged once at startup |
| JA4X computation on cert with missing fields | `ja4x` field set to `"000000000000_000000000000_000000000000"`; no crash |

---

## Acceptance Criteria

### 16a — Adversarial Corpus ✅

- [x] `tests/adversarial/corpus/` contains 13 `.bin` files; each described in `corpus/README.md`
- [x] `test_tls_parser_adversarial.py` — all 12 corpus files (parametrized) parse without uncaught exception; runs in ~0.7s
- [x] `test_ja4_adversarial.py` — 10 degenerate inputs (empty, all-GREASE, max-length, null bytes, duplicates) pass
- [x] `tests/adversarial/` included in default pytest run (testpaths = ["tests"] in pyproject.toml)

### 16b — False-Positive Rate Corpus ✅

- [x] `tests/fp_corpus/data/tranco_top_10k.txt` committed; 10,000 domains; no network required
- [x] `tests/fp_corpus/data/residential_ips.txt` — 500 IPs; collection method documented in `data/README.md`
- [x] `tests/fp_corpus/data/browser_keepalive_timestamps.csv` — 450 rows, 30 sessions across Chrome/Firefox/Safari (synthetic but realistic IAT distributions; deterministic seed=2026)
- [x] DGA FP rate < 1% against Tranco top 10k (`test_dga_fp_rate.py`)
- [x] Beaconing FP rate = 0% on h2/h1 ALPN connections (ALPN guard test)
- [x] Beaconing FP rate = 0% on blocked connections (guard verified)
- [x] ASN FP rate < 2% on known residential IPs (`test_asn_fp_rate.py`)

### 16c — Coverage Gates

- [ ] `asn_classifier.py` ≥ 80% line coverage (currently 70%)
- [ ] `blocklists.py` ≥ 80% line coverage (currently 69%)
- [ ] `dns_enrichment.py` ≥ 80% line coverage (currently 70%)
- [ ] `tcp_analyzer.py` ≥ 85% line coverage (currently 82%)
- [ ] All other `src/security/*.py` modules ≥ 90%
- [ ] `proxy.py` ≥ 95% line coverage
- [ ] `pytest --cov-fail-under=80` added to CI; build fails if any module drops below

### 16d — External API Chaos Tests ✅

- [x] `test_external_api_failure.py` covers: API down (`ConnectionError`), rate limited (429), Redis failures, malformed JSON, timeout (5s drain)
- [x] All scenarios verify: pipeline allows connection (fail open); error logged; no crash
- [x] Simultaneous failure of all external APIs: `TestAllApiSimultaneousFailure` class (3 tests) — AbuseIPDB + RDAP both down → both fail open, no crash

### 16e — Performance Benchmark CI Gate ✅

- [x] `test_bench_pipeline.py` — `TestPhase16eAcceptanceCriteria`: allow bypass p99=2.3µs (<500µs ✓); scoring path p99=20.6µs (<1ms ✓)
- [x] `test_bench_cidr_lookup.py` — 100k-entry trie lookup p99=0.96µs (<10µs ✓); added as proper pytest functions
- [x] Benchmark baseline committed to `reports/benchmark_baseline.txt`; latest results in `reports/benchmark_latest.txt`
- [x] All performance tests pass as part of main test suite (included in `testpaths`)

### 16f — Static Analysis ✅

- [x] `mypy src/ proxy.py` passes with zero errors (mypy.ini baseline; per-module ignores for legacy Redis typing)
- [x] `bandit -r src/ proxy.py -ll` passes with zero high/medium severity findings (B104 suppressed with `# nosec`)
- [x] `pip-audit` passes with no unacknowledged CVEs (replaces safety 3.x which requires login; 4 urllib3 CVEs acknowledged as transitive dep)
- [x] Static analysis gates in `make lint-static` and `scripts/run-local-tests.sh`; all blocking

### 16g — JA4X Extended Fingerprinting

- [ ] `ja4x` field populated in `ConnectionContext` from cert chain (no decryption)
- [ ] `ja4x` emitted in Prometheus labels and structured JSON log
- [ ] JA4X blacklist/whitelist operational (same Redis SET structure as JA4 lists)
- [ ] `ja4x` disabled → `ConnectionContext.ja4x = None`; no crash; no label emitted
- [ ] Unit tests: known cert → correct `ja4x` hash; missing cert → sentinel value

### 16h — Adaptive Rate Limiting ✅

- [x] Adaptive threshold read from `rate:adaptive:{subnet}` when available and `confidence ≥ 0.7`
- [x] Fallback to static config when key missing or confidence below threshold
- [x] `adaptive.enabled = false` → no Redis read; static threshold always used
- [x] Chaos: adaptive key evicted → fallback to static; DEBUG log emitted; no crash

### 16i — Kubernetes / Helm ✅

- [x] `helm lint deploy/helm/ja4proxy/` passes with zero errors
- [x] `helm template` produces valid Kubernetes manifests (validated; kubeval not available in dev env)
- [x] HPA scales on connection metric; min=2, max=20
- [x] PodDisruptionBudget prevents simultaneous eviction of all replicas (`minAvailable: 1`)
- [x] README updated with Helm install instructions

### 16j — OpenTelemetry

- [ ] `telemetry.tracing.enabled = false` (default): zero OTEL imports loaded; no overhead
- [ ] `telemetry.tracing.enabled = true`: spans emitted per pipeline stage with correct attributes
- [ ] OTEL endpoint unreachable: spans dropped silently; proxy performance unaffected
- [ ] Unit test: pipeline with tracing enabled produces correct span tree (mock exporter)

### 16k — Admin CLI ✅

- [x] `ja4proxy-admin --help` lists all commands
- [x] All destructive commands require `--confirm`; fail without it
- [x] All commands read `REDIS_URL` from environment; fail clearly if not set
- [x] `--format json` output is valid JSON for all commands
- [x] Unit tests for each command; use mock Redis; verify correct key operations (39 tests in `tests/unit/test_admin_cli.py`)

### Unit Tests

- [x] `tests/adversarial/test_tls_parser_adversarial.py` — 12 corpus parametrize cases
- [x] `tests/adversarial/test_ja4_adversarial.py` — 10 degenerate input cases
- [ ] `tests/fp_corpus/test_dga_fp_rate.py` — Tranco top 10k; asserts rate < 1%
- [ ] `tests/fp_corpus/test_beaconing_fp_rate.py` — real browser timing; asserts 0% FP
- [ ] `tests/fp_corpus/test_asn_fp_rate.py` — residential IP list; asserts rate < 2%
- [ ] `tests/unit/security/test_ja4x.py` — JA4X hash computation; sentinel on missing cert
- [x] `tests/unit/test_admin_cli.py` — all CLI commands; mock Redis; verify key operations

### Integration Tests

- [ ] `tests/integration/test_fingerprinting.py` — JA4X populated in pipeline; emitted in log
- [ ] `tests/integration/test_adaptive_rate.py` — adaptive threshold applied when available

### Chaos Tests (`tests/chaos/test_external_api_failure.py`)

- [x] AbuseIPDB down → None returned; error logged; pipeline allows
- [x] RDAP down → _process_lookup() returns gracefully; pipeline allows
- [x] All APIs down → pipeline allows all connections; all services fail open

### Performance Tests (`tests/performance/test_bench_pipeline.py`)

- [x] Allow bypass p99 < 500µs over 1000 iterations — p99=2.3µs
- [x] Full scoring path p99 < 1ms over 1000 iterations (no I/O) — p99=20.6µs
- [x] CIDR trie lookup p99 < 10µs for 100k-entry trie — p99=0.96µs
- [x] Baseline in `reports/benchmark_baseline.txt`; tests enforce limits
