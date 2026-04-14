<!--
title: Test_Organization
audience: Developers
last_reviewed: 2026-03-27
phase: 21
-->

# JA4proxy — Test Organisation

> This document defines the canonical test file layout, pytest infrastructure,
> fixture factories, and per-module test mapping.
>
> `docs/TESTING_STRATEGY.md` defines **what** to test (categories, scenarios, CI gates).
> This document defines **how to structure** the tests so any developer can find,
> run, or add a test without guessing.

---

## Current Implementation Status

The test suite targets a **1.3× test-to-code ratio** (lines of test code ÷ lines of production code). Run `make test-ratio` to check the current ratio.

The current test count can be verified with:
```bash
python3 -m pytest tests/ --collect-only -q 2>/dev/null | tail -1
```

Phases completed through 21. The sections below are a mix of **implemented** (what exists today) and **planned** (design for future phases). Each section is labelled.

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


---

## §1. Repository Test Layout

### Implemented

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

> **Note:** `tests/integration/test_docker_stack.py` is excluded from `make test`
> because it makes real HTTP calls to running containers. Run it manually with a live
> stack: `docker compose -f deploy/docker/docker-compose.poc.yml up -d && pytest tests/integration/test_docker_stack.py`.

> **Note:** `tests/performance/bench_*.py` files are not named `test_*.py` so pytest
> does not collect them automatically. Run manually: `python3 tests/performance/bench_pipeline.py`.

### Planned (not yet implemented)

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

---

## §2. Root `../tests/conftest.py` — As Implemented

The root `tests/conftest.py` provides three categories of infrastructure:

### 2a. Async helper

All non-async test functions that need to drive async code use `asyncio.run()`:

```python
def _run(coro):
    """Run a coroutine from a sync test. asyncio.run() cancels pending tasks
    on exit, preventing orphaned background tasks from hanging the container."""
    return asyncio.run(coro)
```

**Why `asyncio.run()` and not `asyncio.new_event_loop().run_until_complete()`:**
The old pattern left background tasks (e.g. `_tor_refresh_loop` sleeping 3600s)
orphaned in unclosed event loops. In Python 3.11, GC cleanup of these loops hangs
~264s per loop, causing the Docker 300s timeout to fire even after pytest finishes.
`asyncio.run()` cancels all pending tasks before closing, keeping container
shutdown under 1s.

### 2b. Session-scoped network isolation

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

### 2c. Redis fixtures

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
---

## §3. Unit Test `../tests/conftest.py`

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

---

## §4. Per-Module Test File Structure

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

---

## §5. Chaos Test `../tests/conftest.py`

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

---

## §6. Integration Test `../tests/conftest.py`

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

---

## §7. Standard Parametrize Patterns

Use `@pytest.mark.parametrize` consistently. These patterns appear throughout the codebase:

### Threshold boundary testing (all modules with configurable scores)

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

### IPv4/IPv6 parity (all modules touching IPs)

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

### Bypass conditions (all enabled/disabled states)

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

### Signal enable/disable (all configurable signal modules)

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

---

## §8. Mock Usage Patterns

### Mocking external services in unit tests

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

### Using `tests/mocks/` servers in integration tests

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

---

## §9. Async Test Configuration

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

---

## §10. Module-to-Test-File Mapping

Every source module has a corresponding unit test file. Additional test files
cover cross-module scenarios. ✓ = implemented, — = planned/not yet needed.

| Source module | Unit test file | Integration test | Chaos test | Coverage |
|--------------|---------------|-----------------|-----------|----------|
| `../src/security/risk_scorer.py` | `../tests/unit/test_risk_scorer.py` ✓ | `test_pipeline.py` ✓ | — | 96% |
| `../src/security/action_decider.py` | `../tests/unit/test_action_decider.py` ✓ | `../tests/integration/test_dial_propagation.py` ✓ | `../tests/chaos/test_dial_change_chaos.py` ✓ | ~95% |
| `../src/security/tls_enforcer.py` | `../tests/unit/test_tls_enforcer.py` ✓ | `test_pipeline.py` ✓ | `../tests/chaos/test_redis_failure.py` ✓ | ~95% |
| `../src/security/sni_analyzer.py` | `../tests/unit/security/test_sni_analyzer.py` ✓ | `../tests/integration/test_sni_pipeline.py` ✓ | `../tests/chaos/test_sni_chaos.py` ✓ | 92% |
| `../src/security/tcp_analyzer.py` | `../tests/unit/security/test_tcp_analyzer.py` ✓ | `../tests/integration/test_tcp_pipeline.py` ✓ | `../tests/chaos/test_tcp_chaos.py` ✓ | 82% |
| `../src/security/mtls.py` | `../tests/unit/security/test_mtls.py` ✓ | `../tests/integration/test_bypass_rules.py` ✓ | — | 80% |
| `../src/security/asn_classifier.py` | `../tests/unit/security/test_asn_classifier.py` ✓ | `../tests/integration/test_asn_pipeline.py` ✓ | `../tests/chaos/test_asn_chaos.py` ✓ | 70% |
| `../src/security/dns_enrichment.py` | `../tests/unit/security/test_dns_enrichment.py` ✓ | `test_pipeline.py` ✓ | `../tests/chaos/test_dns_chaos.py` ✓ | 70% |
| `../src/security/blocklists.py` | `../tests/unit/test_blocklists.py` ✓ | `../tests/integration/test_bypass_rules.py` ✓ | `../tests/chaos/test_feed_staleness.py` ✓ | 69% |
| `../src/security/beaconing_detector.py` | `../tests/unit/security/test_beaconing_detector.py` ✓ | `../tests/integration/test_beaconing_pipeline.py` ✓ | `../tests/chaos/test_redis_failure.py` ✓ | 94% |
| `../src/security/abuseipdb.py` | `../tests/unit/test_abuseipdb.py` ✓ | `test_abuseipdb_integration.py` ✓ | `test_abuseipdb_chaos.py` ✓ | 92% |
| `../src/security/rdap_enrichment.py` | `../tests/unit/test_rdap_enrichment.py` ✓ | `test_rdap_pipeline.py` ✓ | `test_rdap_chaos.py` ✓ | 88% |
| `../src/analytics/main.py` | `test_analytics_node.py` ✓ | `test_analytics_pipeline.py` ✓ | `test_analytics_chaos.py` ✓ | 90% |
| `../src/cache/local_cache.py` | `../tests/unit/test_local_cache.py` ✓ | `../tests/integration/test_cache_hierarchy.py` ✓ | `../tests/chaos/test_redis_failure.py` ✓ | ~95% |
| `config_loader.py` | `../tests/unit/test_config_loader.py` ✓ | `../tests/integration/test_hot_reload.py` ✓ | — | 98% |

### Coverage gaps (as of Phase 9)

| Module | Coverage | Uncovered area |
|--------|----------|---------------|
| `../src/security/asn_classifier.py` | 70% | MaxMind actual IP lookup (requires real .mmdb + real IPs), Tor list leader election when Redis is available |
| `../src/security/blocklists.py` | 69% | Live feed download HTTP paths, FeedManager ETag logic, leader election success path |
| `../src/security/dns_enrichment.py` | 70% | Real async PTR lookup (requires live DNS), worker restart loop, passive DNS log |
| `../src/security/tcp_analyzer.py` | 82% | Some edge cases in connection timing analysis |
| `proxy.py` | 92% | Error paths in `_forward_to_backend`, `handle_connection` edge cases |

The 69–70% modules are intentionally low: the uncovered lines require real external
services (MaxMind DB, live DNS, live HTTP servers) that we don't spin up in unit or
chaos tests. The important failure modes are covered via mock-based chaos tests.

---

## §11. `Makefile` Targets

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
