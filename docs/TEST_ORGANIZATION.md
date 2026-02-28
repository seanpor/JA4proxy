# JA4proxy — Test Organisation

> This document defines the canonical test file layout, pytest infrastructure,
> fixture factories, and per-module test mapping.
>
> `docs/TESTING_STRATEGY.md` defines **what** to test (categories, scenarios, CI gates).
> This document defines **how to structure** the tests so any developer can find,
> run, or add a test without guessing.

---

## §1. Repository Test Layout

```
tests/
├── conftest.py                    # Root: shared fixtures, pytest configuration
│
├── unit/                          # Fast, isolated, no I/O. Run on every commit.
│   ├── conftest.py                # Unit-specific fixtures (fakeredis, mock config)
│   ├── test_risk_scorer.py
│   ├── test_action_decider.py
│   ├── test_tls_enforcer.py
│   ├── test_sni_analyzer.py
│   ├── test_tcp_analyzer.py
│   ├── test_mtls.py
│   ├── test_asn_classifier.py
│   ├── test_dns_enrichment.py
│   ├── test_blocklists.py
│   ├── test_beaconing_detector.py
│   ├── test_abuseipdb.py
│   ├── test_rdap_enrichment.py
│   ├── test_local_cache.py
│   └── test_config_loader.py
│
├── integration/                   # Real Redis (test instance), no external network.
│   ├── conftest.py                # Integration fixtures (Redis container, full config)
│   ├── test_pipeline.py           # Full pipeline: ClientHello → action
│   ├── test_cache_hierarchy.py    # In-process → Redis → API fallback chain
│   ├── test_dial_propagation.py   # Dial change via pub/sub across instances
│   ├── test_hot_reload.py         # SIGHUP / pub/sub config reload
│   ├── test_bypass_rules.py       # Each bypass condition, enabled and disabled
│   ├── test_rate_limiting.py      # Sliding window accuracy under concurrent load
│   └── test_beaconing_pipeline.py # Beaconing signal accumulates across connections
│
├── chaos/                         # Dependency failures. Run on merge to main.
│   ├── conftest.py                # Chaos fixtures (Redis kill/restart, mock failures)
│   ├── test_redis_failure.py      # Redis unreachable, slow, OOM
│   ├── test_external_api_failure.py # AbuseIPDB, RDAP, Spamhaus all down
│   ├── test_feed_staleness.py     # Spamhaus, Tor list download failures
│   ├── test_analytics_down.py     # Analytics node crash, stream lag
│   └── test_dial_change_chaos.py  # Dial changes under traffic
│
├── adversarial/                   # Malformed inputs. Run on every PR.
│   ├── conftest.py
│   ├── test_tls_parser_adversarial.py  # Malformed ClientHello corpus
│   ├── test_ja4_adversarial.py         # JA4 computation on edge-case inputs
│   └── corpus/                         # Byte sequences that triggered issues
│       ├── README.md                   # What each file is and what it triggered
│       └── *.bin
│
├── fp_corpus/                     # False positive rates. Run on every PR.
│   ├── conftest.py
│   ├── test_dga_fp_rate.py
│   ├── test_beaconing_fp_rate.py
│   ├── test_asn_fp_rate.py
│   └── data/                      # Static fixture data (committed, no network)
│       ├── tranco_top_10k.txt     # Top 10k domains — DGA FP baseline
│       ├── residential_ips.txt    # Known residential IPs — ASN classifier baseline
│       ├── browser_ja4t_pairs.csv # Known-good browser JA4/JA4T pairs
│       └── browser_keepalive_timestamps.csv  # Real browser keep-alive timing
│
├── performance/                   # Benchmarks. Run on every PR.
│   ├── conftest.py
│   ├── bench_pipeline.py
│   ├── bench_cache.py
│   ├── bench_tls_parser.py
│   └── bench_cidr_lookup.py
│
├── e2e/                           # Full stack. Run on merge to main.
│   ├── conftest.py                # Spins up docker-compose.test.yml
│   ├── test_browser_always_passes.py
│   ├── test_known_bad_ja4_blocked.py
│   ├── test_dial_escalation.py
│   ├── test_mtls_bypass.py
│   └── test_redis_failure_e2e.py
│
├── mocks/                         # Mock external services (used across categories)
│   ├── abuseipdb_mock.py
│   ├── spamhaus_mock.py
│   ├── rdap_mock.py
│   └── dns_mock.py
│
└── fixtures/                      # Static binary/text fixtures (committed)
    └── clienthello/
        ├── README.md              # Source and JA4 fingerprint for each file
        ├── chrome_121_windows.bin
        ├── firefox_121_linux.bin
        ├── safari_17_macos.bin
        ├── curl_8_ubuntu.bin
        ├── python_requests_2_31.bin
        ├── sliver_c2.bin
        ├── cobalt_strike.bin
        ├── scanner_masscan.bin
        ├── adversarial_truncated.bin
        └── adversarial_garbage.bin
```

---

## §2. Root `conftest.py`

The root conftest provides fixtures used across all test categories.

```python
# tests/conftest.py
import pytest
import fakeredis.aioredis
from unittest.mock import AsyncMock, MagicMock
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────

FIXTURES_DIR = Path(__file__).parent / "fixtures"
CLIENTHELLO_DIR = FIXTURES_DIR / "clienthello"
FP_DATA_DIR = Path(__file__).parent / "fp_corpus" / "data"


# ── Config ─────────────────────────────────────────────────────────────────

@pytest.fixture
def base_config() -> dict:
    """Minimal valid proxy configuration with safe defaults."""
    return {
        "risk_scorer": {
            "enabled": True,
            "thresholds": {
                "flag": 20, "rate_limit": 35, "tarpit": 55,
                "block": 70, "ban": 85,
            },
            "ban_duration_seconds": 300,
        },
        "monitor_mode": {
            "dial": 0,
            "blocking_acknowledged": False,
            "log_counterfactuals": True,
        },
        "security_policy": {
            "alpn_browser_bypass":    {"enabled": True},
            "ja4_whitelist_bypass":   {"enabled": True},
            "mtls_bypass":            {"enabled": True},
            "static_ip_allowlist":    {"enabled": True},
            "ja4_blacklist_bypass":   {"enabled": True},
            "country_blacklist_bypass": {"enabled": True},
            "spamhaus_bypass":        {"enabled": True},
            "tls_version_bypass":     {"enabled": True},
        },
    }


@pytest.fixture
def config_with_dial_100(base_config) -> dict:
    """Config with dial at 100 — full blocking enabled."""
    cfg = base_config.copy()
    cfg["monitor_mode"]["dial"] = 100
    cfg["monitor_mode"]["blocking_acknowledged"] = True
    return cfg


# ── Redis ──────────────────────────────────────────────────────────────────

@pytest.fixture
async def fake_redis():
    """In-process fake Redis for unit tests. No Docker required."""
    r = fakeredis.aioredis.FakeRedis()
    yield r
    await r.flushall()
    await r.aclose()


# ── ClientHello fixtures ───────────────────────────────────────────────────

@pytest.fixture(params=[
    "chrome_121_windows",
    "firefox_121_linux",
    "safari_17_macos",
])
def browser_clienthello(request) -> bytes:
    """Parametrized: yields each known-good browser ClientHello in turn."""
    return (CLIENTHELLO_DIR / f"{request.param}.bin").read_bytes()


@pytest.fixture(params=[
    "sliver_c2",
    "cobalt_strike",
    "scanner_masscan",
])
def malicious_clienthello(request) -> bytes:
    """Parametrized: yields each known-malicious ClientHello in turn."""
    return (CLIENTHELLO_DIR / f"{request.param}.bin").read_bytes()


@pytest.fixture(params=[
    "adversarial_truncated",
    "adversarial_garbage",
])
def adversarial_clienthello(request) -> bytes:
    """Parametrized: yields each adversarial ClientHello in turn."""
    return (CLIENTHELLO_DIR / f"{request.param}.bin").read_bytes()


# ── Connection objects ─────────────────────────────────────────────────────

def make_connection(
    ip="142.250.80.1",
    ja4="t13d1516h2_8daaf6752bf6_02713d6af862",
    alpn="h2",
    sni="www.example.com",
    tls_version=0x0304,
    country="US",
    has_valid_client_cert=False,
):
    """Factory for mock Connection objects used in pipeline tests."""
    conn = MagicMock()
    conn.ip = ip
    conn.ja4 = ja4
    conn.alpn = alpn
    conn.sni = sni
    conn.tls_version = tls_version
    conn.country = country
    conn.has_valid_client_cert = has_valid_client_cert
    return conn


@pytest.fixture
def browser_connection():
    """A connection that looks like Chrome on h2 — should always be allowed."""
    return make_connection(
        ip="142.250.80.1", ja4="t13d1516h2_8daaf6752bf6_02713d6af862",
        alpn="h2", sni="www.google.com", country="US",
    )


@pytest.fixture
def scanner_connection():
    """A connection with missing SNI and datacenter IP — should score high."""
    return make_connection(
        ip="185.220.101.5", ja4="t13d190900_9dc949161b7c_000000000000",
        alpn="", sni=None, country="RU",
    )
```

---

## §3. Unit Test `conftest.py`

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

## §5. Chaos Test `conftest.py`

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

## §6. Integration Test `conftest.py`

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
cover cross-module scenarios.

| Source module | Unit test file | Integration test | Chaos test |
|--------------|---------------|-----------------|-----------|
| `risk_scorer.py` | `test_risk_scorer.py` | `test_pipeline.py` | — |
| `action_decider.py` | `test_action_decider.py` | `test_dial_propagation.py` | `test_dial_change_chaos.py` |
| `tls_enforcer.py` | `test_tls_enforcer.py` | `test_pipeline.py` | — |
| `sni_analyzer.py` | `test_sni_analyzer.py` | `test_pipeline.py` | — |
| `tcp_analyzer.py` | `test_tcp_analyzer.py` | `test_pipeline.py` | `test_redis_failure.py` |
| `mtls.py` | `test_mtls.py` | `test_bypass_rules.py` | — |
| `asn_classifier.py` | `test_asn_classifier.py` | `test_pipeline.py` | `test_feed_staleness.py` |
| `dns_enrichment.py` | `test_dns_enrichment.py` | `test_pipeline.py` | `test_external_api_failure.py` |
| `blocklists.py` | `test_blocklists.py` | `test_bypass_rules.py` | `test_feed_staleness.py` |
| `beaconing_detector.py` | `test_beaconing_detector.py` | `test_beaconing_pipeline.py` | `test_redis_failure.py` |
| `abuseipdb.py` | `test_abuseipdb.py` | `test_pipeline.py` | `test_external_api_failure.py` |
| `rdap_enrichment.py` | `test_rdap_enrichment.py` | `test_pipeline.py` | `test_external_api_failure.py` |
| `local_cache.py` | `test_local_cache.py` | `test_cache_hierarchy.py` | `test_redis_failure.py` |
| `config_loader.py` | `test_config_loader.py` | `test_hot_reload.py` | — |

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
