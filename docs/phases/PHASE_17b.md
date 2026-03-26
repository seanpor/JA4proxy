# Phase 17b — Security Audit Remediation

## Status: PARTIAL (tracked in manifest as Phase 18)

Some work from this spec is already done (exception handling in pipeline.py, f-string
logging, `ja4proxy_signal_skipped_total`, `ja4proxy_signal_error_total`,
`../../tests/chaos/test_pipeline_remediation.py`). Remaining gaps are listed in `manifest.yaml` Phase 18.

## Purpose and Separation from Phase 17a

`PHASE_17.md` contains two unrelated documents. The first (§1–§Notes) is a bug fix
for the Docker test container hang — that work is complete and self-contained.

This document (`PHASE_17b`) extracts and properly specifies the **security audit
remediation** work that was appended to `PHASE_17.md`. It is a full phase document in
its own right, with TDD requirements, observability, acceptance criteria, and
documentation gates.

Read `docs/security/COMPREHENSIVE_SECURITY_AUDIT.md` before starting this phase.

---

## Goal

Remediate all findings from the comprehensive security audit. The audit identified
five categories of issues:

| Category | Severity | Count |
|----------|----------|-------|
| Overly broad exception handling | Critical | 6 files |
| Insecure logging practices | Medium | 4 files |
| Complex function signatures | Medium | 3 files |
| Tight coupling in pipeline | Medium | 2 files |
| Inconsistent error handling | Medium | 8 files |

This phase addresses all of them in four sequential sub-phases.

---

## 17b-1: Critical Fixes — Exception Handling

**Files:** `../../src/security/pipeline.py`, `../../src/security/security_manager.py`, `../../src/security/blocklists.py`, `../../src/security/dns_enrichment.py`,
`../../src/security/asn_classifier.py`, `../../src/security/rdap_enrichment.py`

### Problem

These files use `except Exception: pass` or `except Exception as e: logger.error(e)`.
These patterns:
1. Swallow unexpected exceptions silently
2. Prevent Prometheus error counters from incrementing
3. Make debugging nearly impossible in production

### Specification

Every bare `except Exception` must be replaced with one of:

**Pattern A: Known external service failure (fail-open)**
```python
except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
    # Increment specific error counter
    ja4proxy_abuseipdb_lookups_total.labels(result="error").inc()
    # Log with context at appropriate level
    logger.warning(
        "security | event=abuseipdb_request_failed | ip=%s | error=%s",
        ip, exc
    )
    # Return neutral result (fail open)
    return None
```

**Pattern B: Unexpected internal error (re-raise with context)**
```python
except Exception:
    logger.exception(
        "security | event=unexpected_error | subsystem=pipeline | "
        "client_ip=%s | phase=%s",
        ctx.client_ip, current_phase
    )
    raise   # Do not swallow unexpected internal errors
```

**Pattern C: Redis failure (fail-open, increment counter)**
```python
except redis.exceptions.RedisError as exc:
    ja4proxy_redis_errors_total.labels(operation=op_name).inc()
    logger.warning(
        "security | event=redis_error | op=%s | error=%s", op_name, exc
    )
    return default_value   # Fail open
```

### Rules

- External service failures: Pattern A (fail open, increment counter, log at WARNING)
- Redis failures: Pattern C (fail open, increment redis error counter, log at WARNING)
- Internal logic errors (should never happen): Pattern B (re-raise, log at ERROR)
- Never use bare `except:` or `except Exception: pass`

### Files to Change and What to Fix

| File | Current anti-pattern | Required fix |
|------|---------------------|-------------|
| `src/security/pipeline.py` | `except Exception as e: logger.error(str(e))` at lines ~180–210 | Replace with Pattern B; add phase context |
| `src/security/security_manager.py` | `except Exception: return default` in `_load_*` methods | Replace with Pattern A/C; identify specific exception types |
| `src/security/blocklists.py` | `except Exception: pass` in feed download | Replace with Pattern A; add `ja4proxy_blocklist_download_errors_total` counter |
| `src/security/dns_enrichment.py` | `except Exception: return None` in PTR lookup | Replace with Pattern A; specify `socket.herror`, `socket.timeout` |
| `src/security/asn_classifier.py` | `except Exception` in IP classification | Replace with Pattern A/C; document which exceptions are expected |
| `src/security/rdap_enrichment.py` | `except Exception: return {}` in RDAP fetch | Replace with Pattern A; add `ja4proxy_rdap_lookup_errors_total` counter |

---

## 17b-2: Code Quality — Logging and Complexity

### 2a. Logging Improvements

**Problem:** f-string log messages evaluate the string even when log level is disabled.
At DEBUG level in production, this wastes CPU.

```python
# Before (evaluated unconditionally)
logger.debug(f"Processing {ctx.client_ip} with {len(signals)} signals: {signals}")

# After (evaluated only if DEBUG is active)
logger.debug(
    "security | event=signals_collected | client_ip=%s | count=%d | signals=%s",
    ctx.client_ip, len(signals), signals
)
```

**Rule:** All logger calls must use `%s` format strings, not f-strings. This applies
to all files in `src/security/`, `analytics/`, and `management/`.

**Automated gate:** Add to static analysis CI:
```bash
grep -rn 'logger\.(debug|info|warning|error|critical)(f"' src/ management/ analytics/ \
    && echo "FAIL: f-string in logger call" && exit 1
```

### 2b. Function Signature Complexity

**Problem:** Functions with > 7 parameters are hard to test and likely to have calling
convention errors.

Files affected:
- `src/security/pipeline.py`: `_collect_signals()` has 9 parameters
- `src/security/risk_scorer.py`: `score()` has 8 parameters
- `src/security/beaconing_detector.py`: `maybe_record()` has 7 parameters

**Fix:** Replace positional parameter lists with a single context/config object:

```python
# Before
async def _collect_signals(
    self, client_ip, ja4, sni, alpn, tls_version, ciphers, extensions, country, asn
):

# After — ConnectionContext already has all these fields
async def _collect_signals(self, ctx: ConnectionContext) -> list[RiskSignal]:
```

`ConnectionContext` already exists and carries all these fields. The fix is to pass
`ctx` instead of unpacked fields.

---

## 17b-3: Architectural — Pipeline Coupling

### Problem

`../../src/security/pipeline.py` imports concrete implementations of every signal collector directly
(`from src.security.asn_classifier import ASNClassifier`). This makes it impossible
to test the pipeline in isolation without mocking all 14 signal collectors.

### Fix

Introduce a `SignalCollector` protocol (Python typing.Protocol) and inject collectors
at construction time:

```python
# src/security/protocols.py
from typing import Protocol, runtime_checkable

@runtime_checkable
class SignalCollector(Protocol):
    async def get_signal(self, ctx: ConnectionContext) -> RiskSignal | None: ...
    async def initialize(self) -> None: ...
    async def shutdown(self) -> None: ...
```

```python
# pipeline.py — constructor becomes
class Pipeline:
    def __init__(
        self,
        collectors: list[SignalCollector],
        risk_scorer: RiskScorer,
        action_decider: ActionDecider,
        config: dict,
    ):
        self._collectors = collectors
        ...
```

Tests inject mock collectors:
```python
def _make_pipeline(**kwargs):
    collectors = [
        MockCollector(signal=RiskSignal(name="test", score=50)),
    ]
    return Pipeline(collectors=collectors, ...)
```

This does not change external behaviour — only the internal wiring. The production
entrypoint still constructs all 14 collectors and injects them.

---

## 17b-4: Ongoing — Static Analysis Baseline

This sub-phase establishes the automated quality gates that enforce the fixes from
17b-1 through 17b-3 in all future code.

### Gates Added to CI

```bash
# 1. No f-string logger calls
scripts/check_logger_format.sh

# 2. Bandit security scan — zero high/medium severity
bandit -r src/ proxy.py management/ analytics/ -ll --confidence-level medium

# 3. Pylint score ≥ 8.5/10
pylint src/ management/ analytics/ --fail-under=8.5

# 4. mypy with strict optional (tighten from Phase 16f baseline)
mypy src/ proxy.py --strict-optional --warn-return-any

# 5. No bare except clauses
python3 scripts/check_bare_except.py src/ management/ analytics/
```

### `scripts/check_bare_except.py`

```python
#!/usr/bin/env python3
"""Fail if any file contains bare except: or except Exception: pass."""
import ast
import sys
from pathlib import Path

def check_file(path: Path) -> list[tuple[int, str]]:
    violations = []
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                violations.append((node.lineno, "bare except:"))
            elif (
                isinstance(node.type, ast.Name)
                and node.type.id == "Exception"
                and len(node.body) == 1
                and isinstance(node.body[0], ast.Pass)
            ):
                violations.append((node.lineno, "except Exception: pass"))
    return violations

errors = []
for path in Path(sys.argv[1]).rglob("*.py"):
    for lineno, msg in check_file(path):
        errors.append(f"{path}:{lineno}: {msg}")

if errors:
    print("\n".join(errors))
    sys.exit(1)
```

---

## Observability for This Phase

Phase 17b introduces new Prometheus metrics to make error patterns visible. These must
be added to `docs/OBSERVABILITY_STANDARDS.md`.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ja4proxy_blocklist_download_errors_total` | Counter | `feed_name` | Blocklist feed download failures |
| `ja4proxy_dns_ptr_errors_total` | Counter | `error_type=timeout\|nxdomain\|servfail` | DNS PTR lookup failures |
| `ja4proxy_rdap_lookup_errors_total` | Counter | `rir` | RDAP lookup failures by RIR |
| `ja4proxy_pipeline_unexpected_errors_total` | Counter | `phase` | Pipeline internal errors (should be 0) |
| `ja4proxy_exception_handled_total` | Counter | `module,exception_type` | All caught exceptions by module and type |

`ja4proxy_exception_handled_total` acts as an exception census — any unexpected spike
in a new `exception_type` label value reveals a new failure mode.

### New Grafana Panels

Add to the proxy dashboard:

```
Title: Exception Rate by Module (last 5m)
Type: Bar gauge
Query: rate(ja4proxy_exception_handled_total[5m]) by (module)
Thresholds: 0 = green, > 0.1/s = yellow, > 1/s = red
Description: "Exceptions caught per module. Steady baseline is normal;
             sudden spike indicates new failure mode."
```

```
Title: Pipeline Internal Errors (Must Be Zero)
Type: Stat
Query: rate(ja4proxy_pipeline_unexpected_errors_total[5m])
Thresholds: 0 = green, > 0 = red (critical)
Description: "Unexpected errors in pipeline logic. Non-zero requires immediate investigation."
```

### AlertManager Rules

```yaml
- alert: PipelineInternalError
  expr: rate(ja4proxy_pipeline_unexpected_errors_total[1m]) > 0
  for: 0m   # Immediate — no wait
  labels:
    severity: critical
  annotations:
    summary: "Pipeline internal error ({{ $labels.phase }})"
    description: "An unexpected exception was re-raised in the pipeline. Check logs immediately."

- alert: ExceptionRateSpike
  expr: |
    rate(ja4proxy_exception_handled_total[5m]) > 2 *
    avg_over_time(rate(ja4proxy_exception_handled_total[5m])[1h:5m])
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Exception rate 2× above 1h baseline in {{ $labels.module }}"
    description: "Spike may indicate new failure mode. Current: {{ $value | humanize }}/s"
```

---

## Structured Log Schema for Phase 17b Events

### Unexpected Internal Error (Pattern B)

```json
{
  "type": "system",
  "level": "ERROR",
  "subsystem": "pipeline",
  "event": "unexpected_error",
  "client_ip": "1.2.3.4",
  "phase": "signal_collection",
  "collector": "asn_classifier",
  "exc_type": "AttributeError",
  "exc_message": "'NoneType' object has no attribute 'category'",
  "stack_trace": "...",
  "timestamp": "2026-03-10T14:23:00Z"
}
```

### External Service Failure (Pattern A)

```json
{
  "type": "connection",
  "level": "WARN",
  "subsystem": "abuseipdb",
  "event": "request_failed",
  "client_ip": "1.2.3.4",
  "exc_type": "aiohttp.ClientConnectorError",
  "exc_message": "Cannot connect to host abuseipdb.com:443",
  "effect": "fail_open",
  "timestamp": "2026-03-10T14:23:00Z"
}
```

---

## Testing Requirements

### TDD Process for This Phase

This phase is primarily refactoring. The TDD process is inverted: existing tests must
continue passing after each change. Write any new tests before the refactoring they test.

### New Unit Tests (`tests/unit/test_exception_handling.py`)

Minimum 20 tests. One per specific exception type that should be caught:

```python
class TestExceptionHandling:
    """Verify that each module catches specific exception types and fails open."""

    async def test_pipeline_abuseipdb_client_error_fail_open(self): ...
    async def test_pipeline_rdap_timeout_fail_open(self): ...
    async def test_pipeline_dns_herror_fail_open(self): ...
    async def test_pipeline_redis_error_fail_open_returns_zero_score(self): ...
    async def test_pipeline_unexpected_exception_reraises(self): ...
    async def test_blocklist_download_client_error_increments_counter(self): ...
    async def test_blocklist_download_304_no_counter_increment(self): ...
    async def test_asn_classifier_mmdb_read_error_fail_open(self): ...
    async def test_dns_enrichment_timeout_fail_open(self): ...
    async def test_dns_enrichment_nxdomain_fail_open(self): ...
    async def test_rdap_enrichment_iana_bootstrap_fails_gracefully(self): ...
    async def test_rdap_enrichment_rate_limit_fail_open(self): ...
    # ... 8 more covering remaining modules
```

### New Unit Tests (`tests/unit/test_pipeline_isolation.py`)

After introducing `SignalCollector` protocol:

```python
class TestPipelineIsolation:
    """Pipeline can be unit-tested with mock collectors; no concrete imports needed."""

    def test_pipeline_accepts_mock_collectors(self): ...
    def test_pipeline_calls_all_collectors(self): ...
    def test_pipeline_handles_collector_returning_none(self): ...
    def test_pipeline_handles_collector_raising_exception(self): ...
    def test_risk_scorer_receives_all_signals(self): ...
```

### Integration Tests — Regression Guard

After every sub-phase (17b-1, 17b-2, 17b-3, 17b-4), run the full test suite:

```bash
python3 -m pytest tests/ --ignore=tests/integration/test_docker_stack.py -x
```

No regression is acceptable. All 1293 (or current count) tests must pass.

### Chaos Tests (`tests/chaos/test_exception_handling_chaos.py`)

Minimum 6 tests:

```python
async def test_all_external_apis_fail_simultaneously_pipeline_allows(): ...
async def test_redis_down_all_modules_fail_open(): ...
async def test_abuseipdb_malformed_json_fail_open(): ...
async def test_dns_timeout_fail_open_no_signal(): ...
async def test_rdap_500_error_fail_open(): ...
async def test_blocklist_download_corrupted_response_old_list_retained(): ...
```

### Performance Tests

- [ ] `test_bench_pipeline_with_exception_handling.py` — exception-handling paths add
      < 5µs per connection vs baseline (no exception handling path)

---

## Documentation Requirements

### Runbook: Security Incident Response

**File:** `docs/runbooks/security_incident_response.md`

```markdown
# Security Incident Response Runbook

## Detecting Anomalies

### Monitor These Metrics

| Metric | Normal | Investigate |
|--------|--------|-------------|
| `ja4proxy_pipeline_unexpected_errors_total` | 0 | Any non-zero value |
| `ja4proxy_exception_handled_total{module="pipeline"}` | < 1/s | > 5/s sustained |
| `ja4proxy_redis_errors_total` | < 0.1/s | > 1/s sustained |

### Pipeline Internal Error (Critical)

If `PipelineInternalError` alert fires:

1. Check logs immediately:
   ```bash
   grep '"event":"unexpected_error"' /var/log/ja4proxy/proxy.log | tail -20 | jq .
   ```

2. Identify the `phase` and `collector` fields — they tell you exactly where the error occurred.

3. If the error is repeating: set dial to 0 (monitor mode) to stop blocking while you investigate.
   The proxy continues operating in fail-open mode.

4. Collect the stack trace from the log entry and file a bug with it.

### Exception Rate Spike

If `ExceptionRateSpike` alert fires:

1. Check which module is spiking:
   ```
   Grafana → Exception Rate by Module panel
   ```

2. Identify the exception type:
   ```bash
   grep '"exc_type"' /var/log/ja4proxy/proxy.log | \
       jq -r '.exc_type' | sort | uniq -c | sort -rn | head -10
   ```

3. Common causes:
   - DNS resolution failures (check upstream DNS servers)
   - Redis connectivity issues (check Redis health)
   - External API rate limiting (check AbuseIPDB quota metric)
   - MaxMind GeoIP database file corrupted/deleted
```

### Code Comments

All functions changed in 17b-1 through 17b-3 must have updated docstrings explaining:
- Which exception types are caught and why
- The fail-open or fail-secure behaviour
- What the caller receives on failure

```python
async def get_signal(self, ctx: ConnectionContext) -> RiskSignal | None:
    """Return AbuseIPDB risk signal for the given IP, or None on any failure.

    Failure modes (all return None, fail open):
    - aiohttp.ClientError: network connectivity to AbuseIPDB
    - asyncio.TimeoutError: AbuseIPDB did not respond within timeout
    - json.JSONDecodeError: AbuseIPDB returned malformed JSON
    - redis.exceptions.RedisError: cache read/write failure

    Internal errors (unexpected) are re-raised.
    """
```

---

## Acceptance Criteria

### 17b-1: Exception Handling

- [ ] Zero `except Exception: pass` in `src/`, `management/`, `analytics/`
      (enforced by `scripts/check_bare_except.py`)
- [ ] Zero `except Exception` without a specific type comment explaining why
- [ ] Every caught exception increments a Prometheus counter or logs at WARNING+
- [ ] All 6 files listed in §17b-1 have been updated to Pattern A/B/C
- [ ] `ja4proxy_pipeline_unexpected_errors_total` metric exists and is 0 in all tests

### 17b-2: Code Quality

- [ ] Zero f-string logger calls (enforced by `scripts/check_logger_format.sh` in CI)
- [ ] All functions in the three named files have ≤ 7 parameters (or use context object)
- [ ] `pipeline._collect_signals()` accepts `ConnectionContext` as sole data parameter

### 17b-3: Pipeline Coupling

- [ ] `SignalCollector` protocol exists in `src/security/protocols.py`
- [ ] `Pipeline.__init__` accepts `list[SignalCollector]` (injection)
- [ ] All existing tests pass after injection refactor
- [ ] New `TestPipelineIsolation` class: 5 tests pass

### 17b-4: Static Analysis

- [ ] `bandit -r src/ proxy.py management/ analytics/ -ll` passes with zero high/medium findings
- [ ] `pylint src/ management/ analytics/ --fail-under=8.5` passes
- [ ] `scripts/check_bare_except.py` passes
- [ ] `scripts/check_logger_format.sh` passes
- [ ] All 4 gates run in CI before pytest; failures block merge

### Tests

- [ ] Minimum 20 unit tests in `../../tests/unit/test_exception_handling.py` (one per exception type)
- [ ] Minimum 5 unit tests in `../../tests/unit/test_pipeline_isolation.py`
- [ ] Minimum 6 chaos tests in `../../tests/chaos/test_exception_handling_chaos.py`
- [ ] All 1293+ existing tests still pass after each sub-phase

### Observability

- [ ] 5 new Prometheus metrics added to `docs/OBSERVABILITY_STANDARDS.md`
- [ ] 2 new Grafana panels (Exception Rate by Module, Pipeline Internal Errors)
- [ ] 2 new AlertManager rules pass `promtool check rules`

### Documentation

- [ ] `docs/runbooks/security_incident_response.md` exists
- [ ] All changed functions have updated docstrings documenting exception behaviour
- [ ] `CHANGELOG.md` updated with Phase 17b entry
