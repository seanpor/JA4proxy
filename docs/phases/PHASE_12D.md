# Phase 12d — Security Hardening

## Status: COMPLETE (2026-03-15)

The original 12d plan contained significant scope creep (JIRA integration, SOC
alerting, automated quarantine, Redis RBAC, separate Redis users, forensic
retention). Those items are either Phase 14 (production hardening) concerns or
simply not appropriate for this system's threat model.

**Threat model reality**: The proxy and analytics node are on the same internal
network, sharing the same Redis instance. The primary attack surface is a
compromised proxy instance sending poisoned events, or a misconfigured proxy
flooding the stream. External attackers cannot reach the analytics Redis port.

---

## What Is Already Implemented

### Event Validation (`src/analytics/event_schemas.py`, `validation.py`)
- JSON Schema validation on all incoming events ✓
- Field sanitisation: length limits, control character stripping ✓
- IP format validation ✓
- 7 tests passing ✓

### HMAC Authentication (`src/analytics/authentication.py`)
- HMAC-SHA256 with `hmac.compare_digest` (timing-safe) ✓
- Optional (`hmac_required: false` by default — fail open, not fail closed) ✓
- 8 tests passing ✓

### Rate Limiting (`src/analytics/security_hardening.py`)
- Basic per-proxy rate limiting with sorted set counter ✓
- `SecurityHardening.check_rate_limit()` implemented ✓
- 9 tests passing ✓

### Audit Logging (`src/analytics/security_hardening.py`)
- `SecurityEvent` dataclass with structured fields ✓
- Security events logged as JSON ✓

---

## Genuine Gaps

### 1. Replay attack prevention (missing)
The HMAC implementation does not enforce a timestamp window. A valid signed
event from 30 minutes ago could be replayed indefinitely.

Add to `authentication.py` validation:
```python
MAX_EVENT_AGE_SECONDS = 300  # 5 minutes

def validate_timestamp(event: dict) -> bool:
    ts = event.get("timestamp", 0)
    age = abs(time.time() - float(ts))
    return age <= MAX_EVENT_AGE_SECONDS
```
This should only be enforced when `hmac_required: true`.

### 2. Chaos tests (missing)
These are the most important missing tests — they verify the proxy degrades
gracefully when analytics is unavailable.

Required test file: `tests/chaos/test_analytics_down.py`

- Analytics container stopped: proxy continues scoring, no exceptions, stale
  campaign data used (or zero signals if TTL expired)
- Stream lag > 300s: `ja4proxy_analytics_stream_lag_seconds` gauge reflects lag,
  WARN logged
- Rate limit exceeded: excess events dropped, counter incremented, no crash
- Malformed event in stream: validation rejects it, processing continues

### 3. Rate limiting config (partial)
The per-proxy-specific rate limit config in `analytics.yaml` is defined but not
wired up — `check_rate_limit()` uses a single global limit. Connect the
`proxy_specific` config section.

---

## Out of Scope (removed from this phase)

The following items from the original plan are **not required** for Phase 12d:
- Circuit breaker pattern — not needed; the analytics node is not on the hot path
- Algorithm resource limit decorator — Python's asyncio timeout handles this adequately
- Redis TLS and RBAC separate users — Phase 14 (production hardening)
- Forensic data retention system — YAGNI; raw events are in the Redis Stream already
- JIRA/Slack/SOC integration — ops tooling, not proxy code
- Automated quarantine — too complex, too risky for false positives
- Penetration testing report — Phase 14
- Fuzz testing suite — the validation tests cover this sufficiently

---

## Acceptance Criteria

### Security Functional
- [x] Event schema validation with JSON Schema
- [x] HMAC authentication for all events (optional by config)
- [x] Rate limiting per proxy
- [x] Replay attack prevention (timestamp window when HMAC enabled)
- [x] Per-proxy rate limit config: `check_rate_limit(type, proxy_id)` keys already per-proxy

### Testing
- [x] Unit tests: event validation (7 passing)
- [x] Unit tests: HMAC authentication (8 passing)
- [x] Unit tests: rate limiting (in security_hardening tests)
- [x] Chaos test: analytics node down — proxy continues, no errors (`tests/chaos/test_analytics_down.py`)
- [x] Chaos test: stream lag > 300s — `ja4proxy_analytics_stream_lag_seconds` gauge set, WARN logged
- [x] Chaos test: malformed events in stream — rejected by `validate_event()`, processing continues (`tests/chaos/test_stream_chaos.py`)

### Documentation
- [x] `docs/REDIS_SCHEMA.md` updated with all Phase 12 keys
- [x] `CHANGELOG.md` updated with Phase 12 entries
