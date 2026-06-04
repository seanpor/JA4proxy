---
phase: 209
title: "Proxy Runtime Errors — Fail-Open Audit & Remediation"
status: PROPOSED
size: LARGE
created: 2026-05-30
audience: [developer, operator]
dependencies: []
---

# Proxy Runtime Errors — Fail-Open Audit & Remediation

## Problem

The proxy has several classes of runtime errors where failures are silently swallowed or cause the proxy to operate in a degraded state without the operator's knowledge. The most critical are:

1. **Fail-open on Redis errors** — when Redis is unreachable, country blocking, rate limiting, and dial computation silently disengage, forwarding all traffic.
2. **TLS parse failure silently forwarded** — unparsable ClientHellos (malformed, fragmented, novel TLS stacks) are forwarded with no fingerprint instead of being inspected or blocked.
3. **`docker-compose.prod.yml` builds the wrong proxy** — deploys the legacy Python proxy instead of the production Go binary.
4. **40 `except Exception: pass` clauses in proxy.py** — broad exception swallowing masks crashes, resource leaks, and degraded states.
5. **15 pre-existing test failures** — documented and accepted in the last CHANGELOG with no remediation plan.

---

## Findings

### F-1: `docker-compose.prod.yml` builds legacy Python proxy (CRITICAL)

`deploy/docker/docker-compose.prod.yml:58` references `deploy/docker/Dockerfile` — the **Python experimental prototype** (`proxy.py`, banner says "DO NOT DEPLOY THIS FILE IN PRODUCTION"). The Go production proxy lives at `deploy/docker/Dockerfile.go-proxy` and is the Phase 15+ promoted binary.

**Impact:** Any deployment using the production compose file runs the wrong binary. The Python proxy is single-threaded, has no seccomp profile, and is explicitly labelled experimental.

**Fix:** Change `dockerfile:` to `deploy/docker/Dockerfile.go-proxy`.

### F-2: TLS parse failure silently forwarded (HIGH)

`proxy.py` lines 2454–2470: when the TLS parser cannot parse a ClientHello (returns `"unknown"` or `"error"`), the proxy prints a log line and **forwards the connection** to the backend with no JA4 fingerprint.

```python
if ja4 in ("unknown", "error"):
    self.logger.info("UNKNOWN_JA4: ... Forwarding (TLS parse failed — fail open)")
    await self._forward_to_backend(data, reader, writer, fingerprint)
    return
```

**Impact:** An attacker with a novel TLS stack, a fragmented ClientHello, or a deliberately malformed TLS record bypasses all JA4-based fingerprinting. The backend receives the connection blind. This is the original root cause of JA4PROXY-2026-0003 (TLS fragmentation bypass) — the fix added logging but did not close the fail-open.

**Fix:** Add a configurable `on_unknown_ja4` policy: `"block"`, `"forward"`, or `"tarpit"`. Default to `"block"` in production, `"forward"` in development.

### F-3: Redis fail-open on country blocking (HIGH)

`proxy.py` line 2429–2430:

```python
except Exception:
    pass  # fail open on Redis error
```

When Redis is unreachable, the country-based dynamic blocking check silently passes. All countries are allowed through.

**Impact:** If Redis goes down (OOM, network partition, config change), country blocks silently disengage. An operator monitoring connection counts might notice a gradual increase but there is no alert.

**Fix:** Add a circuit breaker: after N consecutive Redis failures, raise an alert and optionally fail-closed (block country checks until Redis recovers). Log a WARNING on every failure, not just the first.

### F-4: Redis fail-open on rate limiting / dial read (HIGH)

`proxy.py` line 1076:

```python
except Exception:
    pass  # falls through to dial = 0
```

When reading the rate limit counter from Redis fails, `dial` defaults to `0` (monitor mode) — the proxy allows all traffic.

**Impact:** A Redis connection issue silently disengages rate limiting.

**Fix:** Return `dial = max_dial` (most restrictive) instead of `dial = 0` (least restrictive) on Redis error. Or introduce a fail-closed toggle.

### F-5: Broad `except Exception: pass` throughout proxy.py (HIGH)

**40 instances** of `except Exception` in `proxy.py`. Key locations:

| Lines | Context | Risk |
|-------|---------|------|
| 232 | TLS parser returns `None` on any exception | Connection forwarded with no fingerprint (F-2) |
| 1076 | Redis dial counter read | Rate limiting disengaged (F-4) |
| 1150 | Subnet parsing | Adaptive rate limiting disabled |
| 2429 | Country block check | Country blocks disengaged (F-3) |
| 2578 | Writer cleanup on close | Resource leak |
| 2691 | HTTP header `_extract_client_ip_from_http` | IP extraction silently fails |
| 2745, 2772, 2779 | Tarpit operations | Tarpit errors swallowed |
| 2983 | Backend writer cleanup | Resource leak |
| 3104 | Log data filtering | Potential PII leak in logs |
| 3238 | Top-level fatal error | This one correctly re-raises (`sys.exit(1)`) |

**Impact:** The proxy silently enters degraded states. The operator has no visibility until traffic patterns change noticeably.

**Fix:** Each `except Exception:` should be:
- Changed to catch a specific exception type where possible
- Logged at WARNING level with connection context
- Have a documented fail-open vs fail-closed behavior
- Instrumented with a counter metric (`ja4proxy_internal_errors_total`)

### F-6: 15 pre-existing test failures (MEDIUM)

The Phase 206 CHANGELOG documents "15 pre-existing test failures (no new failures introduced)". These are accepted without a remediation plan.

**Impact:** Undiagnosed test failures may indicate real regressions. New contributors see a red test suite and cannot distinguish pre-existing from newly-introduced failures.

**Fix:** Triage each failure:
- 0 genuine regressions → fix or document as expected
- Stale mocks / fixture drift → repair
- Environment-specific (e.g., missing network) → skip with `pytest.mark.skipif` and a reason

### F-7: Go proxy health check goroutine silently dies on panic (MEDIUM)

`cmd/proxy/main.go` lines 94–106: a background goroutine runs `HealthCheck()` every 30 seconds in a `for/select` loop. If `HealthCheck()` panics (nil pointer, unexpected state), the goroutine dies silently — the proxy continues running but health reporting goes dark.

**Impact:** Operator loses health visibility. Load balancer health checks will eventually fail and remove the instance from rotation, but there is zero trace of why.

**Fix:** Add a `recover()` in the health check loop with logging and a metric increment.

### F-8: Go proxy config reload failure silently ignored (LOW)

`cmd/proxy/main.go` line 84: SIGHUP-triggered config reload failure is caught and logged at Warn level. The proxy continues with the stale config.

**Impact:** An operator who edits `proxy.yml` and sends SIGHUP gets no signal that the reload failed (syntax error, missing field). They believe the new config is active.

**Fix:** Log at ERROR level and expose a metric (`ja4proxy_config_reload_failures_total`).

---

## Implementation Plan

### A — Fix production compose file (F-1, Critical)

**Files:** `deploy/docker/docker-compose.prod.yml`

Change the `proxy` service's `dockerfile:` from `deploy/docker/Dockerfile` to `deploy/docker/Dockerfile.go-proxy`. Update `context:` if needed (`.dockerignore` already accounts for Go proxy).

### B — Add configurable on_unknown_ja4 policy (F-2, High)

**Files:** `proxy.py`, `config/proxy.yml`

1. Add `on_unknown_ja4: block | forward | tarpit` to config schema (default: `forward` for backward compatibility, `block` documented as production recommendation).
2. In the `if ja4 in ("unknown", "error"):` branch, evaluate the policy:
   - `forward` — current behavior
   - `block` — close connection with TLS alert
   - `tarpit` — redirect to tarpit
3. Log at WARNING level (not INFO) when triggered.
4. Increment `ja4proxy_unknown_ja4_total` counter.

### C — Fail-closed Redis error handling (F-3/F-4, High)

**Files:** `proxy.py`

1. Country block check (line 2429): on Redis error, log WARNING + increment counter. Add config `country_block_on_redis_error: block | allow` (default: `block`).
2. Rate limit dial read (line 1076): on Redis error, return `dial = max_dial` (most restrictive) instead of `dial = 0`.
3. Add a Redis circuit breaker: after 3 consecutive errors in a 30-second window, log CRITICAL and optionally take configured action.

### D — Audit and narrow every `except Exception:` (F-5, High)

**Files:** `proxy.py`

1. Go through all 40 `except Exception:` clauses.
2. For each:
   - If the specific exception type is known, catch that type.
   - If it must remain broad, log at WARNING with context.
   - Add a `ja4proxy_internal_errors_total` counter increment with a label for the error location.
3. Remove all bare `pass` — replace with at minimum a log statement.

### E — Triage pre-existing test failures (F-6, Medium)

**Files:** Various test files

1. Capture the current failure list: `python3 -m pytest tests/ --collect-only -q 2>&1 | tail -50`
2. Run full suite to reproduce: `python3 -m pytest tests/ -q --tb=short 2>&1 | grep FAILED`
3. Investigate each:
   - Flaky test (environment-dependent)? → mark with `pytest.mark.flaky` or `@pytest.mark.skipif`
   - Fixture drift? → update fixtures
   - Real regression? → treat as bug
4. Document remaining skips in `docs/security/EXCEPTIONS.md` with approved exception IDs.

### F — Health check panic recovery (F-7, Medium)

**Files:** `cmd/proxy/main.go`

1. Wrap the health check loop body in a `defer recover()`.
2. On panic, log the stack trace at ERROR level.
3. Increment `ja4proxy_health_check_panics_total` metric.
4. The goroutine should continue looping (not die).

### G — Config reload failure metric (F-8, Low)

**Files:** `cmd/proxy/main.go`

1. Add a counter metric: `ja4proxy_config_reload_failures_total`.
2. Change SIGHUP error log from Warn to Error.
3. Emit failure reason as a label value.

---

## Acceptance Criteria

### Critical
- [ ] `docker-compose.prod.yml` builds the Go proxy, not the Python proxy
- [ ] Deployed proxy image is < 20MB (Go binary) not > 500MB (Python + deps)

### High
- [ ] `on_unknown_ja4` config key implemented; `block` policy stops unknown TLS connections
- [ ] Country block check logs WARNING on every Redis error (not just first)
- [ ] Redis dial read failure defaults to `dial = max_dial` (most restrictive)
- [ ] All 40 `except Exception:` clauses reviewed; none have bare `pass`
- [ ] Every caught exception is logged at WARNING or ERROR with connection context
- [ ] `ja4proxy_internal_errors_total` counter exists with location label

### Medium
- [ ] Pre-existing test failures triaged; each has a documented status (fixed, skipif, or EXCEPTIONS.md entry)
- [ ] `make test` reports 0 unexpected failures (only intentional skips)
- [ ] Go health check goroutine recovers from panic and continues looping
- [ ] `ja4proxy_health_check_panics_total` metric exposed

### Low
- [ ] Config reload failure logged at ERROR level
- [ ] `ja4proxy_config_reload_failures_total` metric exposed with reason label

### Standard
- [ ] `make test` passes
- [ ] `go test ./...` passes
- [ ] `ruff check .` clean
- [ ] `go vet ./...` clean
- [ ] CHANGELOG.md updated
- [ ] manifest.yaml updated with `status: COMPLETE`
- [ ] `make lint-phases` exits 0

---

## Risks & Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| Changing `dial=0` default to `dial=max_dial` on Redis error may cause unexpected blocking in production if Redis has transient blips | HIGH | Make fail-closed vs fail-open configurable; default to fail-closed for new installs, document migration for existing |
| `on_unknown_ja4=block` may break legitimate clients with unusual TLS stacks (e.g., embedded devices, legacy browsers) | HIGH | Log every blocked connection with full TLS metadata so operators can build allowlist; make `tarpit` a middle-ground option |
| Tightening 40 `except Exception:` clauses may expose latent crashes that were previously masked | MEDIUM | Staged rollout: log-only mode for 1 week, then activate new behavior |
| Changing `docker-compose.prod.yml` proxy type changes env vars and volume mounts | MEDIUM | Compare environment variables between Python and Go images; ensure compat or update docs |
| Go RPC `recover()` in health check may hide programming errors | LOW | Log full stack trace on panic; monitor the error counter |

---

## Out of Scope

- **Go proxy feature parity gaps** (Python-only signal modules) — that is ongoing Phase 15 work.
- **Python proxy deprecation** — the Python proxy is still needed for parity validation.
- **New signal modules or security features** — only fixing existing error handling.
- **Redis infrastructure** (HA, sentinel, cluster) — fixing what the proxy does when Redis is down, not making Redis never go down.
- **Performance optimization** — only correctness and safety.
- **Refactoring proxy.py into smaller files** — structural refactoring is a separate phase.
