---
phase: 843
title: "Configurable Fail-Open Policy & Overload Resilience"
status: PROPOSED
size: MEDIUM
created: 2026-10-13
audience: [developer, operations, architect, secops]
---

# Configurable Fail-Open Policy & Overload Resilience

> **STATUS: PROPOSED — plan incorporating Systems & Security Architecture Expert Review.**

## Executive Summary & Context

JA4proxy is designed as an inline, transparent security proxy. In production enterprise deployments, SecOps and Network Engineering teams require deterministic failure behavior:
1. **Business Continuity (Transparency First):** If auxiliary inspection infrastructure (Redis state store, threat feeds, enrichment microservices, internal queues) experiences transient outages or saturation, proxy traffic MUST continue flowing without disrupting legitimate user transactions.
2. **Deterministic Attack Defense (Protocol Violations & Hard Blocks):** Protocol-layer attacks (malformed TLS records, HTTP/1.1 request smuggling headers, truncated ClientHello frames) MUST NEVER be forwarded to downstream backends. Furthermore, synchronous security invariants established under `JA4PROXY-2026-0094` (explicit operator `ban:{ip}`, Spamhaus blocklists, and TLS version/cipher restrictions) must remain strictly enforced.

Currently, several proxy subcomponents handle errors with disparate hardcoded policies. This phase introduces an operator-configurable `security_policy.fail_open` toggle (defaulting to `true` for transparency), backed by a lightweight fast-failure circuit breaker to prevent goroutine explosion during Redis outages.

---

## Architectural Principles & Boundary Matrix

| Condition Category | Trigger Examples | `fail_open: true` (Default) | `fail_open: false` (Strict SecOps) | Rationale |
|---|---|---|---|---|
| **Auxiliary / State Store Outage** | Redis connection refused, Redis command timeout, sentinel failover lag | **ALLOW (Fail-Open)** + fast-fail circuit breaker + increment metrics | **DROP / TARPIT** + increment metrics | Infrastructure outages must not cause enterprise network blackout unless explicitly requested by SecOps. |
| **Worker Queue Saturation** | `workChan` capacity exhausted under traffic spikes | **ALLOW (Bypass Deferred Scoring)** + increment `work_chan_dropped_total` | **DROP (Fail-Closed)** + increment drop metric | Soft backpressure allows traffic through rather than causing wholesale self-inflicted DoS. Hard blocks are checked synchronously *before* enqueue. |
| **Lookup / Feed Degraded** | Threat intelligence feed stale, GeoIP database missing | **ALLOW (Default Allow)** | **ALLOW / BLOCK** (policy-dependent) | Missing contextual enrichment degrades gracefully. |
| **Operator Manual Bans** | `ban:{ip}` lookup errors during Redis outage | **ALLOW** (or cached local memory allow) | **DROP / TARPIT** | Synchronous pre-checks adhere to the operator's global fail-open/fail-closed posture. |
| **Transport / TLS Malformation** | Truncated ClientHello, invalid TLS version, invalid SNI control bytes | **DROP / HARD REJECT** | **DROP / HARD REJECT** | Protocol attacks threaten backend web servers; malformed frames can never be forwarded safely. |
| **Smuggling Attacks** | Split PROXY protocol frames, secondary injection headers | **DROP / HARD REJECT** | **DROP / HARD REJECT** | In-flight smuggling is an exploit, not a transient operational blip. |

---

## Configuration Schema & Hot Reload

In `config/proxy.yml` (and reflected in `internal/config/loader.go`'s `SecurityPolicyConfig`):

```yaml
security_policy:
  # Operator-configurable failure behavior when auxiliary services fail
  # or evaluation queues saturate.
  # Default: true (transparent inline proxy behavior).
  fail_open: true

  # Subsystem-specific overrides (optional; inherit security_policy.fail_open if omitted)
  subsystems:
    redis_failure: true
    queue_saturation: true
    geo_enrichment_failure: true
    reputation_feed_failure: true

  # Circuit breaker threshold for auxiliary Redis calls:
  circuit_breaker:
    failure_threshold: 5        # Consecutive failures to trip
    cooldown_seconds: 10        # Fast-fail bypass duration before probing
```

Environment variables:
- `JA4PROXY_SECURITY_POLICY_FAIL_OPEN=true|false`
- `JA4PROXY_SECURITY_POLICY_SUBSYSTEMS_REDIS_FAILURE=true|false`

### Zero-Lock Runtime Reloading
To maintain Phase 842 concurrency invariants, `FailOpen` and circuit breaker settings are embedded directly into the immutable `PipelineSnapshot` pointer and updated atomically via `atomic.Pointer[PipelineSnapshot]` upon `SIGHUP` config reload.

---

## Implementation Scope

1. **Configuration Loader (`internal/config/`):**
   - Extend `SecurityPolicyConfig` with `FailOpen bool`, `Subsystems map[string]bool`, and `CircuitBreakerConfig`.
   - Provide default `true` when omitted.
2. **Circuit Breaker & Redis Error Propagation (`internal/redis/` & `internal/security/`):**
   - Add a fast-failing circuit breaker latch on `redis.Client` to avoid repeated TCP connection timeouts under high connection volume.
   - Surface Redis error state so `pipeline.go` can differentiate clean nil vs backend outage, enabling strict `fail_open: false` enforcement when configured.
3. **Queue Saturation & Hard-Block Pre-Checks (`internal/security/pipeline.go`):**
   - Preserve synchronous checks (`ban:{ip}`, Spamhaus, TLS record validations from `JA4PROXY-2026-0094`).
   - Route `workChan` saturation fallback through `p.snapshot.Load().FailOpen`:
     - If `true`: return `allow` (bypass deferred scoring) and increment bypass metric.
     - If `false`: return `block` / `tarpit` and increment fail-closed drop metric.
4. **Prometheus Telemetry & Logging:**
   - Counter: `ja4proxy_fail_open_events_total{subsystem="redis|queue|enrichment"}`
   - Counter: `ja4proxy_fail_closed_events_total{subsystem="redis|queue|enrichment"}`
   - Structured log event on transition to degraded state.
5. **Testing Strategy (TDD):**
   - Unit tests for `fail_open: true` vs `false` with mock Redis errors.
   - Unit tests verifying `workChan` saturation behavior under both modes.
   - Circuit breaker transition tests (closed -> open -> half-open probe -> closed).
   - Integration tests simulating Redis container stoppage while asserting proxy transparent passthrough.

---

## Acceptance Criteria
- Proxy defaults to `fail_open: true`, allowing continuous traffic flow during Redis outage without blocking on timeouts.
- Setting `fail_open: false` strictly drops/tarpits traffic on Redis or queue failure.
- Malformed TLS and smuggling attempts remain unconditionally dropped under all modes.
- SIGHUP configuration reload updates fail-open posture without connection drops or mutex contention.
- Full test suite, linters, and race detector pass clean.
