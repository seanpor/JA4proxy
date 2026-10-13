---
phase: 843
title: "Configurable Fail-Open Policy & Overload Resilience"
status: PROPOSED
size: MEDIUM
created: 2026-10-13
audience: [developer, operations, architect, secops]
---

# Configurable Fail-Open Policy & Overload Resilience

> **STATUS: PROPOSED — plan for review and discussion.**

## Executive Summary & Context

JA4proxy is designed as an inline, transparent security proxy. In production enterprise deployments, SecOps and Network Engineering teams require deterministic failure behavior:
1. **Business Continuity (Transparency First):** If downstream inspection infrastructure (Redis, enrichment microservices, rate-limiter caches, internal queues) experiences outages or saturation, proxy traffic MUST continue flowing without disrupting legitimate user transactions.
2. **Deterministic Attack Defense (Protocol Violations):** Even in fail-open mode, genuine transport/protocol-layer attacks (e.g. malformed TLS records, HTTP/1.1 request smuggling headers, truncated ClientHello frames) MUST NOT be forwarded to downstream backends.

Currently, several proxy subcomponents handle errors with disparate policies (some fail-closed on cache disconnect, others drop or tarpit). This phase proposes and plans a centralized, operator-configurable `security_policy.fail_open` toggle (defaulting to `true`), establishing clear boundary definitions between protocol-layer defense and auxiliary-service degradation.

---

## Architectural Principles & Boundary Matrix

| Condition Category | Trigger Examples | `fail_open: true` (Default) | `fail_open: false` (Strict SecOps) | Rationale |
|---|---|---|---|---|
| **Auxiliary / State Store Failure** | Redis connection refused, Redis command timeout, sentinel failover lag | **ALLOW (Fail-Open)** + log warning + increment metric | **DROP / TARPIT** + increment metric | Infrastructure outages must not cause enterprise network blackout unless explicitly configured. |
| **Worker Queue Saturation** | `workChan` capacity exhausted under traffic spikes | **ALLOW (Bypass Evaluation)** + increment `queue_overflow_bypass_total` | **DROP (Fail-Closed)** + increment `queue_overflow_drop_total` | Soft backpressure allows traffic through rather than causing wholesale self-inflicted DoS. |
| **Lookup / Feed Degraded** | Threat intelligence feed stale, GeoIP database missing | **ALLOW (Default Allow)** | **ALLOW / BLOCK** (policy-dependent) | Missing contextual enrichment should degrade gracefully. |
| **Transport / TLS Malformation** | Truncated ClientHello, invalid TLS version, invalid SNI control bytes | **DROP / HARD REJECT** | **DROP / HARD REJECT** | Protocol attacks threaten backend web servers; malformed frames can never be forwarded safely. |
| **Smuggling Attacks** | Split PROXY protocol frames, secondary injection headers | **DROP / HARD REJECT** | **DROP / HARD REJECT** | In-flight smuggling is an exploit, not a transient operational blip. |

---

## Proposed Configuration Schema

In `config/config.yaml`:

```yaml
security_policy:
  # Operator-configurable failure behavior when auxiliary services fail
  # or evaluation queues saturate.
  # Default: true (transparent inline proxy behavior).
  fail_open: true

  # Subsystem-specific overrides (optional; default to security_policy.fail_open)
  subsystems:
    redis_failure: true
    queue_saturation: true
    geo_enrichment_failure: true
    reputation_feed_failure: true
```

In environment variables:
`JA4PROXY_SECURITY_POLICY_FAIL_OPEN=true|false`

---

## Implementation Scope

1. **Central Policy Management in Go Proxy (`internal/config`, `internal/security`):**
   - Introduce `FailOpen bool` into configuration structs and runtime atomic snapshot pointers.
   - Provide clean helper methods on `SecurityPipeline`: `pipeline.ShouldFailOpen(failureType FailureType) bool`.
2. **Error-Handling Refactoring:**
   - Audit all Redis query error branches in `internal/security/pipeline.go` and `internal/redis/`.
   - Audit `workChan` backpressure handling in `cmd/ja4pd/main.go`.
3. **Observability & SecOps Telemetry:**
   - Prometheus metrics:
     - `ja4proxy_fail_open_events_total{subsystem="redis|queue|enrichment"}`
     - `ja4proxy_fail_closed_events_total{subsystem="redis|queue|enrichment"}`
   - Structured JSON audit log events:
     `{"event": "security_fail_open", "reason": "redis_timeout", "client_ip": "...", "action": "forwarded"}`
4. **Testing Strategy:**
   - Unit tests covering matrix of `fail_open: true` vs `false` across mocked Redis timeouts and filled channels.
   - Integration chaos tests simulating complete Redis outage while verifying traffic passthrough.

---

## Out of Scope
- Dynamic hot-toggling without config reload (SIGHUP reload will be supported, but no unauthenticated runtime endpoint).
- Altering protocol-level parsing rules (smuggling and invalid TLS remain unconditionally dropped).
