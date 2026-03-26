# Phase 14b — Production Hardening Supplement

## Status: OPEN

## Purpose

This document supplements `PHASE_14.md`. Read that document first. This supplement
adds the items identified as missing from Phase 14:

1. TDD category checklist with specific test file names and minimum counts
2. Grafana dashboard panel specifications for production hardening metrics
3. ADR-014: Tarpit self-protection design rationale
4. Tarpit threat model: attacks defended against, attacks not defended, information disclosure
5. Runbook scenario: tarpit capacity exhausted under sustained attack
6. End-user security model documentation
7. Log schema for new events introduced in Phase 14

---

## 1. TDD Category Checklist

Phase 14 must satisfy all seven test categories from `docs/TESTING_STRATEGY.md`. The
following is the complete checklist. Every box must be ticked before Phase 14 is marked
complete.

### 1a. Unit Tests (`tests/unit/test_tarpit.py`)

Minimum 12 tests. Write these **before** implementing `TarpitManager`.

- [x] `test_cap_not_reached_connection_tarpitted` — under cap → action is tarpit
- [x] `test_global_cap_reached_overflow_block` — at cap, overflow_action=block → RST returned
- [x] `test_global_cap_reached_overflow_rst` — at cap, overflow_action=rst → RST returned
- [x] `test_global_cap_reached_overflow_allow` — at cap, overflow_action=allow → allow returned
- [x] `test_per_ip_cap_reached_other_ips_unaffected` — IP at per-IP cap; different IP unaffected
- [x] `test_per_ip_cap_independent_of_global_cap` — per-IP cap fires before global cap
- [x] `test_counter_decr_on_clean_close` — counter returns to pre-connection value after close
- [x] `test_counter_decr_on_abrupt_disconnect` — counter cleaned up when TCP drops without close
- [x] `test_counter_not_leaked_on_redis_error` — Redis INCR fails → fail open; counter at 0
- [x] `test_overflow_prometheus_counter_incremented` — `ja4proxy_tarpit_overflow_total{action}` +1
- [x] `test_overflow_log_emitted` — overflow event logged at WARN with structured JSON
- [x] `test_config_hot_reload_updates_cap` — new cap applied to connections after reload

### 1b. Integration Tests (`tests/integration/test_pipeline.py`)

Minimum 5 tests. Write these **before** wiring tarpit into the pipeline.

- [x] `test_graceful_shutdown_drains_in_flight` — SIGTERM during 50 active connections; all drain within timeout
- [x] `test_redis_auth_wrong_password_fatal` — proxy refuses to start; FATAL logged
- [x] `test_structured_json_logging_valid` — 100 connections; every log line parses as JSON
- [x] `test_tarpit_overflow_does_not_affect_legitimate_connections` — overflow at cap; connections
      with non-tarpit actions (block, allow) proceed normally
- [x] `test_config_hot_reload_tarpit_cap_live` — cap lowered mid-traffic; new cap enforced

### 1c. Chaos Tests (`tests/chaos/test_redis_failure.py`)

Minimum 4 tests.

- [x] `test_redis_down_tarpit_counter_fail_open` — Redis unreachable during INCR; connection
      tarpitted (fail open); counter assumed 0; no crash
- [x] `test_redis_recovers_counter_resync` — Redis down then up; counter re-syncs within 1 cycle
- [x] `test_oom_kill_and_restart` — container killed at memory limit; restarts cleanly; no
      corrupted Redis keys; counter reset correctly
- [x] `test_redis_password_rotate_hot_reload` — new REDIS_URL with new password; proxy
      re-authenticates without restart; zero connection drop

### 1d. Adversarial Tests (`tests/adversarial/test_tarpit_adversarial.py`)

Minimum 3 tests. These verify the tarpit cannot be used against the proxy itself.

- [x] `test_tarpit_exhaustion_attack_capped` — simulate attacker opening `max_concurrent + 50`
      simultaneous connections; all overflow connections receive `overflow_action`; proxy
      continues accepting non-tarpit connections throughout
- [x] `test_per_ip_exhaustion_capped` — single IP opens `max_per_ip + 10` connections; excess
      receive overflow_action; other IPs unaffected
- [x] `test_overflow_action_allow_does_not_bypass_scoring` — overflow_action=allow must not skip
      audit log; connection still scored and logged; only tarpitting is skipped

### 1e. FP Corpus Tests (`tests/fp_corpus/test_tarpit_fp.py`)

Minimum 2 tests.

- [x] `test_h2_alpn_never_tarpitted` — browser ALPN bypass fires before tarpit check;
      no h2/h1 connection ever reaches the tarpit decision point
- [x] `test_known_good_ja4_whitelist_never_tarpitted` — whitelisted fingerprints bypass
      before tarpit; not affected by cap

### 1f. Performance Tests (`tests/performance/test_bench_tarpit.py`)

- [x] `test_tarpit_counter_ops_p99_under_1ms` — INCR+DECR under 500 concurrent tarpitted
      connections; Redis operations p99 < 1ms
- [x] `test_tarpit_does_not_affect_allow_path_latency` — allow bypass latency unchanged
      when tarpit at full capacity (comparison: baseline vs 500 concurrent tarpitted)

### 1g. E2E Tests (smoke only — Docker required)

- [x] `test_e2e_tarpit_connection_receives_slow_drain` — end-to-end: connect to proxy; receive
      1 byte per second; verify connection stays open for configurable duration; verify
      `ja4proxy_tarpit_concurrent` gauge increments

---

## 2. Grafana Dashboard Panel Specifications

Add the following panels to the existing `grafana/dashboards/proxy.json` dashboard. Do
not create a separate dashboard — production hardening metrics belong alongside the main
proxy metrics.

### Panel: Tarpit Capacity Usage

```
Title: Tarpit Capacity
Type: Stat + Gauge
Query: ja4proxy_tarpit_concurrent / <max_concurrent from config label>
Thresholds:
  - 0–50%: green
  - 50–80%: yellow
  - 80–100%: red
Description: "Current / max concurrent tarpitted connections"
```

### Panel: Tarpit Overflow Rate

```
Title: Tarpit Overflows (last 5m)
Type: Stat
Query: rate(ja4proxy_tarpit_overflow_total[5m]) * 60
Unit: overflows/min
Thresholds:
  - 0: green
  - > 1/min: yellow
  - > 10/min: red
Description: "Non-zero means tarpit is at capacity and some connections are
             receiving overflow_action instead"
```

### Panel: Tarpit Overflow by Action

```
Title: Tarpit Overflow Actions
Type: Time series
Queries:
  - rate(ja4proxy_tarpit_overflow_total{action="block"}[1m])   label="Block"
  - rate(ja4proxy_tarpit_overflow_total{action="rst"}[1m])     label="RST"
  - rate(ja4proxy_tarpit_overflow_total{action="allow"}[1m])   label="Allow (risk)"
```

### Panel: Graceful Shutdown Events

```
Title: Process Restarts
Type: Stat
Query: increase(ja4proxy_system_restarts_total[24h])
Description: "Container restarts in last 24h. Non-zero = investigate."
```

### Panel: Log Parse Error Rate

```
Title: Structured Log Validity
Type: Stat (0 = green)
Query: rate(ja4proxy_log_parse_errors_total[5m])
Thresholds: 0 = green, > 0 = red
Description: "Log lines that failed JSON parsing. Must be zero."
```

### AlertManager Rule Additions

Add to `monitoring/alertmanager/rules/security.rules.yml`:

```yaml
- alert: TarpitCapacityHigh
  expr: ja4proxy_tarpit_concurrent / on() group_left() ja4proxy_tarpit_capacity > 0.8
  for: 2m
  labels:
    severity: warning
  annotations:
    summary: "Tarpit at {{ $value | humanizePercentage }} capacity"
    description: "Tarpit slots {{ $value | humanizePercentage }} full. Overflow_action
                 will fire soon. May indicate tarpit exhaustion attack."

- alert: TarpitOverflowSustained
  expr: rate(ja4proxy_tarpit_overflow_total[5m]) > 1
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Sustained tarpit overflow ({{ $value | humanize }}/min)"
    description: "Tarpit at capacity for 5+ minutes. Check if attacker has
                 discovered the tarpit and is deliberately exhausting slots."

- alert: TarpitOverflowAllowActive
  expr: rate(ja4proxy_tarpit_overflow_total{action="allow"}[1m]) > 0
  for: 0m
  labels:
    severity: critical
  annotations:
    summary: "Tarpit overflow_action=allow is firing"
    description: "Connections that should be tarpitted are being allowed through.
                 Tarpit is at capacity and overflow_action is set to allow."
```

---

## 3. Structured Log Schema for Phase 14 Events

The following events are new in Phase 14. Each must produce a structured JSON log line
matching the schema in `docs/OBSERVABILITY_STANDARDS.md §2`.

### 3a. SIGTERM received

```json
{
  "type": "system",
  "level": "INFO",
  "subsystem": "proxy",
  "event": "shutdown_initiated",
  "active_connections": 47,
  "drain_timeout_s": 30,
  "timestamp": "2026-03-10T14:23:00Z"
}
```

### 3b. Tarpit overflow

```json
{
  "type": "connection",
  "level": "WARN",
  "subsystem": "tarpit",
  "event": "tarpit_overflow",
  "client_ip": "185.220.101.5",
  "ja4": "t13d1516h2_8daaf6152771_02713d6af862",
  "overflow_action": "block",
  "global_concurrent": 500,
  "global_cap": 500,
  "per_ip_concurrent": 3,
  "per_ip_cap": 3,
  "timestamp": "2026-03-10T14:23:00Z"
}
```

### 3c. Redis AUTH failure at startup

```json
{
  "type": "system",
  "level": "FATAL",
  "subsystem": "redis",
  "event": "auth_failure",
  "error": "WRONGPASS invalid username-password pair",
  "timestamp": "2026-03-10T14:23:00Z"
}
```

### 3d. Config hot-reload applied

```json
{
  "type": "system",
  "level": "INFO",
  "subsystem": "config",
  "event": "config_reloaded",
  "changed_keys": ["tarpit.max_concurrent_connections", "tarpit.overflow_action"],
  "old_values": {"tarpit.max_concurrent_connections": 500, "tarpit.overflow_action": "block"},
  "new_values": {"tarpit.max_concurrent_connections": 200, "tarpit.overflow_action": "allow"},
  "timestamp": "2026-03-10T14:23:00Z"
}
```

---

## 4. ADR-014: Tarpit Self-Protection Design

**File:** `docs/decisions/ADR-014.md`

```markdown
# ADR-014: Tarpit Self-Protection Design

## Status: Accepted

## Context

The tarpit action holds a connection open at 1 byte/second to waste an attacker's
resources. Each tarpitted connection consumes one file descriptor and ~8KB of memory
in the proxy process. The proxy runs with `ulimit -n 65536` in production.

An attacker who learns they are being tarpitted (by observing the 1-byte/second drain
rate rather than an RST) can deliberately generate thousands of simultaneous tarpitted
connections to exhaust the proxy's file descriptors.

## Options Considered

**Option A: No cap — fail open**
Allow unlimited tarpit connections. Risk: a single attacker can exhaust all file
descriptors and crash the proxy.
Rejected: denial-of-service against the proxy itself is unacceptable.

**Option B: Hard in-process cap with overflow_action**
Track concurrent tarpit count in-process (fast, no Redis round trip). When cap
reached, apply a configurable overflow_action (block / rst / allow).
Selected.

**Option C: Adaptive cap based on memory / FD pressure**
Monitor `/proc/self/fd` or memory usage and lower the cap dynamically.
Deferred: adds complexity; the hard cap with conservative default (500) is sufficient
for the threat model.

**Option D: Redis-coordinated cross-instance cap**
All proxy instances share one counter for the total tarpit count across the cluster.
Rejected for the fast path: Redis round-trip adds ~0.5ms per tarpit connection open/close.
Redis gauge is kept for monitoring (cross-instance visibility) but the enforcement cap
is per-instance in-process.

## Decision

Per-instance in-process hard cap (`max_concurrent_connections`), with a separate
per-source-IP cap (`max_per_ip`). When either cap is reached, `overflow_action` is
applied. Default `overflow_action` is `block` (RST sent to attacker).

The cross-instance Redis gauge (`ja4proxy_tarpit_concurrent` Prometheus metric via
Redis) gives operators visibility into total tarpit load without affecting the
hot-path decision latency.

## Consequences

1. **Information disclosure**: The tarpit timeout is observable by the attacker. An
   attacker receiving 1 byte/second knows they are being tarpitted, not blocked. This
   is by design — the tarpit's value is wasting attacker resources, not hiding the
   proxy's presence.

2. **Overflow leaks defensive posture**: When `overflow_action=block`, an attacker
   who exhausts tarpit slots receives immediate RST instead of slow drain. This tells
   the attacker the slot cap has been reached, which could help them calibrate their
   attack. `overflow_action=allow` avoids this but creates a fail-open window.
   Operators should choose based on their threat model.

3. **Per-instance cap**: In a multi-instance deployment, the effective cluster-wide
   cap is `max_concurrent_connections × instance_count`. This scales naturally.

4. **Counter accuracy**: The in-process counter can drift if the proxy crashes without
   clean shutdown. On restart, the counter resets to zero. This is acceptable — a
   fresh start means fresh capacity.

## Revisit If

- The proxy moves to Go (Phase 15): Go goroutines are lighter than Python coroutines;
  the cap may need recalibration upward.
- Multi-instance deployments require cross-instance coordination: switch to Redis
  counter with Lua script for atomic INCR+CAP check.
```

---

## 5. Tarpit Threat Model

**File:** `docs/security/TARPIT_THREAT_MODEL.md`

### Threats Defended Against

| Threat | How tarpit defends | Residual risk |
|--------|-------------------|---------------|
| Automated scanner (low concurrency) | Each scanner connection held for minutes, wasting scanner threads | Scanner with large thread pool unaffected |
| Bot farm (moderate concurrency) | Resource drain at bot farm; bots timeout waiting | Sophisticated bots reconnect immediately after timeout |
| Reconnaissance — is this a proxy? | Slow response makes port appear non-standard | Attacker still learns "something is there" |

### Threats NOT Defended Against

| Threat | Why tarpit does not help |
|--------|--------------------------|
| DDoS at volumetric scale (>1000 conn/s) | Tarpit slots exhausted immediately; overflow_action fires |
| Attacker with dedicated tarpit exhaust | Attacker sends `max_concurrent + N` connections deliberately; proxy forced into overflow |
| UDP flood | Tarpit is TCP-only; no effect on UDP |
| TLS fingerprint reconnaissance | Attacker observes proxy's TLS characteristics from the handshake, which completes before tarpit starts |

### Information Disclosed by the Tarpit

An attacker can learn the following by probing the proxy:

| Observable | What attacker learns | Risk level |
|------------|---------------------|------------|
| 1 byte/second drain rate | Connection is being tarpitted, not firewalled | Low — attacker learns they are detected, not how |
| Overflow causes immediate RST | Tarpit capacity is exhausted | Medium — attacker can calibrate exhaustion attacks |
| Specific per-IP cap (3 by default) | IP cap value | Low — easily discovered by trial |
| Latency of overflow_action=allow | Connection count threshold | Medium — sophisticated attacker can extract cap |

### Configuration Risk Matrix

| Configuration | Behaviour at cap | Risk |
|--------------|-----------------|------|
| `overflow_action: block` | RST; attacker learns cap was reached | Information disclosure; capacity exact threshold discoverable |
| `overflow_action: rst` | Same as block | Same |
| `overflow_action: allow` | Connection passes through; **may allow malicious traffic** | Fail-open risk; attacker can exhaust tarpit and then pass unblocked |

**Recommendation:** Use `overflow_action: block` for most deployments. Only use
`overflow_action: allow` if false-positive risk (blocking legitimate users due to
tarpit exhaustion) outweighs the risk of adversarial exhaustion.

---

## 6. Operator Runbook Scenario: Tarpit Capacity Exhausted

**File:** Add to `docs/SECOPS_OPERATIONS.md` under "Incident Scenarios"

```markdown
### Scenario: Tarpit Capacity Exhausted During Attack

**Symptoms**
- `TarpitCapacityHigh` or `TarpitOverflowSustained` alert fires
- `ja4proxy_tarpit_overflow_total` spike in Grafana
- Possible: attacker connections are passing through (if overflow_action=allow)

**Immediate Triage (< 2 minutes)**

1. Check current overflow action:
   `redis-cli GET config:features:tarpit_overflow_action`

2. If overflow_action=allow and traffic is malicious, escalate immediately:
   Set overflow_action to block via management UI → Config page → Feature flags

3. Check which IPs are exhausting tarpit slots:
   `ja4proxy-admin suspect list --top 20 --format json`

4. Check actual tarpit concurrent count vs cap:
   Grafana → Tarpit Capacity panel

**Investigation**

1. Is this legitimate high traffic or an attack?
   - Plot `ja4proxy_connections_active` — spike without legitimate traffic explanation
     indicates attack
   - Check country distribution: high volume from unexpected country = likely attack

2. Is a single IP or subnet exhausting per-IP cap?
   `ja4proxy-admin inspect ip <top-offender-ip>`

3. Is this a deliberate tarpit exhaustion attack?
   - Attacker sends exactly `max_per_ip` connections from many IPs to exhaust global cap
   - Look for IPs all at exactly `max_per_ip` concurrent connections

**Remediation Options**

| Situation | Action |
|-----------|--------|
| Single attacker IP | `ja4proxy-admin ban <ip> --ttl 86400` |
| Subnet attack | `ja4proxy-admin ban-cidr <cidr>` via management UI |
| Sustained overflow | Temporarily lower `tarpit.max_concurrent_connections` to free FDs; OR raise `tarpit.max_concurrent_connections` if FDs allow |
| overflow_action=allow creating risk | Change to `block` immediately via config hot-reload |

**Recovery**

1. Once attack subsides, verify tarpit counter returns to normal:
   Grafana → Tarpit Capacity panel should drop to near zero

2. If counter appears stuck (process restart):
   `redis-cli DEL ja4proxy:tarpit:concurrent` — counter resets on next connection

3. Post-incident: document attacker IPs/subnets; consider adding to Spamhaus manual
   blocklist if not already covered
```

---

## 7. End-User Security Model

**File:** Add to `docs/DEPLOYMENT_SECURITY_MODEL.md` (create if not present)

```markdown
## Phase 14 Security Properties

### What Phase 14 Hardening Provides

1. **Secrets at rest**: All credentials (Redis password, API keys) are loaded from
   environment variables at startup. The Docker Compose file contains no plaintext secrets.

2. **Network isolation**: Redis is bound to the internal Docker network only. It is
   not reachable from outside the compose stack.

3. **Resource containment**: CPU and memory limits on all containers prevent a single
   component from exhausting host resources. File descriptor limits are set appropriately
   for expected connection counts.

4. **Tarpit self-protection**: The tarpit cannot be exploited to exhaust proxy file
   descriptors. A hard cap + overflow action prevents denial-of-service via tarpit
   exhaustion.

5. **Graceful shutdown**: In-flight connections are drained before the process exits.
   No partial state is written to Redis during shutdown.

### What Phase 14 Does NOT Provide

1. **Encryption at rest**: Redis data is not encrypted at rest. Data at rest protection
   requires filesystem encryption (LUKS/dm-crypt) at the host layer.

2. **Redis TLS**: Redis uses TCP without TLS by default. For cross-host replication,
   configure TLS in `../../docker/docker-compose.prod.yml`. Single-host deployments are protected
   by Docker network isolation.

3. **Multi-tenant isolation**: All proxy instances share a single Redis instance. There
   is no per-tenant data isolation.

4. **Key rotation automation**: Redis password rotation requires restarting the proxy.
   Automated rotation with zero downtime is not implemented.

### Deployment Prerequisites

Before deploying to production:

- [x] `UI_API_KEY` set to a random 32+ byte value (`openssl rand -base64 32`)
- [x] `REDIS_PASSWORD` set to a random 32+ byte value
- [x] `ABUSEIPDB_API_KEY` set (if using AbuseIPDB integration)
- [x] Redis not exposed outside Docker network (verify with `docker network ls`)
- [x] `ulimit -n` ≥ 65536 on the host (check with `ulimit -n`)
- [x] `max_connections` in config ≤ `ulimit -n` - 100 (headroom for system FDs)
```

---

## 8. Acceptance Criteria (Supplement)

These additions extend the acceptance criteria in `PHASE_14.md`. Both sets must pass.

### TDD Process

- [x] All unit tests written before `TarpitManager` class is implemented (verified by
      git history: test commit precedes implementation commit)
- [x] All 7 test categories present: unit, integration, chaos, adversarial, FP corpus,
      performance, E2E (smoke)
- [x] Test-to-code ratio ≥ 1.3× for `src/tarpit/` or wherever tarpit is implemented

### Grafana

- [x] Five new Grafana panels added to existing proxy dashboard (Tarpit Capacity,
      Tarpit Overflow Rate, Tarpit Overflow by Action, Process Restarts, Log Parse Errors)
- [x] Three new AlertManager rules pass `promtool check rules`

### Logging

- [x] All four new log event types (SIGTERM, tarpit overflow, Redis AUTH failure, config
      reload) produce valid JSON matching schemas in §3
- [x] Log line for tarpit overflow includes `global_concurrent`, `global_cap`,
      `per_ip_concurrent`, `per_ip_cap` fields

### Documentation

- [x] `docs/decisions/ADR-014.md` exists and covers all four options considered
- [x] `docs/security/TARPIT_THREAT_MODEL.md` exists with complete threat matrix
- [x] `docs/SECOPS_OPERATIONS.md` updated with tarpit exhaustion runbook scenario
- [x] `docs/DEPLOYMENT_SECURITY_MODEL.md` updated with Phase 14 security properties
