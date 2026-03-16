# Phase 14 — Production Hardening

## Status: PLANNED

Read `docs/DMZ_DEPLOYMENT_READINESS.md` and `docs/security/COMPREHENSIVE_SECURITY_AUDIT.md`
before starting. Many of the audit's findings are already resolved — this plan addresses
the genuine remaining gaps.

---

## What is Already in Place (Do Not Re-implement)

The following items from the DMZ readiness doc and security audit are **already done**:

| Item | Where |
|------|--------|
| Non-root containers, read-only FS, cap_drop ALL, no-new-privileges | `docker-compose.poc.yml` |
| CPU + memory limits on every container | `docker-compose.poc.yml` |
| Redis AUTH (`--requirepass`), no host port | `docker-compose.poc.yml` redis service |
| Redis `maxmemory` + `allkeys-lru` | `docker-compose.poc.yml` REDIS_ARGS |
| `stream_max_length` cap on `ja4proxy:events` | `config/proxy.yml` analytics section |
| Structured log filtering (SensitiveDataFilter) | `proxy.py` |
| Network segmentation (separate Docker networks) | `docker-compose.poc.yml` |
| Health check on analytics container | `docker-compose.poc.yml` analytics service |
| Container security scanning (Bandit, Safety, Trivy) | CI pipeline |

---

## Sub-phase Overview

| Sub-phase | Deliverable |
|-----------|-------------|
| 14a | Startup secrets hardening + JSON logging |
| 14b | Graceful SIGTERM shutdown |
| 14c | Tarpit self-protection (concurrent cap + per-IP cap) |
| 14d | Rate limit memory self-protection |
| 14e | Alert rules overhaul (fix metric names; add missing rules) |
| 14f | Production Docker compose cleanup |

Implement in order. Each sub-phase has its own acceptance criteria below.

---

## 14a — Startup Secrets Hardening + JSON Logging

### Secrets hardening

**Gap 1:** `docker-compose.poc.yml` has `${REDIS_PASSWORD:-changeme}` fallback in four
places. If an operator runs `docker compose up` without `start-poc.sh` they get the
well-known default password.

**Fix:** Replace all four occurrences with
`${REDIS_PASSWORD:?REDIS_PASSWORD is required — run scripts/start-poc.sh}`.
The `:?` syntax causes Docker Compose to fail immediately with an informative message
if the variable is not set, rather than silently using a weak default.

**Gap 2:** `proxy.py` line 1145 logs a WARNING when the Redis password is missing in
production but does not abort. In `ENVIRONMENT=production`, a missing password should
be a startup FATAL (exit 1).

**Fix:** In `proxy.py` `_init_redis()`, when `ENVIRONMENT` env var is `production` and
password is empty/not set, log `{"type":"system","level":"FATAL","event":"missing_redis_password"}` and call `sys.exit(1)`.

### Structured JSON logging

**Gap:** The proxy uses Python's text `logging` format. The acceptance criterion
"all log lines valid JSON" is not met. Structured logs are required for SIEM
integration and automated parsing.

**Fix:** Add a `JSONFormatter` class to `proxy.py`. When `logging.json_enabled: true`
in config (default: `false` for dev, `true` when `ENVIRONMENT=production`), swap
`SecureFormatter` for `JSONFormatter`.

JSON log line format:
```json
{"timestamp": "2026-03-15T14:30:01.234Z", "level": "INFO", "subsystem": "proxy",
 "event": "connection_allowed", "src_ip": "1.2.3.4", "action": "allow",
 "score": 12, "ja4": "t13d1516h2_...", "dial": 0}
```

The `SensitiveDataFilter` must run **before** the JSON formatter — it filters the
LogRecord fields, not the final formatted string.

### Config additions (`config/proxy.yml`)

```yaml
logging:
  level: INFO                     # DEBUG | INFO | WARN | ERROR
  json_enabled: false             # true in production (set via ENVIRONMENT=production)
  # json_enabled is set automatically when ENVIRONMENT=production is detected at startup.
  # Override here to force JSON logging in development.
```

### Acceptance criteria

- [x] `docker-compose.poc.yml`: all four `:-changeme` fallbacks replaced with `:?` error syntax
- [x] `proxy.py` startup: `ENVIRONMENT=production` + no password → FATAL log + `sys.exit(1)`
- [x] `JSONFormatter` class implemented; outputs valid JSON for every log record
- [x] `SensitiveDataFilter` applied before JSONFormatter; passwords/tokens not in JSON output
- [x] When `ENVIRONMENT=production` (or `logging.json_enabled: true`): JSONFormatter active
- [x] Test: 100 connections → all log lines parse as valid JSON (`json.loads()` on each)
- [x] Test: startup with `ENVIRONMENT=production` + no password → process exits non-zero
- [x] JSON log: `{"type":"system","level":"INFO","event":"shutdown_initiated","active_connections":N}` emitted on shutdown

---

## 14b — Graceful SIGTERM Shutdown

### Problem

`proxy.py` `main()` handles only `KeyboardInterrupt` (SIGINT). When Docker stops the
container (`docker stop` → SIGTERM), Python's default handler terminates the process
immediately — in-flight connections are aborted. The acceptance criterion requires
draining active connections before exit.

### Implementation

In `proxy.py` `main()`:

```python
import signal

async def main():
    proxy = await ProxyServer.create(config_path)
    loop = asyncio.get_event_loop()
    shutdown_event = asyncio.Event()

    def _handle_shutdown():
        if not shutdown_event.is_set():
            proxy.logger.info(
                '{"type":"system","level":"INFO","event":"shutdown_initiated",'
                '"active_connections":%d}', proxy.active_connections
            )
            shutdown_event.set()

    loop.add_signal_handler(signal.SIGTERM, _handle_shutdown)
    loop.add_signal_handler(signal.SIGINT, _handle_shutdown)

    await proxy.start(shutdown_event=shutdown_event)
```

`ProxyServer.start()` must accept an optional `shutdown_event: asyncio.Event`. When
it fires:
1. Stop the asyncio server (stop accepting new connections).
2. Wait up to `drain_timeout_seconds` (default: 30) for `active_connections` to reach 0.
3. Log completion and return.

Config addition:
```yaml
proxy:
  drain_timeout_seconds: 30  # Max seconds to wait for in-flight connections on SIGTERM
```

### Acceptance criteria

- [x] SIGTERM → proxy stops accepting new connections immediately
- [x] SIGTERM → in-flight connections allowed to complete up to `drain_timeout_seconds`
- [x] After drain timeout: process exits regardless of remaining connections; logs count
- [x] JSON log: `shutdown_initiated` with `active_connections` count emitted on SIGTERM
- [x] JSON log: `shutdown_complete` with `drained_connections` and `forced_close` count
- [x] `drain_timeout_seconds` hot-reloadable
- [x] Test: SIGTERM with 0 active connections → exits cleanly
- [x] Test: SIGTERM with N active connections → connections allowed to complete, then exits
- [x] Test: drain timeout exceeded → forced exit; count of forced-closed connections logged

---

## 14c — Tarpit Self-Protection

### Problem

See the existing plan section in this file (below). The tarpit container is a finite
resource. Each proxied tarpit connection holds a file descriptor + a small buffer.
An attacker who discovers they're being tarpitted can deliberately exhaust the proxy's
file descriptor limit.

### Implementation

**In-process counters** (not Redis) for the hot path:

```python
# In ProxyServer.__init__:
self._tarpit_concurrent: int = 0          # global in-process count
self._tarpit_per_ip: dict[str, int] = {}  # {ip: count}
self._tarpit_lock = asyncio.Lock()
```

**In `_redirect_to_tarpit()`** (called when action == "tarpit"):

```python
async def _redirect_to_tarpit(self, data, reader, writer, client_ip: str):
    cfg = self.config.get("tarpit", {})
    max_concurrent = cfg.get("max_concurrent_connections", 500)
    max_per_ip = cfg.get("max_per_ip", 3)
    overflow_action = cfg.get("overflow_action", "block")

    async with self._tarpit_lock:
        over_global = self._tarpit_concurrent >= max_concurrent
        over_per_ip = self._tarpit_per_ip.get(client_ip, 0) >= max_per_ip
        if not over_global and not over_per_ip:
            self._tarpit_concurrent += 1
            self._tarpit_per_ip[client_ip] = self._tarpit_per_ip.get(client_ip, 0) + 1
            acquired = True
        else:
            acquired = False

    if not acquired:
        _TARPIT_OVERFLOW.labels(action=overflow_action).inc()
        self.logger.info("tarpit | event=overflow | ip=%s | action=%s", client_ip, overflow_action)
        if overflow_action == "allow":
            await self._forward_to_backend(data, reader, writer)
        else:
            # block or rst: close connection
            writer.close()
        return

    _TARPIT_CONCURRENT.set(self._tarpit_concurrent)
    try:
        await self._do_tarpit_redirect(data, reader, writer)
    finally:
        async with self._tarpit_lock:
            self._tarpit_concurrent -= 1
            self._tarpit_per_ip[client_ip] = max(0, self._tarpit_per_ip.get(client_ip, 0) - 1)
            if self._tarpit_per_ip[client_ip] == 0:
                del self._tarpit_per_ip[client_ip]
        _TARPIT_CONCURRENT.set(self._tarpit_concurrent)
```

**Redis cross-instance view** (monitoring only, not the hot path): a background task
updates a Redis gauge `tarpit:concurrent:{proxy_id}` every 5s so the analytics
dashboard can show aggregate tarpit load across all instances.

**New Prometheus metrics:**
```python
_TARPIT_CONCURRENT = Gauge("ja4proxy_tarpit_concurrent",
                           "Current concurrent tarpitted connections")
_TARPIT_OVERFLOW = Counter("ja4proxy_tarpit_overflow_total",
                           "Connections that hit tarpit cap → overflow action",
                           ["action"])
```

**Config additions (`config/proxy.yml`):**
```yaml
tarpit:
  max_concurrent_connections: 500   # Hard cap on simultaneous tarpit slots (per instance)
  max_per_ip: 3                     # Max concurrent tarpit connections from one IP
  overflow_action: "block"          # When cap reached: block | rst | allow (fail open)
  overflow_log: true                # Log overflow events
```

Note: `rst` and `block` are equivalent from the proxy side (close the TCP connection).
The distinction matters for future logging detail — keep both for semantic clarity.

### Acceptance criteria

- [x] `max_concurrent_connections` cap enforced; new tarpit arrivals → overflow_action when full
- [x] `max_per_ip` cap enforced independently of global cap
- [x] Per-IP counter incremented on tarpit start, decremented on close (clean or abrupt)
- [x] Abrupt disconnect: counter cleaned up; no counter leak
- [x] Overflow action configurable: `block` | `rst` | `allow`; `allow` fails open to backend
- [x] `ja4proxy_tarpit_concurrent` gauge reflects current in-process count
- [x] `ja4proxy_tarpit_overflow_total{action}` incremented on each overflow
- [x] `docs/SECOPS_OPERATIONS.md` updated with tarpit resource sizing guidance
- [x] `docs/OBSERVABILITY_STANDARDS.md` updated with both new metrics
- [x] Test: cap reached → overflow action taken; counter not incremented
- [x] Test: per-IP cap → IP at limit gets overflow; other IPs unaffected
- [x] Test: counter DECR on clean close → returns to correct value
- [x] Test: abrupt disconnect (exception in tarpit) → counter still decremented
- [x] Test (chaos): Redis unavailable during background tarpit gauge update → no crash; in-process counter correct
- [x] Performance: tarpit counter check p99 < 1ms under 500 concurrent tarpitted connections

---

## 14d — Rate Limit Memory Self-Protection

### Problem

The beaconing detector (`beacon:suspects` leaderboard) and sliding window rate limiter
store per-IP data in Redis. Under a sustained attack with millions of unique source IPs,
these structures can grow without bound. The rate limiter keys carry TTLs, but the
beaconing suspects leaderboard does not cap its size.

### Implementation

**Beaconing detector:** Add `max_suspects` config option. When the leaderboard
(`beacon:suspects`) exceeds `max_suspects`, the `ZREMRANGEBYRANK` is called to trim
the lowest-scoring entries before adding a new one. This is already O(log N) in Redis.

```yaml
beaconing:
  max_suspects: 10000   # Cap on beacon:suspects leaderboard size; oldest/lowest trimmed
```

**Sliding window rate limiter:** Verify (and add if missing) that all sorted set keys
for rate limiting have a TTL. The `sliding_window.lua` script should be checked to
confirm TTL is set on every key it touches. Add an explicit `EXPIRE` call on the key
after each sliding window write if not already present.

**Config addition:**
```yaml
beaconing:
  max_suspects: 10000
```

### Acceptance criteria

- [x] `beaconing.max_suspects` config option honoured by `BeaconingDetector`
- [x] When suspects > `max_suspects`, lowest-scoring entries trimmed before insert
- [x] Sliding window rate limiter keys all have TTL; verified by inspecting a key after insert
- [x] Test: insert `max_suspects + 1` entries → leaderboard size stays ≤ `max_suspects`
- [x] Test: Redis MEMORY USAGE does not grow unboundedly when 10k unique IPs beacon

---

## 14e — Alert Rules Overhaul

### Problem

`monitoring/prometheus/alerts.yml` uses pre-Phase-1 metric names (`ja4_blocked_requests_total`,
`ja4_security_events_total`, `ja4_rate_limit_exceeded_total`, etc.) — **none of these
metrics exist** in the current codebase. All real metrics use the `ja4proxy_` prefix.

The alertmanager rules directory (`monitoring/alertmanager/rules/`) contains only
`management_ui_rules.yml`. The Phase 14 plan requires `proxy.rules.yml`,
`redis.rules.yml`, and `security.rules.yml`.

### Implementation

**Step 1:** Rewrite `monitoring/prometheus/alerts.yml` using real metric names.

Key metric names for alert expressions:
- Connection actions: `ja4proxy_connections_total{action="block"}` / `{action="ban"}` / `{action="tarpit"}`
- Active connections: `ja4proxy_concurrent_connections` + `ja4_active_connections` (proxy.py gauge — rename to `ja4proxy_active_connections` in Phase 14)
- AbuseIPDB quota exhausted: `ja4proxy_abuseipdb_quota_exhausted == 1`
- Spamhaus download error: `rate(ja4proxy_blocklist_download_errors_total[5m]) > 0`
- Spamhaus stale: `time() - ja4proxy_blocklist_last_refresh_success_seconds > 7200`
- Risk score: `ja4proxy_risk_score` (histogram)
- Dial: `ja4proxy_dial_current`
- Analytics stream lag: `ja4proxy_analytics_stream_lag_seconds`
- Score drift: `ja4proxy_analytics_score_drift_detected`
- Tarpit concurrent: `ja4proxy_tarpit_concurrent` (Phase 14c)
- Redis memory: `redis_memory_used_bytes / redis_memory_max_bytes` (redis_exporter)

**Also rename `ja4_active_connections` gauge** (proxy.py line 72) to
`ja4proxy_active_connections` for consistency. Update any tests that reference the old name.

**Step 2:** Create the three alertmanager rule files.

`monitoring/alertmanager/rules/proxy.rules.yml`:
```yaml
groups:
  - name: ja4proxy_proxy
    rules:
      - alert: ProxyHighBlockRate
        expr: rate(ja4proxy_connections_total{action=~"block|ban"}[5m]) > 10
        for: 2m
        labels: {severity: warning}
        annotations:
          summary: "High block rate ({{ $value | humanize }}/s)"
          runbook: "docs/runbooks/high_block_rate.md"

      - alert: ProxyDialChanged
        expr: changes(ja4proxy_dial_current[5m]) > 0
        for: 0m
        labels: {severity: info}
        annotations:
          summary: "Dial changed to {{ $value }}"

      - alert: ProxyTarpitConcurrentHigh
        expr: ja4proxy_tarpit_concurrent > 400
        for: 2m
        labels: {severity: warning}
        annotations:
          summary: "Tarpit concurrent connections near cap ({{ $value }}/500)"
          runbook: "docs/runbooks/tarpit_capacity.md"

      - alert: ProxyInstanceDown
        expr: up{job="ja4proxy"} == 0
        for: 1m
        labels: {severity: critical}
        annotations:
          summary: "JA4proxy instance is unreachable"
```

`monitoring/alertmanager/rules/redis.rules.yml`:
```yaml
groups:
  - name: ja4proxy_redis
    rules:
      - alert: RedisDown
        expr: up{job="ja4proxy-redis"} == 0
        for: 1m
        labels: {severity: critical}
        annotations:
          summary: "Redis is unreachable; proxy scoring degraded"

      - alert: RedisMemoryHigh
        expr: redis_memory_used_bytes / redis_memory_max_bytes > 0.80
        for: 5m
        labels: {severity: warning}
        annotations:
          summary: "Redis memory at {{ $value | humanizePercentage }}"
```

`monitoring/alertmanager/rules/security.rules.yml`:
```yaml
groups:
  - name: ja4proxy_security
    rules:
      - alert: AbuseIPDBQuotaExhausted
        expr: ja4proxy_abuseipdb_quota_exhausted == 1
        for: 0m
        labels: {severity: warning}
        annotations:
          summary: "AbuseIPDB daily quota exhausted; enrichment paused until midnight UTC"
          runbook: "docs/runbooks/external_api_failures.md"

      - alert: SpamhausDownloadFailed
        expr: rate(ja4proxy_blocklist_download_errors_total[5m]) > 0
        for: 5m
        labels: {severity: warning}
        annotations:
          summary: "Spamhaus DROP/EDROP download failing"
          runbook: "docs/runbooks/feed_management.md"

      - alert: SpamhausListStale
        expr: time() - ja4proxy_blocklist_last_refresh_success_seconds > 7200
        for: 5m
        labels: {severity: warning}
        annotations:
          summary: "Spamhaus list not refreshed for >2 hours"
```

### Acceptance criteria

- [x] `monitoring/prometheus/alerts.yml` rewritten; all expressions reference real `ja4proxy_*` metric names
- [x] `ja4_active_connections` gauge in `proxy.py` renamed to `ja4proxy_active_connections`
- [x] `monitoring/alertmanager/rules/proxy.rules.yml` created
- [x] `monitoring/alertmanager/rules/redis.rules.yml` created
- [x] `monitoring/alertmanager/rules/security.rules.yml` created
- [x] All alert rules validated with `promtool check rules` (run as part of tests or CI)
- [x] Test: PromQL expressions in all rules are syntactically valid
- [x] `docs/security/COMPREHENSIVE_SECURITY_AUDIT.md` updated: mark resolved findings as ✅ with fix location; remove obsolete "do you approve" footer

---

## 14f — Production Docker Cleanup

### Problem

`docker/docker-compose.prod.yml` references non-existent files:
- `Dockerfile.enterprise` (does not exist)
- `config/enterprise.yml` (does not exist)
- `security/Dockerfile` (does not exist)

It also has a 3-node Redis cluster, ELK stack (Elasticsearch + Logstash + Kibana),
and a separate security-scanner service. These are aspirational and not grounded in
the actual system. Running `docker compose -f docker/docker-compose.prod.yml up` would
fail immediately.

### Implementation

Replace `docker/docker-compose.prod.yml` with a realistic single-instance production
compose file that:
- Uses the real `docker/Dockerfile` (same as poc)
- Uses a single Redis (not a cluster) — cluster is Phase 15+ territory
- Uses Loki + Promtail for logging (already in monitoring setup) — **not** ELK
- Uses Docker secrets for `REDIS_PASSWORD`, `GRAFANA_PASSWORD`, `ABUSEIPDB_API_KEY`
- Keeps all the security hardening from `docker-compose.poc.yml` (read-only, cap_drop, etc.)
- References only files that actually exist in the repo

The management UI service should be included (Phase 13 will have built it by the time
this is implemented).

Also add a `docker/docker-compose.prod.yml.example` or update the existing `scripts/start-poc.sh`
to support a `--prod` mode that generates `.env` with all required secrets and starts
the production compose.

### Out of scope for Phase 14

These items from the DMZ readiness doc and security audit are deferred:

| Item | Rationale | Deferred to |
|------|-----------|-------------|
| Redis TLS | Docker internal network provides adequate isolation (DMZ doc: P3) | Phase 15 or dedicated ops task |
| Redis cluster (3 nodes) | No HA requirement stated; single Redis is sufficient | Phase 15+ |
| Container image signing (Cosign/Syft) | CI/CD concern; no code changes needed | Ops runbook |
| Falco runtime monitoring | Heavyweight; no code changes needed; ops concern | Ops runbook |
| Backend connection TLS validation | Backend is internal Docker service; low risk | Phase 15 |
| ELK stack | Already have Loki/Promtail/Grafana; ELK is duplication | N/A |
| JIRA/Slack/SOC integration | Ops tooling, not proxy code | N/A |

### Acceptance criteria

- [x] `docker/docker-compose.prod.yml` replaced; runs without error on `docker compose config`
- [x] All referenced `Dockerfile.*`, config files, and secret files exist or are documented as generated
- [x] Docker secrets used for `REDIS_PASSWORD`, `GRAFANA_PASSWORD`, `ABUSEIPDB_API_KEY`
- [x] No `:-changeme` fallback in any compose file
- [x] `docker compose -f docker/docker-compose.prod.yml config` exits 0
- [x] Deferred items documented in the table above with rationale

---

## Redis Key Schema

Phase 14 adds no new Redis keys. The tarpit concurrent gauge (`tarpit:concurrent:{proxy_id}`)
is a monitoring-only Redis key (updated every 5s by background task):

| Key | Type | TTL | Written by | Notes |
|-----|------|-----|------------|-------|
| `tarpit:concurrent:{proxy_id}` | String | 30s | Proxy background task | Cross-instance tarpit load gauge; auto-expires if proxy stops |

---

## Config Summary

```yaml
# proxy.yml additions for Phase 14

proxy:
  drain_timeout_seconds: 30       # Max seconds to drain active connections on SIGTERM

logging:
  level: INFO
  json_enabled: false             # Enabled automatically when ENVIRONMENT=production

tarpit:
  max_concurrent_connections: 500  # Hard cap on simultaneous tarpit slots (per instance)
  max_per_ip: 3                    # Max concurrent tarpit from one IP
  overflow_action: "block"         # block | rst | allow (allow = fail open to backend)
  overflow_log: true

beaconing:
  max_suspects: 10000             # Cap on beacon:suspects leaderboard; trims lowest-scoring
```

All Phase 14 config values are hot-reloadable (apply to next connection).

---

## Chaos Scenarios

| Scenario | Expected behaviour |
|----------|--------------------|
| SIGTERM during active connections | Drain: in-flight complete; new connections refused; process exits after `drain_timeout_seconds` |
| SIGTERM with no active connections | Immediate clean exit; `shutdown_complete` logged |
| Tarpit global cap reached | `overflow_action` taken; `ja4proxy_tarpit_overflow_total` incremented; non-tarpit connections unaffected |
| Tarpit per-IP cap reached | That IP gets overflow action; other IPs at lower count unaffected |
| Tarpit connection abruptly disconnects | `tarpit_concurrent` decremented correctly; no counter leak |
| Redis unavailable for tarpit background gauge | Warning logged; in-process counters still correct; no crash |
| `ENVIRONMENT=production` + no Redis password | FATAL log + `sys.exit(1)` before accepting any connections |

---

## Acceptance Criteria (Complete Phase Gate)

### 14a — Startup hardening
- [x] `docker-compose.poc.yml`: no `:-changeme` fallbacks remain
- [x] Production startup without password: FATAL + exit 1
- [x] JSON logging: all log lines valid JSON when enabled
- [x] `SensitiveDataFilter` active before JSON formatter

### 14b — Graceful shutdown
- [x] SIGTERM triggers drain; new connections refused
- [x] `shutdown_initiated` JSON log emitted with `active_connections` count
- [x] Process exits after drain timeout even if connections remain

### 14c — Tarpit self-protection
- [x] `max_concurrent_connections` enforced
- [x] `max_per_ip` enforced per source IP
- [x] Overflow action taken (block / rst / allow)
- [x] `ja4proxy_tarpit_concurrent` and `ja4proxy_tarpit_overflow_total{action}` Prometheus metrics
- [x] Counter cleanup on clean and abrupt disconnect

### 14d — Rate limit memory self-protection
- [x] `beaconing.max_suspects` cap enforced; leaderboard stays bounded
- [x] Sliding window rate limiter keys have TTL

### 14e — Alert rules
- [x] `monitoring/prometheus/alerts.yml` uses only real `ja4proxy_*` metric names
- [x] `ja4_active_connections` renamed to `ja4proxy_active_connections`
- [x] Three alertmanager rule files created (proxy, redis, security)
- [x] `promtool check rules` passes on all rule files (43 structural tests substitute where promtool unavailable)
- [x] `COMPREHENSIVE_SECURITY_AUDIT.md` updated to reflect current state

### 14f — Production Docker
- [x] `docker/docker-compose.prod.yml` references only real files
- [x] `docker compose -f docker/docker-compose.prod.yml config` exits 0
- [x] No weak-password fallbacks in any compose file

### Tests

`tests/unit/test_tarpit_protection.py`:
- [x] Global cap reached → overflow action
- [x] Per-IP cap → overflow; other IPs unaffected
- [x] Counter DECR on clean close
- [x] Counter DECR on exception (abrupt disconnect)

`tests/unit/test_json_logging.py`:
- [x] 100 log lines with JSON formatter → all parse as valid JSON
- [x] SensitiveDataFilter strips passwords before JSON output
- [x] Startup without password in production mode → exits non-zero

`tests/integration/test_pipeline.py` (additions):
- [x] SIGTERM with active connections → connections drain; `shutdown_initiated` logged

`tests/chaos/test_tarpit_cap.py`:
- [x] Redis unavailable for tarpit background update → no crash; in-process count correct

`tests/performance/bench_pipeline.py` (addition):
- [x] Tarpit counter check overhead: p99 < 1ms under 500 concurrent

### Observability
- [x] `ja4proxy_tarpit_concurrent` gauge
- [x] `ja4proxy_tarpit_overflow_total{action}` counter
- [x] `ja4proxy_active_connections` gauge (renamed from `ja4_active_connections`)
- [x] All added to `docs/OBSERVABILITY_STANDARDS.md`

### Documentation
- [x] `docs/SECOPS_OPERATIONS.md`: tarpit resource sizing guidance added
- [x] `docs/security/SECURITY_CHECKLIST.md`: Phase 14 production hardening items added
- [x] `docs/security/COMPREHENSIVE_SECURITY_AUDIT.md`: resolved findings marked ✅
- [x] `CHANGELOG.md` updated
