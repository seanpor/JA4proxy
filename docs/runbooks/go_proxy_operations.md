<!--
title: Go_Proxy_Operations
audience: Operators, Security Teams
last_reviewed: 2026-03-27
phase: 21
-->

# Go Proxy Operations Runbook

## Overview

Day-to-day operations guidance for running the Go proxy in production.

## GC Tuning

The Go proxy uses mark-and-sweep GC. Default settings work well up to ~5,000 conn/s.
For higher loads, tune the GC target:

```bash
# Set GC target to 200% (reduces GC frequency at cost of higher peak memory)
GOGC=200 bin/ja4proxy

# Or in Docker:
environment:
  GOGC: "200"
```

GC pause targets:
- At 1,000 conn/s sustained: p99 GC pause < 1ms
- At 5,000 conn/s sustained: p99 GC pause < 5ms
- At 10,000 conn/s sustained: p99 GC pause < 10ms

Monitor GC pauses via Prometheus: `go_gc_duration_seconds{quantile="0.99"}`

## Memory Tuning

The Go runtime defaults to returning memory to the OS aggressively. If you see
excessive page faults under bursty traffic, set:

```bash
GOMEMLIMIT=512MiB bin/ja4proxy
```

## Goroutine Leak Detection

If `go_goroutines` grows unboundedly, there may be a goroutine leak.
Dump goroutine stacks:

```bash
curl http://localhost:9090/debug/pprof/goroutine?debug=1
```

Normal goroutine count at idle: ~10-20 (main loop + background workers + per-connection).

## Log Levels

Change at runtime via config reload (SIGHUP):

```yaml
logging:
  level: DEBUG  # or INFO, WARN, ERROR
```

## Health Check

```bash
curl http://localhost:9090/health
# OK: {"redis":"ok","status":"ok"}
# Degraded: {"redis":"error","status":"degraded"} — 503
```

## Config Hot Reload

```bash
# Via SIGHUP:
kill -HUP $(cat server.pid)

# Via Redis pub/sub (Python management UI or CLI):
redis-cli publish config:reload "reload"
```

## Metrics Reference

| Metric | Description |
|--------|-------------|
| `ja4proxy_connections_total{action}` | Cumulative connections by decision |
| `ja4proxy_active_connections` | Current in-flight connections |
| `ja4proxy_risk_score_distribution` | Risk score histogram |
| `ja4proxy_dial_setting` | Current dial value |
| `ja4proxy_bypass_hits_total{reason}` | Bypass short-circuit hits |
| `ja4proxy_signal_total{signal}` | Individual signal firing counts |
| `ja4proxy_config_reloads_total` | Number of config reloads |

## Common Operational Tasks

### Raise the dial (increase blocking aggressiveness)

```bash
redis-cli set config:dial 50
redis-cli publish config:dial:change "50"
```

### Emergency block an IP

```bash
# Add to blocklist file, then reload
echo "1.2.3.4/32" >> config/blocklists/emergency.txt
kill -HUP $(cat server.pid)
```

### Check current signal firing rates

```bash
curl -s http://localhost:9090/metrics | grep ja4proxy_signal_total
```

## Alert: `ja4proxy_redis_health{status="error"}`

Raised by the Phase-201c health-check goroutine when the Go proxy's periodic
`PING` to Redis fails. The proxy remains up and serves traffic from local
cache (fail-open); this is a degradation alert, not an outage alert.

**Response (four-step):**

1. **Is Redis up?**
   ```bash
   docker ps | grep redis
   redis-cli -h <redis-host> -p <port> PING   # expect PONG
   ```
2. **TLS misconfigured?** If `redis.ssl: true` is set, check startup logs for
   a `redis: TLS ping failed` ERROR line:
   ```bash
   journalctl -u ja4proxy | grep -E "TLS ping failed|redis: dial options"
   ```
   The `redis: dial options configured` line at startup shows `ssl=true|false`
   and `username=true|false` as Booleans (password is never logged).
3. **Is the proxy still serving?** Check `ja4proxy_connections_total` is still
   incrementing. If yes, fail-open is working — no emergency; fix Redis at
   normal priority.
4. **Force a Lua-script reload** after Redis recovers: no hot-reload endpoint
   exists in this phase. The next successful 30-second health tick will call
   `loadScripts` automatically and increment
   `ja4proxy_redis_script_reloads_total{result="ok"}`. If a faster reload is
   required, restart the proxy.

Verified against the Phase 201 implementation:

- Startup log line (Info): `redis: dial options configured` with fields
  `ssl` and `username` as Booleans.
- TLS failure log line (Error, fail-open): `redis: TLS ping failed; continuing fail-open`.
- Health-check failure log line (Warn): `redis: health check ping failed`.
- Metric labels: `ja4proxy_redis_health{status="ok"|"error"}`,
  `ja4proxy_redis_script_reloads_total{result="ok"|"error"}`.

## Phase 203 — Signal additions

Phase 203 adds five defensive-parity signals to the Go proxy (203a–e). Only
the two that affect operational behaviour are documented here; the rest
(`ja4_tls_mismatch`, weak-cipher parity, DGA algorithm re-port) are internal
detection changes with no new runbook surface.

### JA4T-OS-mismatch (203a)

The `tap_os_mismatch` signal fires when the OS class implied by a client's
JA4 TLS fingerprint disagrees with the OS class observed by the Phase 20
TAP node from the client's TCP SYN packet. The Go proxy **does not compute
JA4T itself** (architecturally impossible from an `accept()`'d socket — see
[ADR-203a](../decisions/ADR-203a.md)); it reads the Phase-20 TAP node's
fingerprint from Redis (`fp:os:ip:{ip}`) and compares.

**Enabling requires the Phase 20 TAP node deployed alongside this proxy,
writing to the same Redis instance.** Without a TAP node, every lookup
misses and no signal is emitted — the proxy continues to function exactly
as before. Setting `tap_consumer.enabled: true` in `config/proxy.yml`
without a deployed TAP node is a no-op, not an error.

Configuration (see `config/proxy.yml` `tap_consumer:` block):

| Key | Default | Purpose |
|---|---|---|
| `enabled` | `false` | Master switch. Leave `false` unless Phase 20 TAP is deployed. |
| `signal_score` | `30` | Score added to RiskScorer when a mismatch is detected (matches `signal_scores.yml`). |
| `redis_timeout_ms` | `50` | Hot-path timeout on the `GET fp:os:ip:{ip}` lookup; fail open on timeout. |
| `cache_ttl_seconds` | `60` | `LocalCache` TTL for per-IP lookup results; bounds the Redis QPS. |
| `max_age_seconds` | `300` | Discard TAP fingerprints older than this (stale entries → no signal, never a false positive from old data). |

**Operational prereq:** the Phase 20 TAP node must be deployed and writing
`fp:os:ip:{ip}` to the same Redis instance this proxy reads from. Without
it, every lookup misses and the signal is silently dormant.

Metrics:

- `ja4proxy_tap_lookups_total{result="hit_match|hit_mismatch|miss|error"}`
- `ja4proxy_tap_signal_total{action="flag|rate_limit|tarpit|block|ban"}`

How to verify it's working:

```bash
# After deploying TAP + enabling tap_consumer, drive some traffic, then:
curl -s http://localhost:9090/metrics | grep ja4proxy_tap_lookups_total
# Expect non-zero on at least hit_match or hit_mismatch once TAP has
# written fp:os:ip entries for the client IPs you observe.
redis-cli KEYS 'fp:os:ip:*' | head   # TAP-writer smoke check
```

Troubleshooting:

| Symptom | Likely cause | Action |
|---|---|---|
| Signal never fires despite `enabled: true` | Phase 20 TAP node not deployed or not writing to this Redis | `redis-cli KEYS 'fp:os:ip:*' \| head` — empty = TAP absent; confirm TAP DSN matches proxy DSN |
| `tap_lookups_total{result="miss"}` is the only non-zero label | TAP not deployed, OR IP canonical-form mismatch (IPv4-mapped IPv6, zone IDs) between TAP and proxy | Confirm TAP key population; check proxy client-IP normalisation for your ingress shape |
| `tap_lookups_total{result="error"}` climbing | Redis timeout (> `redis_timeout_ms`) or transport error | Check Redis latency; fail-open is preserved (no block risk), but raise `redis_timeout_ms` or investigate Redis capacity |
| Signal fires unexpectedly at high volume | NAT churn (multiple real clients behind one IP) | Widen `cache_ttl_seconds`, or reduce `max_age_seconds` to discard stale TAP entries sooner |

### Health endpoint shape (203e)

Phase 203e extends `/health/deep` (not `/health` — which remains the tight
k8s-liveness probe) with component checks and N=3 anti-flap hysteresis.
The N=3 threshold lives in `internal/health.Config.FailThreshold` and is
applied per component.

**HTTP status codes:**

| Condition | Status code | Body `status` |
|---|---|---|
| All healthy | 200 | `"ok"` |
| Redis transient failure (< 3 consecutive) | 200 | `"degraded"` |
| Redis unhealthy (≥ 3 consecutive failures) | **503** | `"error"` |
| Redis latency > 50 ms | 200 | `"degraded"` |
| Tarpit saturated (`active >= max`) | **200** | `"degraded"` |

Tarpit saturation is intentionally **not** 503: the proxy is still accepting
traffic on its fast path, and flapping an LB out under slow-path load would
make things worse. Redis unhealthy **is** 503 because local cache cannot
carry an indefinitely-cut-off proxy.

**Time-to-detect** a real Redis failure on `/health/deep` is
`3 × probe_interval` due to N=3 anti-flap — tune probe cadence
accordingly (e.g. a 5 s probe interval ⇒ ~15 s detection).

**GeoIP is presence-only.** `geoip.present: true` iff the Go proxy loaded a
MaxMind reader at startup; `geoip.status` is `"ok"` when present. The
reader is not actively probed on the hot path (that would be a syscall
storm); a future revision may add active probing with its own anti-flap.

**Response body shape** (produced by `handleHealthDeep` in
`cmd/proxy/main.go`):

```json
{
  "status": "ok",
  "redis_connected": true,
  "redis_latency_ms": 0.42,
  "dial": 0,
  "active_connections": 3,
  "connections_total": 12847,
  "block_rate_pct": 0.18,
  "active_bans": 4,
  "tarpit": { "active": 0, "max": 256, "status": "ok" },
  "geoip": { "present": true, "status": "ok" },
  "cert_days_remaining": 74.3
}
```

`cert_days_remaining` is `null` when no TLS certificate expiry metric is
exposed (e.g. a build without TLS terminating listeners).


