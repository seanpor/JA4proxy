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
