<!--
title: Go_Proxy_Migration
audience: Operators, Security Teams
last_reviewed: 2026-03-27
phase: 21
-->

# Go Proxy Migration Runbook

## Overview

This runbook covers the procedure for migrating from the Python proxy (`proxy.py`)
to the Go proxy (`cmd/proxy/`) in production. The migration is designed to be
zero-downtime via HAProxy upstream switching.

## Prerequisites

- Go proxy built and tested: `GOROOT=/snap/go/current go build -o bin/ja4proxy ./cmd/proxy`
- Docker image built: `docker build -f deploy/docker/Dockerfile.go-proxy -t ja4proxy-go:latest .`
- Both proxies can share the same Redis instance (key schema unchanged)
- Parallel validation complete: Go proxy running on port 8082, Python on 8080

## Step-by-Step Cutover

### Phase 1: Parallel Validation (Recommended: 48h minimum)

1. Start the Go proxy (it is now the default service in poc.yml):
   ```bash
   docker compose -f deploy/docker/docker-compose.poc.yml up -d proxy
   ```

2. Verify Go proxy health:
   ```bash
   curl http://localhost:9092/health
   # Expected: {"redis":"ok","status":"ok"}
   ```

3. Verify metrics are being published:
   ```bash
   curl -s http://localhost:9092/metrics | grep ja4proxy_connections_total
   ```

4. Run integration tests:
   ```bash
   python3 -m pytest tests/integration/test_go_python_parity.py -v
   ```

5. Monitor both proxies in Grafana for 48 hours. Compare:
   - Decision parity (allow/block/tarpit rates should match within 5%)
   - Score distributions
   - Signal firing rates

### Phase 2: Traffic Switch (HAProxy)

1. Update HAProxy config to route to Go proxy:
   ```haproxy
   backend ja4proxy
       server go-proxy ja4proxy-go:8080 check
       # server python-proxy ja4proxy:8080 check backup
   ```

2. Reload HAProxy:
   ```bash
   docker exec haproxy haproxy -sf $(cat /var/run/haproxy.pid)
   ```

3. Monitor for 15 minutes. Verify:
   - Error rate < 0.1%
   - P99 latency < previous baseline
   - No goroutine panics in Go proxy logs

### Phase 3: Cleanup

1. After 7 days of stable operation, decommission Python proxy workers.
2. Remove `backup` server entry from HAProxy config.

## Rollback Procedure

If issues are detected, rollback takes < 30 seconds:

1. Restore HAProxy config to Python proxy:
   ```haproxy
   backend ja4proxy
       server python-proxy ja4proxy:8080 check
   ```

2. Reload HAProxy:
   ```bash
   docker exec haproxy haproxy -sf $(cat /var/run/haproxy.pid)
   ```

3. Investigate Go proxy issue (goroutine stacks, logs).

## Key Differences from Python Proxy

| Feature | Python | Go |
|---------|--------|-----|
| GC | Reference counting | Mark-and-sweep (sub-ms GC pauses) |
| Concurrency | asyncio single-thread | Goroutines (multi-core) |
| Signal modules | All in Python | All ported to Go |
| Analytics | Python (stays Python) | N/A |
| Config hot-reload | SIGHUP + pub/sub | SIGHUP + pub/sub (same) |
| Redis schema | Shared | Shared |

## Monitoring During Cutover

Key Grafana panels to watch:
- `ja4proxy_connections_total` by action (should match Python rates)
- `ja4proxy_risk_score_distribution` (should match Python distribution)
- `ja4proxy_active_connections` (should be bounded)
- Go runtime metrics: `go_goroutines`, `go_gc_duration_seconds`
