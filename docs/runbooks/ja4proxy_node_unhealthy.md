<!--
title: "ja4proxy node unhealthy Runbook"
audience: oncall, sre
last_reviewed: 2026-04-10
phase: 86
-->

# Runbook: ja4proxy_node_unhealthy

## Severity
WARNING (status=degraded) → CRITICAL (status=error)

## What is happening
A JA4proxy node has reported unhealthy status via `/api/v1/health/deep`.
A degraded node may have elevated Redis latency; an error node has lost
Redis connectivity entirely.

## Impact
- **High (error):** Redis is unreachable. The proxy operates in fail-open
  mode — all connections are allowed without ban enforcement, rate
  limiting, or behavioural analysis.
- **Low (degraded):** Redis latency is elevated (>50ms). Pipeline decisions
  are slower but still functional.

## Diagnosis
1. Check Management UI → Nodes page for the affected node's status.
2. `curl -sf http://<node>:8090/api/v1/health/deep | python3 -m json.tool`
3. Check Redis connectivity:
   ```bash
   redis-cli -h <redis-host> -p 6379 PING
   ```
4. Check proxy logs for Redis connection errors:
   ```bash
   docker compose -f deploy/docker/docker-compose.poc.yml logs proxy | grep -i redis | tail -20
   ```
5. Check Redis container/host health:
   ```bash
   docker compose -f deploy/docker/docker-compose.poc.yml ps redis
   ```

## Resolution
**If Redis is down:**
1. Restart Redis: `docker compose -f deploy/docker/docker-compose.poc.yml restart redis`
2. Verify proxy reconnects: check `/health/deep` shows `redis_connected: true`
3. If Redis doesn't restart, check disk space and logs.

**If network partition:**
1. Verify connectivity between proxy and Redis:
   ```bash
   docker compose -f deploy/docker/docker-compose.poc.yml exec proxy nc -zv <redis-host> 6379
   ```
2. Check for firewall changes or VPC routing issues.

**If Redis is slow (degraded):**
1. Check Redis memory usage: `redis-cli INFO memory`
2. Check for slow queries: `redis-cli SLOWLOG GET 10`
3. Consider scaling Redis or reducing key count.

## Escalation
Page SecOps lead if node remains in error state for >5 minutes.
Page Platform Engineering if Redis cluster is affected.
