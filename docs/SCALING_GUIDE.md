<!--
title: Scaling Guide
audience: Operators, DevOps
last_reviewed: 2026-04-03
phase: 26
-->

# JA4Proxy Multi-Process Scaling Guide (Phase 26d)

## Overview

> **⚠ Pending rewrite (phase-309 WP-5).** This guide models the legacy
> **Python multi-worker** architecture (per-process workers, the GIL bottleneck,
> ~350 conn/s per process). The production runtime is now the **single, stateless
> Go binary** (`ja4pd`), which scales by **adding nodes**, not worker processes —
> a single instance sustains ~3,000 conn/s host-native (see
> `docs/performance/benchmarks.md`). Treat the per-process math below as historical
> until this guide is rewritten for the Go architecture.

This guide explains how to scale JA4Proxy using multiple worker processes to achieve higher throughput while maintaining all security guarantees.

## Architecture

```
Internet → HAProxy:443 (Round-Robin) → [Worker 1:8080, Worker 2:8083, Worker 3:8084, Worker 4:8085]
                                      ↓
                                  Redis:6379 (Shared State)
```

### Key Components

1. **HAProxy**: TCP load balancer that distributes connections across workers
2. **Worker Processes**: Independent JA4Proxy instances (4 recommended for i9-9900K)
3. **Redis**: Shared state backend (rate limits, bans, fingerprints, etc.)
4. **Shared Configuration**: All workers use the same Redis backend

## Quick Start

### 1. Start Scaled Configuration

```bash
make start-scaled
```

This will:
- Start 4 worker processes on ports 8080, 8083, 8084, 8085
- Start HAProxy load balancer on port 443
- All workers share the same Redis backend

### 2. Verify Scaling

```bash
# Check HAProxy stats
curl http://admin:admin123@localhost:8404/stats

# Check worker logs
docker logs ja4proxy_worker_1
docker logs ja4proxy_worker_2

# Check overall status
make status
```

## Configuration

### Worker Count and max_per_ip Adjustment

The `max_per_ip` setting controls how many concurrent tarpit connections are allowed from a single IP **per worker**. To maintain the global semantic of "max 3 concurrent tarpit connections per IP across all workers", adjust `max_per_ip` based on worker count:

| Workers | max_per_ip | Formula |
|---------|------------|----------|
| 1 | 3 | ceil(3/1) = 3 |
| 2 | 2 | ceil(3/2) = 2 |
| 3 | 1 | ceil(3/3) = 1 |
| 4 | 1 | ceil(3/4) = 1 |
| 8 | 1 | ceil(3/8) = 1 |

**Example configuration for 4 workers:**

```yaml
# config/proxy.yml
tarpit:
  worker_count: 4
  max_per_ip: 1  # Adjusted for 4 workers
  max_concurrent_connections: 500
  overflow_action: "block"
```

### HAProxy Configuration

The HAProxy configuration is in `config/haproxy.cfg`:

- **Port 443**: Main TLS frontend (accepts PROXY protocol)
- **Port 8404**: Stats endpoint (admin/admin123)
- **Load balancing**: Round-robin across all healthy workers
- **Health checks**: TCP checks every 2 seconds
- **Emergency fallback**: Routes to worker 1 if all others fail

### Docker Compose Scale Overlay

The scale configuration is in `deploy/docker/docker-compose.scale.yml`:

- 4 worker services (proxy-worker-1 through proxy-worker-4)
- Each worker has its own port and WORKER_ID
- HAProxy service with health checks
- Shared network for all services

## Performance Characteristics

### Expected Throughput

| Configuration | Expected conn/s | Notes |
|--------------|----------------|-------|
| Single process (baseline) | ~250–300 | Original baseline |
| After 26a+26b+26c+26e (single) | ~700–950 | With optimizations |
| 2 workers | ~1,400–1,900 | Linear scaling |
| 4 workers | ~2,800–3,800 | Optimal for i9-9900K |
| 8 workers | ~5,600–7,600 | Upper bound on this hardware |

### Resource Usage

| Workers | CPU Cores | Memory | Redis Connections |
|---------|-----------|---------|-------------------|
| 1 | 1 | ~500MB | 1 |
| 2 | 2 | ~900MB | 2 |
| 4 | 4 | ~1.7GB | 4 |
| 8 | 8 | ~3.3GB | 8 |

## Worked Scenarios

> **Production runtime is the Go proxy daemon (`ja4pd`).** All legacy Python
> prototyping components (such as `proxy.py`) have been archived and removed.
> Sizing and capacity guidelines for the Go runtime are documented in the
> central [Operations Guide](OPERATIONS_GUIDE.md#📈-capacity-&-scaling-go-proxy).

The three scenarios below illustrate end-to-end sizing for representative
deployments. All scenarios assume:

- Backend HTTPS server reachable from every proxy node.
- HAProxy in front of the proxy fleet, configured per
  [`docs/runbooks/rolling_upgrade.md`](runbooks/rolling_upgrade.md) §1.
- Redis available with persistence (AOF) and authentication.
- Prometheus scraping `/metrics` from every node.

### Scenario A — Small site (~100 req/s)

Single-marketing-site / small-SaaS use case. Modest traffic; a few brief
spikes per day. Cost-sensitive.

| Item | Value | Source |
|------|-------|--------|
| Target sustained throughput | 100 conn/s | Requirement |
| Peak (2× headroom) | 200 conn/s | (estimate, standard 2× headroom rule) |
| Proxy instances | 2 (HA pair) | Required by `rolling_upgrade.md` §1 (≥2 instances for zero-downtime upgrades) |
| Per-instance load at steady state | ~100 conn/s | 200 ÷ 2 instances |
| Per-instance ceiling (Python) | ~350 conn/s with real Redis | BENCHMARK_HISTORY 2026-03-07 |
| Headroom per instance | ~250 conn/s (~70%) | Derived from above |
| Redis sizing | 1 node, 256 MB max-memory, AOF on | (estimate; ban+rate-limit+HLL key set < 50 MB at this volume) |
| Recommended dial progression | 0 → 25 → 50 over 14 days, observe FP rate at each step | `OPERATIONS_GUIDE.md` |
| Monitoring thresholds | `ja4proxy_active_connections` > 200 sustained → investigate; `ja4proxy_redis_errors_total` rate > 0 → page | `OPERATIONS_GUIDE.md#📊-viewing-logs-&-assets` |

**Notes for this scenario:**
- A single instance would meet the throughput requirement but cannot satisfy
  the zero-downtime-upgrade prerequisite. Run two.
- `tarpit.max_per_ip` should remain at default (3) — only one instance
  serves a given client at a time at this scale, so global semantics hold
  without per-worker adjustment.

### Scenario B — Enterprise (~2,000 req/s)

Large internal application or mid-market e-commerce. Steady business-hour
traffic; predictable spikes. Operates on real hardware or sized cloud VMs.

| Item | Value | Source |
|------|-------|--------|
| Target sustained throughput | 2,000 conn/s | Requirement |
| Peak (2× headroom) | 4,000 conn/s | (estimate, 2× headroom rule) |
| Per-process throughput (single Python proxy with Redis) | ~350 conn/s | BENCHMARK_HISTORY 2026-03-07 |
| Required Python-process count to hit peak | 4,000 ÷ 350 ≈ **12 worker processes** | Derived |
| Recommended deployment | 3 nodes × 4-worker scaled config (`make start-scaled`) | This doc, "Resource Usage" table (4 workers ≈ 2,800–3,800 conn/s per node) |
| Per-node expected throughput | ~2,800–3,800 conn/s | This doc, "Expected Throughput" table |
| Per-node CPU / memory | 4 cores, ~1.7 GB | This doc, "Resource Usage" table |
| Redis sizing | 1 primary + 1 replica, 2 GB max-memory, AOF on, persistence to fast SSD | (estimate; ban + HLL + rate-limit volumes scale linearly with unique-IP count) |
| `tarpit.max_per_ip` | 1 per worker (12 workers across 3 nodes) | Per "Worker Count and max_per_ip Adjustment" formula above |
| Recommended dial progression | 0 → 25 → 50 → 75 over 30 days; hold at 50 for at least 7 days before final raise | `OPERATIONS_GUIDE.md` |
| Monitoring thresholds | Per-node `ja4proxy_active_connections` > 800 sustained → add a node; FP rate > 0.1% over 1 h → halt dial progression and investigate; HAProxy backend down > 30 s → page | `OPERATIONS_GUIDE.md#📊-viewing-logs-&-assets`, [`SERVICE_TARGETS.md`](SERVICE_TARGETS.md) |

**Notes for this scenario:**
- 3 nodes is the minimum for `maxSurge: 1, maxUnavailable: 0` rolling upgrades
  with comfortable headroom (loss of one node still leaves 2× peak capacity).
- Monitor Redis CPU and `INFO commandstats` — at this volume Redis is the
  next bottleneck after the proxy GIL. If Redis CPU sustains > 70%, consider
  splitting state into two Redis instances by key family or migrating to a
  cluster.
- This is the deployment shape where the Go proxy gives the largest
  cost saving once Phase 15 throughput numbers are re-recorded; expected
  per-node ceiling is materially higher **(estimate)** but not yet measured.

### Scenario C — High-volume API / DDoS-resistant edge (~15,000 req/s)

Public API gateway, large-scale e-commerce front door, or an edge tier that
must survive volumetric L7 attacks. Continuous high traffic with frequent
spikes.

| Item | Value | Source |
|------|-------|--------|
| Target sustained throughput | 15,000 conn/s | Requirement |
| Peak (2× headroom) | 30,000 conn/s | (estimate, 2× headroom rule) |
| Per-node ceiling on i9-9900K-class hardware | ~5,600–7,600 conn/s (8 workers) | This doc, "Expected Throughput" table |
| Required node count (Python) | 30,000 ÷ ~6,000 ≈ **5–6 nodes** | Derived |
| Recommended deployment | 6 nodes × 8-worker scaled config; reserve 1 spare node for upgrades | This doc + standard N+1 rule (estimate) |
| Per-node CPU / memory | 8 cores, ~3.3 GB | This doc, "Resource Usage" table |
| Redis sizing | Redis Cluster, 3 primaries + 3 replicas, 8 GB max-memory each, AOF every-second | (estimate; required because single-Redis throughput becomes the bottleneck above ~10K conn/s — see "Conclusion" section in this doc) |
| `tarpit.max_per_ip` | 1 per worker (48 workers fleet-wide) | Per "Worker Count and max_per_ip Adjustment" formula |
| Recommended dial progression | 0 → 10 → 25 → 50 → 75 over 60 days; hold ≥ 14 days at each non-zero step; pause at any FP rate > 0.05% | `OPERATIONS_GUIDE.md`; conservative due to traffic volume (estimate) |
| Monitoring thresholds | Per-node `ja4proxy_active_connections` > 4,000 sustained → add a node; FP rate > 0.05% over 1 h → halt and roll back dial; Redis P99 latency > 5 ms → page; HAProxy backend down > 15 s → page | `OPERATIONS_GUIDE.md#📊-viewing-logs-&-assets`, [`SERVICE_TARGETS.md`](SERVICE_TARGETS.md) |

**Notes for this scenario:**
- At this scale **the Python proxy is end-of-life**. Plan the deployment on
  the assumption of migrating to the Go runtime; the numbers above are a
  worst-case sanity check.
- Bandwidth, kernel sysctl tuning (`net.core.somaxconn`,
  `net.ipv4.tcp_max_syn_backlog`, `nf_conntrack_max`), and NIC RX queues
  matter at this scale and are out of scope here. See
  long-form sizing reference in `OPERATIONS_GUIDE.md`.
- Bypass coverage matters more than dial setting at this volume: ensure
  `h2`/`h1` ALPN bypass and JA4 whitelist are populated; otherwise even a 1%
  scoring overhead becomes hundreds of connections/second of unnecessary work.
- Threat-intel feeds (Spamhaus DROP/EDROP) provide most of the value at the
  edge — keep them current via the leader-election feed manager and watch
  `ti_feed_stale` alerts.

### Cross-scenario notes

- **All "(estimate)" numbers above** should be replaced with measured values
  once Go-runtime production benchmarks land in
  [`docs/performance/BENCHMARK_HISTORY.md`](performance/BENCHMARK_HISTORY.md).
  When updating this guide, replace the estimate marker with the date and
  commit hash of the benchmark entry.
- **Dial progression cadence** is conservative on purpose. False positives
  cost more than false negatives — see `CLAUDE.md` "Core Asymmetry" section.
  When in doubt, slow the dial.
- **Capacity is per-instance ceiling × instance count, minus headroom for
  upgrades.** Always reserve at least one instance worth of capacity for
  rolling upgrades and one for unexpected node failure.

## Shared State Correctness

### What's Shared (via Redis)

✅ **Rate limiting**: All workers use the same Redis keys for rate tracking
✅ **IP bans**: `ban:{ip}` keys are visible to all workers
✅ **JA4 blacklist/whitelist**: Shared Redis sets
✅ **Beaconing detection**: Shared Redis sorted sets
✅ **Analytics signals**: Shared Redis keys
✅ **Dial settings**: Shared Redis key

### What's Per-Worker

🔸 **max_per_ip tarpit limit**: Each worker enforces its own limit (adjust as shown above)
🔸 **In-process LRU cache**: Each worker has its own cache (converges quickly)
🔸 **Connection tracking**: Each worker tracks its own active connections

## Operational Considerations

### Starting and Stopping

```bash
# Start scaled configuration
make start-scaled

# Stop scaled configuration
docker compose -f deploy/docker/docker-compose.poc.yml -f deploy/docker/docker-compose.scale.yml down

# Restart a single worker
docker restart ja4proxy_worker_1
```

### Monitoring

```bash
# HAProxy stats
docker exec -it ja4proxy_haproxy socat /var/run/haproxy.sock -

# Worker-specific logs
docker logs -f ja4proxy_worker_1
docker logs -f ja4proxy_worker_2

# Redis monitoring
docker exec -it redis redis-cli info stats
```

### Scaling Up/Down

To change the number of workers:

1. Edit `deploy/docker/docker-compose.scale.yml`
2. Add/remove worker service definitions
3. Update HAProxy configuration to include new workers
4. Update `max_per_ip` setting in `config/proxy.yml`
5. Restart: `make start-scaled`

## Troubleshooting

### Worker Health Checks Failing

```bash
# Check HAProxy logs
docker logs ja4proxy_haproxy

# Check worker health
docker exec -it ja4proxy_worker_1 curl -v http://localhost:8080/health
```

### Uneven Load Distribution

```bash
# Check HAProxy stats for load distribution
curl http://admin:admin123@localhost:8404/stats

# If uneven, check:
# 1. All workers are healthy
# 2. No worker is overloaded
# 3. Network connectivity between HAProxy and workers
```

### Redis Connection Issues

```bash
# Check Redis connections
docker exec -it redis redis-cli info clients

# Check Redis logs
docker logs redis
```

## Advanced Configuration

### Custom Worker Counts

To use a different number of workers:

1. Create a custom overlay file (e.g., `docker-compose.scale-8workers.yml`)
2. Add 8 worker service definitions
3. Start with: `docker compose -f deploy/docker/docker-compose.poc.yml -f docker-compose.scale-8workers.yml up -d`

### Worker-Specific Configuration

Each worker can have environment variables:

```yaml
# deploy/docker/docker-compose.scale.yml
environment:
  - PROXY_PORT=8080
  - WORKER_ID=1
  - LOG_LEVEL=INFO
  - WORKER_NAME=primary
```

### Resource Limits

Add resource limits to prevent worker runaway:

```yaml
# deploy/docker/docker-compose.scale.yml
deploy:
  resources:
    limits:
      cpus: '1.0'
      memory: '512M'
```

## Security Considerations

### PROXY Protocol

HAProxy is configured to accept PROXY protocol v2 from upstream load balancers/CDNs. This is secure because:

- ✅ Only enabled when behind trusted upstream (configured in `upstream_trust`)
- ✅ Trusted CIDRs must be explicitly configured
- ✅ Prevents IP spoofing from untrusted sources

### TLS Termination

- HAProxy operates at Layer 4 (TCP) and does not terminate TLS
- TLS termination happens at the worker level
- Each worker maintains its own TLS session state

### Rate Limiting Consistency

- All workers use the same Redis-backed rate limiting
- Lua scripts ensure atomic operations
- No race conditions between workers

## Benchmarking

### Before and After

```bash
# Single-instance, host-native — the real per-node ceiling
make bench-hostnative

# Bridge-port macro benchmark (lower; capped by docker-proxy)
make bench-macro
```

### Expected Results

```
Scenario: Mixed traffic (5% browser, 95% scored)
Hardware: i9-9900K, Redis in Docker

Single process:  ~700–950 conn/s
4 workers:        ~2,800–3,800 conn/s  (3.5–4× improvement)
8 workers:        ~5,600–7,600 conn/s  (7–8× improvement)
```

## Migration Guide

### From Single Process to Multi-Process

1. **Update configuration**:
   ```yaml
   # config/proxy.yml
tarpit:
   worker_count: 4
   max_per_ip: 1  # Was 3 for single process
   ```

2. **Start scaled configuration**:
   ```bash
   make start-scaled
   ```

3. **Verify**:
   ```bash
   # Check HAProxy stats
   curl http://admin:admin123@localhost:8404/stats
   
   # Check all workers are healthy
   docker ps | grep ja4proxy_worker
   ```

4. **Monitor performance**:
   ```bash
   # Check throughput
   make status
   
   # Check for errors
   docker logs ja4proxy_haproxy | grep ERROR
   ```

## Best Practices

### Worker Count Recommendations

| CPU Cores | Recommended Workers | Notes |
|-----------|---------------------|-------|
| 4–8 | 2–4 | Optimal balance |
| 8–16 | 4–8 | Good scaling |
| 16+ | 8–12 | Diminishing returns |
| 32+ | Consider Go rewrite (Phase 15) | Better scaling |

### Monitoring Checklist

- [ ] HAProxy stats endpoint accessible
- [ ] All workers show "UP" status
- [ ] Load distribution is even (±10%)
- [ ] Redis connection count matches worker count
- [ ] No worker has high CPU/memory usage
- [ ] Error rates are low (<0.1%)

### Performance Tuning

1. **Adjust worker count** based on CPU cores
2. **Tune Redis timeout** settings for your network
3. **Monitor HAProxy** for uneven load distribution
4. **Adjust max_per_ip** when changing worker count
5. **Scale Redis** if it becomes a bottleneck

## Conclusion

The multi-process worker model provides linear scaling while maintaining all security guarantees. With 4 workers, you can achieve ~3.5–4× the throughput of a single process, making it suitable for handling DDoS-scale traffic on modern hardware.

For even higher throughput (>10,000 conn/s), consider:
- **Phase 15**: Go rewrite for better single-process performance
- **Horizontal scaling**: Multiple machines behind a global load balancer
- **Redis clustering**: For higher Redis throughput

## Support

For issues with multi-process scaling:
1. Check HAProxy logs first
2. Verify Redis connectivity
3. Ensure all workers have identical configuration
4. Check resource limits (CPU/memory)
5. Review health check status

## References

- [HAProxy Documentation](https://docs.haproxy.org/)
- [Docker Compose Overlay Pattern](https://docs.docker.com/compose/extends/)
- [Redis Scaling Guide](https://redis.io/topics/cluster-tutorial)
- Phase 26 throughput hardening (historical context)
