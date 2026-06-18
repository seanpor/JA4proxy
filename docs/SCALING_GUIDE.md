<!--
title: Scaling Guide
audience: operator
version: 2.0.0
last_reviewed: 2026-06-10
phase: 309
-->

# JA4proxy Scaling Guide

## Overview

JA4proxy scales the way any stateless network service scales: **run more
instances behind a load balancer.** The production runtime is a single,
statically-linked Go binary (`ja4pd`). An instance holds no authoritative local
state — bans, rate-limit windows, beaconing history, and unique-IP counters all
live in Redis — so adding a node adds capacity without any coordination beyond a
shared Redis.

This is a deliberate change from the earlier Python prototype, which scaled by
adding **worker processes** per host to work around the interpreter's GIL. The
Go engine has no GIL and no per-process worker model: **one `ja4pd` process uses
all the cores you give it.** Scale by nodes, not workers.

> **Throughput anchors** (measured on a commodity Intel i9-9900K, full scoring
> pipeline, 0 errors / 0% false positives — see `docs/performance/benchmarks.md`):
> a single instance sustains **~3,000 conn/s with host networking** and
> **~600 conn/s through the Docker bridge** (the bridge ceiling is Docker's
> userland `docker-proxy`, not the engine). A single modest server therefore
> absorbs several hundred connections per second without breaking a sweat — more
> than enough to give a bot-pressured site immediate relief.

## Architecture

```
            (optional LB / HAProxy)
Internet ──:443──▶ load balancer ──▶ ja4pd × N ──▶ backend(s)
                                       │  ▲
                          XADD events  │  │  bans / rate limits / counters
                                       ▼  │
                                   ┌──────────┐
                                   │  Redis   │  (shared state, all instances)
                                   └──────────┘
```

- **`ja4pd` instances** are interchangeable and stateless. Any instance can
  serve any connection; losing one loses no security state.
- **Redis** is the single source of truth for cross-instance state.
- **A load balancer is optional.** For a single instance you can point the
  outside firewall straight at `ja4pd` (see "Minimal single-server deployment").

### Key components

| Component | Role | State |
|-----------|------|-------|
| `ja4pd` | The proxy engine — fingerprint, score, act, forward | Stateless (in-process LRU cache is an optimisation only) |
| Redis | Bans, rate-limit windows, beaconing, HLL counters, config | Authoritative shared state |
| Load balancer (optional) | Distributes connections across instances | — |
| Backend(s) | Your protected origin | — |

## Minimal single-server deployment

The smallest useful deployment is **one server**, and it needs neither a load
balancer nor HAProxy:

1. Run `ja4pd` (container or binary) on the box, configured to forward to your
   backend and to reach a Redis (local or remote).
2. Point the **outside firewall** at the `ja4pd` listener — only the public
   port (typically `443`) need be open; everything else stays on the management
   network.
3. Raise the dial when you trust the scores (it starts at `0`, monitor-only).

This alone handles hundreds of connections per second and gives an operator
under active bot pressure immediate relief, with no decryption and no change to
the backend.

> **Ports are configurable — do not hard-code them.** The listener, metrics, and
> backend ports are all driven by config / environment (`PROXY_PORT`,
> `METRICS_PORT`, `BACKEND_HOST`/`BACKEND_PORT`, …). Map whatever the firewall
> forwards (e.g. `443`) to the `ja4pd` listener; nothing requires a fixed port.

## Horizontal scaling

When one node approaches its ceiling, add nodes:

1. Run additional `ja4pd` instances (more containers, more hosts, or more
   replicas — `make start-scaled` brings up a multi-instance Compose overlay,
   `deploy/docker/docker-compose.scale.yml`).
2. Put a load balancer in front (HAProxy, your cloud LB, or Kubernetes Service).
   Plain TCP/L4 distribution is sufficient — JA4proxy is connection-oriented.
3. Point every instance at the **same Redis** so bans and rate limits are shared.

Throughput scales approximately linearly with instance count because instances
share nothing on the hot path except Redis. Beyond ~10K conn/s aggregate, Redis
becomes the next thing to scale (replica/cluster, or split state by key family).

> **Deploy with host networking for throughput.** Containerised instances behind
> Docker's bridge are capped by `docker-proxy` (~600 conn/s/instance regardless
> of CPU); `network_mode: host` (or running the binary directly) removes that
> ceiling and is the recommended production topology.

## Capacity planning

| Quantity | Value | Source |
|----------|-------|--------|
| Per-instance ceiling, host networking | ~3,000 conn/s | `docs/performance/benchmarks.md` (i9-9900K) |
| Per-instance ceiling, Docker bridge | ~600 conn/s | same — `docker-proxy` limited |
| Allow-path core decision latency | ~272 ns | micro-benchmark |
| Memory per instance | < 12 MB RSS + LRU cache | static binary |
| Scaling model | linear in instance count (Redis-shared) | architecture |

Rough sizing: `instances ≈ ceil(peak_conn_per_sec ÷ per_instance_ceiling)`, then
add **N+1** for rolling upgrades and headroom. Validate on your own hardware with
`make bench-hostnative` — the numbers above are anchors, not guarantees.

## Shared state correctness

### Shared via Redis (consistent across all instances)
- IP bans (`ban:*`) and CIDR bans (`ban_cidr:*`)
- Sliding-window rate-limit state
- Beaconing timestamp history (sorted sets)
- Unique-IP-per-subnet HyperLogLog counters
- Black/whitelists and dial/config (with pub/sub for immediate removals)

### Per-instance (optimisation only, never authoritative)
- The in-process LRU decision cache. A cache miss simply re-scores; it never
  produces a wrong decision. Per the core asymmetry, when Redis says "block" but
  a local cache entry says "allow", **local allow wins** — a real browser keeps
  working even if Redis is briefly unavailable.

## Operations

```bash
# Start a multi-instance stack
make start-scaled

# Per-instance health / metrics
curl -s http://<instance>:${METRICS_PORT:-9090}/health
curl -s http://<instance>:${METRICS_PORT:-9090}/metrics | grep ja4proxy_active_connections

# Redis connection count (aggregate load proxy)
redis-cli -a "$REDIS_PASSWORD" --no-auth-warning INFO clients
```

**Scaling signal:** add an instance when per-node `ja4proxy_active_connections`
is sustained near your measured ceiling, or when p99 connection latency starts
climbing under load. Halt dial progression (do not add nodes blindly) if the
false-positive rate rises.

## Security considerations

- **PROXY protocol:** when behind a load balancer, enable PROXY protocol v2 so
  `ja4pd` sees the real client IP; restrict it to your trusted upstream CIDR so a
  client cannot spoof a header by reaching the listener directly.
- **TLS:** JA4proxy never terminates or decrypts TLS — it forwards byte-for-byte.
  Adding instances changes nothing about key custody (there is none).
- **Rate-limit consistency:** rate limiting is correct across instances because
  the sliding-window state is in Redis, not per-instance.

## Troubleshooting

| Symptom | Likely cause | Check |
|---------|--------------|-------|
| Throughput plateaus far below ~3,000 conn/s | Bridge `docker-proxy` ceiling | Use host networking; compare `make bench-hostnative` vs `make bench-macro` |
| Bans not consistent across instances | Instances on different Redis | Confirm `REDIS_HOST`/`REDIS_PORT` identical everywhere |
| One instance hot, others idle | LB not distributing | Check LB backend health and balancing algorithm |
| Redis CPU saturating | Aggregate write rate too high | Add a replica / split state by key family; see `docs/performance/benchmarks.md` |

## Benchmarking

```bash
# Single-instance, host-native — the real per-node ceiling
make bench-hostnative

# Bridge-port macro benchmark (lower; capped by docker-proxy)
make bench-macro
```

See `docs/performance/benchmarks.md` for method and recorded results.

## References

- `docs/performance/benchmarks.md` — measured throughput and the bench harness
- `docs/DEPLOYMENT_OPTIONS.md` — deployment topologies
- `docs/OPERATIONS_GUIDE.md` — day-to-day operation and the dial
- `docs/REDIS_SCHEMA.md` — the shared-state key schema
