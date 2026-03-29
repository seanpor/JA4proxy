# Phase 41 — Robust Health Check API & Anti-Flap Logic

Status: PROPOSED

## Goal

Implement a comprehensive health checking API for upstream load balancers (HAProxy, F5, AWS NLB) that provides deep visibility into the proxy's operational state while preventing "flapping" during transient issues.

## Background

The current health check is limited to a simple Prometheus `/metrics` port or a basic TCP connection test. This does not distinguish between "the process is running" and "the proxy is functional" (e.g., Redis is reachable, GeoIP DB is loaded). Upstream load balancers need a more reliable indicator to avoid sending traffic to a "zombie" proxy.

## Sub-Tasks

### 41a — Internal Health API Server
- Replace the simple `prometheus_client` server in `proxy.py` with a dedicated `aiohttp` or lightweight `asyncio` HTTP server.
- Serve `/metrics` (Prometheus), `/health` (Deep Check), and `/ready` (Readiness Check).
- Support configurable bind address and port (default 9090).

### 41b — Deep Health Checks
- Implement a `HealthMonitor` class that tracks:
    - **Redis Connectivity:** Active ping test.
    - **Filesystem:** Presence and readability of config and GeoIP files.
    - **Pipeline Latency:** Moving average of recent processing times.
    - **Resource Usage:** Memory/CPU bounds check.
- `/health` returns 200 OK only if all critical systems are functional.

### 41c — Anti-Flap Logic
- Implement a "hysteresis" or "leaky bucket" algorithm for health state.
- **Rise/Fall Thresholds:** Require N consecutive successes to become healthy; M consecutive failures to become unhealthy.
- **Grace Period:** Allow a configurable window after startup where checks are more lenient.
- Prevent rapid traffic shifting by the load balancer during intermittent network blips.

### 41d — Upstream Integration (HAProxy)
- Update `config/haproxy.cfg` to use the new `/health` endpoint with HTTP checks.
- Document configuration for F5 and other enterprise load balancers.

## Acceptance Criteria

- [ ] Proxy provides `/health` and `/ready` JSON endpoints.
- [ ] `/health` fails if Redis is disconnected.
- [ ] Transient Redis blips (< 2 seconds) do not cause the health check to fail (anti-flap).
- [ ] HAProxy correctly detects unhealthy workers via the HTTP endpoint.
- [ ] Zero performance impact on the connection processing hot path.
