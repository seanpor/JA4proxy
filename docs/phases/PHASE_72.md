# PHASE 72 — Docker Isolation: Logical Network Zones

## Goal

Implement a production-mirrored, three-tier network architecture within Docker Compose.
Ensures that even in development, components like Redis and the Mockbackend are logically
isolated from the public-facing HAProxy and the management-facing Analytics node.

---

## 72a. Define Production-Mirror Zones

### Implementation

Replace the existing two networks (`ja4proxy-frontend`, `ja4proxy-backend`) with four
discrete zones in `docker-compose.poc.yml`:

| Network | `internal` | Purpose |
|---------|-----------|---------|
| `dmz_net` | no | Public-facing ingress: HAProxy ↔ Proxy |
| `data_net` | **yes** | Internal state: Proxy ↔ Redis. No internet egress. |
| `origin_net` | **yes** | Backend egress: Proxy ↔ Backend, Proxy ↔ Tarpit. No internet egress. |
| `mgmt_net` | no | Monitoring/Admin: Proxy ↔ Analytics |

```yaml
networks:
  dmz_net:
    driver: bridge
  data_net:
    driver: bridge
    internal: true   # No internet/external access
  origin_net:
    driver: bridge
    internal: true   # No internet/external access
  mgmt_net:
    driver: bridge
```

---

## 72b. Service Zone Assignment

Reassign every service's network interfaces to enforce zero-trust boundaries.

| Service | Networks | Rationale |
|---------|----------|-----------|
| `haproxy` | `dmz_net` | Ingress gateway only. Cannot reach Redis or backend directly. |
| `proxy` | `dmz_net`, `data_net`, `origin_net`, `mgmt_net` | The secure bridge node — the only dual-homed service. |
| `redis` | `data_net` | Deep isolated state. No route to internet or other zones. |
| `backend` | `origin_net` | Isolated origin simulation. |
| `tarpit` | `origin_net` | Receives tarpitted connections forwarded by proxy. |
| `analytics` | `mgmt_net` | Management and telemetry only. |
| `trafficgen` | `dmz_net` | Sends synthetic TLS traffic to HAProxy ingress. |
| `test` | `dmz_net`, `data_net`, `origin_net` | Needs to reach proxy, redis, and backend for integration tests. |

### Service network config fragments

```yaml
services:
  haproxy:
    networks:
      - dmz_net

  proxy:
    networks:
      - dmz_net
      - data_net
      - origin_net
      - mgmt_net

  redis:
    networks:
      - data_net

  backend:
    networks:
      - origin_net

  tarpit:
    networks:
      - origin_net

  analytics:
    networks:
      - mgmt_net

  trafficgen:
    networks:
      - dmz_net

  test:
    networks:
      - dmz_net
      - data_net
      - origin_net
```

---

## 72c. DNS Resolution After Zone Change

Docker Compose DNS resolves service names (e.g. `redis`, `proxy`) only between services
that share a network. Verify the following cross-zone DNS paths work after migration:

| From | To | Via | Expected result |
|------|----|-----|----------------|
| `haproxy` | `proxy:8080` | `dmz_net` | ✓ resolves |
| `proxy` | `redis:6379` | `data_net` | ✓ resolves |
| `proxy` | `backend:443` | `origin_net` | ✓ resolves |
| `proxy` | `tarpit:8888` | `origin_net` | ✓ resolves |
| `proxy` | `analytics:8080` | `mgmt_net` | ✓ resolves |
| `haproxy` | `redis` | — | ✗ no shared network |
| `redis` | `backend` | — | ✗ no shared network |
| `backend` | `analytics` | — | ✗ no shared network |

The `haproxy.cfg` file does NOT need changes — it references `proxy:8080` and `proxy:9090`
which resolve via `dmz_net`, unchanged from before.

---

## Acceptance Criteria

- [x] `docker-compose.poc.yml` has exactly 4 network definitions, replacing the old 2.
- [x] `internal: true` set on `data_net` and `origin_net`.
- [x] Proxy can reach `redis` via DNS (`data_net`).
- [x] HAProxy CANNOT reach `redis` directly (no shared network).
- [x] Backend CANNOT reach `analytics` directly (no shared network).
- [x] All 8 services have correct network assignments per the table above.

---

## Files to Modify

| File | Change |
|------|--------|
| `docker-compose.poc.yml` | Replace network definitions and reassign all service networks |
| `CHANGELOG.md` | Phase 72 entry |
