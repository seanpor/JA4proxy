# PHASE 73 — Docker Isolation: Host-Level Hardening

## Goal

Partition physical resources of the i9-9900K host and minimise the attack surface by
enforcing per-agent loopback IP binding across all host-exposed ports, removing
unnecessary host exposure, adding CPU pinning, non-root users, and log rotation.

---

## 73a. Complete Port Change Table

This table specifies every host `ports:` mapping change in `docker-compose.poc.yml`.
Current state → target state.

| Service | Current | Target | Reason |
|---------|---------|--------|--------|
| `haproxy` | `443:443` | `${AGENT_BIND_IP:-127.0.0.1}:${HOST_PORT_INGRESS:-443}:443` | Per-agent IP binding |
| `haproxy` | `8880:80` | *(remove)* | HTTP redirect not needed in POC; reduces surface |
| `haproxy` | `127.0.0.1:8404:8404` | `${AGENT_BIND_IP:-127.0.0.1}:8404:8404` | Per-agent binding to avoid collision |
| `proxy` | `127.0.0.1:8080:8080` | *(remove)* | Internal service; route via HAProxy only |
| `proxy` | `127.0.0.1:9090:9090` | `${AGENT_BIND_IP:-127.0.0.1}:9090:9090` | Per-agent binding for metrics scrape |
| `redis` | `127.0.0.1:6379:6379` | *(remove)* | `data_net` internal; never expose to host |
| `backend` | `127.0.0.1:8443:443` | *(remove)* | `origin_net` internal; no direct host access |
| `tarpit` | `127.0.0.1:8888:8888` | *(remove)* | `origin_net` internal |
| `tarpit` | `127.0.0.1:9099:9099` | *(remove)* | `origin_net` internal; tarpit metrics collected by proxy |
| `analytics` | `127.0.0.1:8083:8080` | `${AGENT_BIND_IP:-127.0.0.1}:${HOST_PORT_ANALYTICS:-8080}:8080` | Per-agent IP binding |

**Default behaviour** (no agent env): `AGENT_BIND_IP` defaults to `127.0.0.1`, which
preserves backward-compatible single-instance behaviour.

---

## 73b. CPU Partitioning

Use `cpuset` (top-level service key) to pin agent containers to specific logical cores.
Apply to the `proxy` service only — it is the CPU-intensive hot path.

```yaml
services:
  proxy:
    cpuset: "${AGENT_CPU_SET:-0-15}"   # default: unrestricted
    deploy:
      resources:
        limits:
          cpus: '4.0'          # weight/share limit — separate from cpuset
          memory: 512M
        reservations:
          memory: 128M
```

`cpuset` and `deploy.resources.limits.cpus` are independent controls:
- `cpuset`: which physical cores the container may use (hard affinity)
- `cpus`: maximum CPU share weight (soft scheduling limit)

Both are set so that even on the allowed cores, one agent cannot consume all CPU weight.

---

## 73c. Non-Root Execution

All first-party Dockerfiles already create and switch to a named non-root system user:

| Service | Dockerfile | User |
|---------|-----------|------|
| `proxy` | `docker/Dockerfile` | `proxy` |
| `backend` | `docker/Dockerfile.mockbackend` | `backend` |
| `tarpit` | `tarpit/Dockerfile` | `tarpit` |
| `analytics` | `src/analytics/Dockerfile` | `analytics` |
| `trafficgen` | `docker/Dockerfile.trafficgen` | `trafficgen` |
| `test` | `docker/Dockerfile.test` | `proxy` |

These use `useradd -r` (system accounts, UID < 1000). Do NOT add `user:` overrides in
`docker-compose.poc.yml` — that would override the Dockerfile's USER directive with a UID
that does not exist in the container's `/etc/passwd`, breaking file permission checks on
internal paths. The `haproxy` stock image manages its own privilege dropping internally.

Verify non-root after starting: `docker compose exec proxy id` should show a non-root UID.

---

## 73d. Log Rotation

Add to every service to prevent disk exhaustion:

```yaml
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "3"
```

300 MB cap per container (3 × 100 MB). Apply to all 8 services.

---

## 73e. Backward Compatibility

When no `.env.<agent>` is used (plain `docker compose up` or `make start`):
- `AGENT_BIND_IP` unset → defaults in compose expressions (`:-127.0.0.1`) kick in
- `AGENT_CPU_SET` unset → defaults to `0-15` (unrestricted)
- `HOST_PORT_INGRESS` unset → defaults to `443`
- `HOST_PORT_ANALYTICS` unset → defaults to `8080`

Behaviour is identical to the current single-instance setup. Existing `make start`,
`make stop`, smoke tests, and CI are unaffected.

---

## Acceptance Criteria

- [ ] `haproxy` port `8880:80` removed from compose.
- [ ] `redis` host port `6379` removed from compose.
- [ ] `backend` host port `8443` removed from compose.
- [ ] `tarpit` host ports `8888` and `9099` removed from compose.
- [ ] `haproxy` ingress port bound to `${AGENT_BIND_IP}:443`.
- [ ] `analytics` port bound to `${AGENT_BIND_IP}:8080`.
- [ ] `proxy` metrics port bound to `${AGENT_BIND_IP}:9090`.
- [ ] `proxy` has `cpuset: "${AGENT_CPU_SET:-0-15}"`.
- [ ] All containers run as non-root users (Dockerfiles set named system users; no `user:` override in compose).
- [ ] All services have log rotation at 300 MB.
- [ ] `make start` (no agent env) still works identically to before.
- [ ] Verify loopback IP binding: `ss -tlnp | grep 127.0.0.10` shows 443 and 8080 when running as gemini agent.

---

## Files to Modify

| File | Change |
|------|--------|
| `docker-compose.poc.yml` | All port, cpuset, user, logging changes per tables above |
| `CHANGELOG.md` | Phase 73 entry |
