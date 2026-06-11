---
phase: 303
title: Production Compose Port-Exposure Hardening
status: COMPLETE
size: SMALL
created: 2026-06-09
completed: 2026-06-09
audience: [operator, security, developer]
---

# Production Compose Port-Exposure Hardening

## Goal

Close an inconsistency in `deploy/docker/docker-compose.prod.yml`: several
services were **published on `0.0.0.0`** (every host interface) while their inline
comments said *"internal only"*. The project's own posture (pentest finding 0045,
which loopback-bound Grafana) is that monitoring/management surfaces must **never**
bind a public interface — this extends that rule to the services it missed.

## Findings (before)

| Service | Was | Reachable how it's actually used |
|---|---|---|
| proxy | `- "8080"`, `- "9090"` (random `0.0.0.0` ports) | HAProxy → `proxy:8080`; Prometheus → `proxy:9090` (network) |
| analytics | `0.0.0.0:8082→8080` | Prometheus → `analytics:8080` (network) |
| tarpit | `0.0.0.0:8888`, `0.0.0.0:9099` | proxy → `tarpit:8888`; Prometheus → `tarpit:9099` (network) |
| loki | `0.0.0.0:3100` | Grafana queries / Promtail pushes (network) |
| prometheus | `0.0.0.0:9091→9090` | operator UI (debugging) |
| grafana | `127.0.0.1:3001` | ✅ already loopback (0045) |
| haproxy stats | `127.0.0.1:8404` | ✅ already loopback |
| redis-exporter | *(no `ports:`)* | ✅ already network-only (the correct pattern) |

All inter-service traffic already flows over the `ja4proxy-backend` /
`-monitoring` networks by service name — verified that `prometheus.yml` scrapes by
DNS (`analytics:8080`, `ja4proxy:9090`, …), **not** host-published ports — so the
publishes were pure, unnecessary attack surface.

## Changes

- **proxy, analytics, tarpit, loki:** removed the `ports:` blocks entirely
  (network-only, matching `redis-exporter`).
- **prometheus:** `0.0.0.0:9091` → **`${AGENT_BIND_IP:-127.0.0.1}:9091:9090`**
  (loopback by default, private if `AGENT_BIND_IP` is set — same pattern as
  Grafana / Phase 154). The UI stays available for debugging without public
  exposure.
- Corrected the misleading "internal only" comments.
- Fixed the stale quick-start path in the header (`docker/…` → `deploy/docker/…`).

The only remaining host-published ports are **`haproxy 443/80`** (the public
ingress — by design) and the two loopback-bound dashboards.

## Also fixed (bundled — same `deploy`/compose hygiene)

`make clean` aborted with `MANAGEMENT_JWT_SECRET is required` in a freshly-cloned
worktree whose `.env` was incomplete, because `docker compose down` still
evaluates the compose `${VAR:?required}` interpolations. Added a `CLEAN_DUMMY_ENV`
prefix (dummy values — irrelevant for `down`, which only identifies containers)
and made `--env-file` conditional on the file existing, so `clean` works
regardless of `.env` completeness. (Reported live; related to the Phase 300/301
template work.)

## Verification
- `prometheus.yml` scrapes by service DNS, so removing host ports does not break
  monitoring.
- Only `443/80` remain on `0.0.0.0`; everything else is network-only or loopback.
- `make clean` parses the compose with an **empty** `.env` (exit 0).
- `lint-meta` green; the bind-hardening + docker-consistency regression tests
  (incl. `test_pentest_grafana_loopback_bind_regression`) all pass (83).

## Out of Scope
- Grafana `read_only` (it legitimately writes more; left as-is).
- Redis `--save ""` (intentional cache-only persistence).

## Acceptance Criteria
1. No prod service publishes an internal port on `0.0.0.0`.
2. Monitoring still scrapes (network DNS, unaffected).
3. `make clean` succeeds with a missing/incomplete `.env`.
4. Bind-regression + consistency tests pass; manifest records this phase.
