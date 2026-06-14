---
phase: 232c
title: Container Networking & Port Hardening
status: PROPOSED
size: SMALL
created: 2026-06-14
audience: [developer, operator]
dependencies: [232a]
---

# Container Networking & Port Hardening

> **STATUS: IN_PROGRESS.** Part 3 of 4 of the split Phase 232. Hardens network
> topology and guards against exposed host ports.

> **Grounding note (2026-06-14):** verified against `main` before building. The
> original plan's main deliverable — prefixing the internal production ports
> (proxy `9090`, tarpit `8888`/`9099`, analytics `8082`) with `127.0.0.1:` — was
> **already done, and more thoroughly**, by Phase 0046: those services now
> publish **no host ports at all** (Prometheus and the proxy reach them over the
> compose network). So the prod-compose edit is obsolete; this phase instead
> *regression-guards* that hardening. The remaining real gap is the POC
> `analytics` ↔ Redis network, which is genuinely broken on `main`.

## Goal

Ensure robust isolation and secure default network configuration. Attach the
`analytics` container to the internal `ja4proxy-data` network in
`docker-compose.poc.yml` so it can resolve and connect to Redis (today it sits
on `ja4proxy-mgmt` only, while Redis is on `ja4proxy-data` only — so the `redis`
hostname does not resolve and the analytics node cannot read the events stream
or write findings). Add structural tests that (a) assert analytics shares a
network with Redis and (b) regression-guard the Phase 0046 host-port removal so
no internal production service is ever republished on a wildcard interface.

## Scope

### Files to create/modify:
- [deploy/docker/docker-compose.poc.yml](../../deploy/docker/docker-compose.poc.yml) — add `ja4proxy-data` to the `analytics` service networks.
- [tests/integration/test_container_config.py](../../tests/integration/test_container_config.py) — extend the existing structural-invariants suite (the mandatory `test_container_config.py` already lives here, not under `tests/unit/`).

### Out of scope:
- `docker-compose.prod.yml` — already hardened in Phase 0046 (no change needed; this phase only guards it).
- `docs/DOCKER_IMAGES.md` — an image inventory; it carries no port/network-topology tables to update (the compose files are the source of truth for topology).
- Frontend asset changes or situation bar UI code (covered by 232a/b).
- Removing the `admin-api` container or testing its absence (covered by 232d).

## Implementation Plan

1. **Fix Analytics Network**:
   - In `docker-compose.poc.yml`, add `ja4proxy-data` to the `analytics`
     service's `networks` list (it keeps `ja4proxy-mgmt`), mirroring the
     `management` and `admin-api` services which are already on both.
2. **Guard the production hardening (already landed in Phase 0046)**:
   - Add a regression test asserting the internal prod services (`proxy`,
     `analytics`, `tarpit`) never publish a host port on a wildcard/public
     interface. `haproxy`'s `443`/`80` are intentionally public and excluded.

## Test Strategy

Both tests parse the compose files (no live containers) and run in the standard
`make test` gate; they extend `tests/integration/test_container_config.py`:

- **`test_poc_analytics_shares_redis_data_network`**: parse `docker-compose.poc.yml`
  and assert the `analytics` and `redis` services share at least one network
  (i.e. analytics can resolve `redis`). Fails on the pre-fix tree.
- **`test_prod_internal_services_not_published_on_wildcard`**: parse
  `docker-compose.prod.yml` and assert no `proxy`/`analytics`/`tarpit` published
  port binds to a wildcard/public host-IP (brace-aware `${VAR:-default}`
  handling; loopback/private only). Passes trivially today; fails if a bare
  `- "8082"`-style mapping is reintroduced.

## Acceptance Criteria

- [x] `analytics` service is connected to both `ja4proxy-mgmt` and `ja4proxy-data` networks in the POC compose.
- [x] A test asserts `analytics` shares a network with `redis` in the POC compose.
- [x] A regression test asserts the internal production services are never published on a wildcard interface (guarding the Phase 0046 hardening).
- [x] `make test` exits successfully.
