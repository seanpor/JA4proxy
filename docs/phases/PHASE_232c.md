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

> **STATUS: PROPOSED — plan for review. No code until approved.**
> Part 3 of 4 of the split Phase 232. Hardens network topology and limits exposed host ports.

## Goal

Ensure robust isolation and secure default network configuration. Attach the `analytics` container to the `ja4proxy-data` network in `docker-compose.poc.yml` so that it can resolve and connect to Redis in the development/local environment. Harden the production port mappings in `docker-compose.prod.yml` by prefixing exposed internal ports (proxy metrics, tarpit, analytics) with `127.0.0.1:` to prevent them from being exposed on wildcard interface bindings (`0.0.0.0`), restricting access to the host loopback interface only. Update the docker images document to align with these mappings.

## Scope

### Files to create/modify:
- [deploy/docker/docker-compose.poc.yml](../../deploy/docker/docker-compose.poc.yml)
- [deploy/docker/docker-compose.prod.yml](../../deploy/docker/docker-compose.prod.yml)
- [docs/DOCKER_IMAGES.md](../../docs/DOCKER_IMAGES.md)

### Out of scope:
- Frontend asset changes or situation bar UI code (covered by 232a/b).
- Removing the `admin-api` container or testing its absence (covered by 232d).

## Implementation Plan

1. **Fix Analytics Network**:
   - In `docker-compose.poc.yml`, edit the `analytics` service configuration.
   - Add `ja4proxy-data` network to the `networks` list.
2. **Restrict Production Port Bindings**:
   - In `docker-compose.prod.yml`, find the published ports for:
     - `proxy` (Prometheus/health): change `"9090"` to `"127.0.0.1:9090:9090"`.
     - `tarpit`: change `"8888"` and `"9099"` to `"127.0.0.1:8888:8888"` and `"127.0.0.1:9099:9099"`.
     - `analytics`: change `"8082"` to `"127.0.0.1:8082:8082"`.
3. **Update Docker Images Documentation**:
   - Update `docs/DOCKER_IMAGES.md` to ensure all port definitions, bindings, and container network layouts are documented accurately according to the new configurations.

## Test Strategy

- **Network Connectivity Validation**: Exec into the `analytics` container and run a Python script testing `redis.Redis().ping()` on host `redis` (resolving over the shared `ja4proxy-data` network) to confirm connectivity.
- **Port Binding Configuration Test**: Create `test_no_wildcard_port_bindings_in_prod_compose` inside `tests/unit/test_container_config.py` using regular expression matching to scan `docker-compose.prod.yml` and assert that no exposed port uses wildcard (`0.0.0.0`) bindings without loopback prefixes.

## Acceptance Criteria

- [ ] `analytics` service is connected to both `ja4proxy-mgmt` and `ja4proxy-data` networks.
- [ ] Production compose ports for metrics, tarpit, and analytics are restricted to `127.0.0.1`.
- [ ] [docs/DOCKER_IMAGES.md](../../docs/DOCKER_IMAGES.md) is updated to reflect the hardended bindings.
- [ ] Unit tests assert that no wildcard ports are exposed in the production compose file.
- [ ] `make test` exits successfully.
