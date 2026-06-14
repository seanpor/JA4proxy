---
phase: 232d
title: Admin-API Decommissioning
status: IN_PROGRESS
size: SMALL
created: 2026-06-14
audience: [developer, operator]
dependencies: [232a]
---

# Admin-API Decommissioning

> **STATUS: IN_PROGRESS.** Part 4 of 4 of the split Phase 232. Eliminates the
> unauthenticated backdoor API container.

> **Grounding note (2026-06-14):** verified against `main` before building.
> Findings that adjust the plan as originally written:
>
> 1. **Premise confirmed.** The `admin-api` service in
>    `deploy/docker/docker-compose.poc.yml` builds `deploy/docker/Dockerfile.admin`,
>    which launches `src/management/app:app` on host port `8091`. That app is
>    genuinely unauthenticated — `PUT /api/v1/dial` and `POST`/`DELETE
>    /api/v1/lists/ja4/*` modify proxy state with no auth dependency (it imports
>    `Depends` but never wires an authenticator). The secure replacement is the
>    `management` service (host port `8090`), which runs `management/api/main:app`
>    behind JWT (`MANAGEMENT_JWT_SECRET` / `MANAGEMENT_ADMIN_*`). So the backdoor
>    and its migration target are both real. (The host binding already defaults
>    to `127.0.0.1` via `AGENT_BIND_IP`, so this is loopback/agent-host exposure,
>    not public — but it still bypasses all auth for anyone on that host.)
> 2. **Test file path corrected.** The mandatory container-config suite lives at
>    `tests/integration/test_container_config.py` (where Phase 232c added its
>    structural tests), **not** `tests/unit/test_container_config.py`. The
>    regression test is added there.
> 3. **Doc targets retargeted.** `docs/OPERATIONS_GUIDE.md` carries **no**
>    `admin-api`/`8091` references — that cleanup step is a no-op. The docs that
>    actually reference the service are `docs/runbooks/REMOTE_TESTING.md` (port
>    table + bind-model list) and `deploy/docker/README.md` (service/network
>    tables); those are updated instead.
> 4. **Consumers corrected.** `scripts/ja4proxy_admin.py` is **not** an admin-api
>    HTTP consumer — it talks to Redis directly, so it needs no migration. The
>    real automation touch-points are `scripts/agent-env.sh`
>    (`HOST_PORT_ADMIN_API=8091`) and `scripts/check_updates.py` (the
>    `ja4proxy-admin-api` image in its update-check set). No Ansible playbook
>    references `8091`.
> 5. **`src/management/` code is retained (scope boundary).** This phase
>    decommissions the *container*: once nothing builds `Dockerfile.admin` or
>    runs `src/management/app`, the unauthenticated app is unreachable. The dead
>    `src/management/` Python and its existing tests
>    (`tests/management/test_api.py`, `tests/unit/test_health_deep.py`,
>    `tests/unit/management/test_redis_client.py`) are left intact so the suite
>    stays green; deleting that legacy module is a larger, separate cleanup and
>    is filed as a follow-up rather than smuggled into this SMALL phase.

## Goal

Decommission and completely remove the unauthenticated `admin-api` container (which exposes port `8091` to the host and runs legacy unauthenticated configuration-modifying code). Ensure that all external scripts, Ansible playbooks, and CLI tools are redirected to the secure `management` service API (port `8090` / `/api/v1/*`) using authenticated Bearer tokens. Update the operations manual and runbooks to remove references to the backdoor service.

## Scope

### Files to create/modify:
- [deploy/docker/docker-compose.poc.yml](../../deploy/docker/docker-compose.poc.yml) — remove the `admin-api` service block.
- [deploy/docker/Dockerfile.admin](../../deploy/docker/Dockerfile.admin) — `git rm`.
- [tests/integration/test_container_config.py](../../tests/integration/test_container_config.py) — add the absence regression test (corrected from `tests/unit/`).
- [scripts/agent-env.sh](../../scripts/agent-env.sh) — drop `HOST_PORT_ADMIN_API`.
- [scripts/check_updates.py](../../scripts/check_updates.py) — drop `ja4proxy-admin-api` from the first-party image set.
- [deploy/docker/README.md](../../deploy/docker/README.md) — remove `admin-api` from the service/network tables.
- [docs/runbooks/REMOTE_TESTING.md](../../docs/runbooks/REMOTE_TESTING.md) — remove the `8091`/admin-api port row and bind-list mention.

### Out of scope:
- Vendoring assets or frontend situation bar code (covered by 232a/b).
- Modifying production bindings for ports other than `8091` (covered by 232c).
- Deleting the legacy `src/management/` module and its tests (separate follow-up;
  removing the container already neutralises the backdoor — see grounding note 5).

## Implementation Plan

1. **Audit API Usage**:
   - Search the repository for any scripts, playbooks, or instructions referencing port `8091` or `admin-api`.
2. **Decommission the Service**:
   - Remove the `admin-api` service block from `deploy/docker/docker-compose.poc.yml`.
   - Remove `deploy/docker/Dockerfile.admin` from the filesystem using `git rm`.
3. **Migrate Automation Consumers**:
   - Drop `HOST_PORT_ADMIN_API` from `scripts/agent-env.sh` and `ja4proxy-admin-api`
     from the first-party image set in `scripts/check_updates.py`. (Per grounding
     note 4, `scripts/ja4proxy_admin.py` already talks to Redis directly and needs
     no change; any HTTP automation uses the secure management API at
     `http://localhost:8090/api/v1/` with a Bearer token.)
4. **Update Runbooks and Image Inventory**:
   - Remove the legacy `admin-api`/`8091` references from
     `docs/runbooks/REMOTE_TESTING.md` and `deploy/docker/README.md`.
     (`docs/OPERATIONS_GUIDE.md` carries no such references — grounding note 3.)
5. **Add Regression Test**:
   - Create `test_admin_api_absent_from_all_compose_files` in
     `tests/integration/test_container_config.py` asserting that `admin-api` and
     port `8091` references do not appear in any compose file.

## Test Strategy

- **Regression Test Suite**: Run `pytest tests/unit/test_container_config.py` to assert that the `admin-api` service is absent and port `8091` is no longer declared.
- **Repository Search**: Verify that a recursive `grep` for `admin-api` and `8091` returns empty results across configuration and deployment directories.

## Acceptance Criteria

- [ ] `admin-api` container block is deleted from compose configurations.
- [ ] `Dockerfile.admin` is removed.
- [ ] Runbooks and the image inventory (`docs/runbooks/REMOTE_TESTING.md`,
      `deploy/docker/README.md`) are free of port `8091` and `admin-api` references.
- [ ] Automation touch-points (`scripts/agent-env.sh`, `scripts/check_updates.py`)
      no longer reference the admin-api port or image.
- [ ] A structural regression test asserting the removal of the backdoor passes
      (`test_admin_api_absent_from_all_compose_files`).
- [ ] `make test` passes cleanly.
