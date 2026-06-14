---
phase: 232d
title: Admin-API Decommissioning
status: PROPOSED
size: SMALL
created: 2026-06-14
audience: [developer, operator]
dependencies: [232a]
---

# Admin-API Decommissioning

> **STATUS: PROPOSED — plan for review. No code until approved.**
> Part 4 of 4 of the split Phase 232. Eliminates the unauthenticated backdoor API container.

## Goal

Decommission and completely remove the unauthenticated `admin-api` container (which exposes port `8091` to the host and runs legacy unauthenticated configuration-modifying code). Ensure that all external scripts, Ansible playbooks, and CLI tools are redirected to the secure `management` service API (port `8090` / `/api/v1/*`) using authenticated Bearer tokens. Update the operations manual and runbooks to remove references to the backdoor service.

## Scope

### Files to create/modify:
- [deploy/docker/docker-compose.poc.yml](../../deploy/docker/docker-compose.poc.yml)
- [deploy/docker/Dockerfile.admin](../../deploy/docker/Dockerfile.admin) (to be deleted)
- [tests/unit/test_container_config.py](../../tests/unit/test_container_config.py)
- [docs/OPERATIONS_GUIDE.md](../../docs/OPERATIONS_GUIDE.md)

### Out of scope:
- Vendoring assets or frontend situation bar code (covered by 232a/b).
- Modifying production bindings for ports other than `8091` (covered by 232c).

## Implementation Plan

1. **Audit API Usage**:
   - Search the repository for any scripts, playbooks, or instructions referencing port `8091` or `admin-api`.
2. **Decommission the Service**:
   - Remove the `admin-api` service block from `deploy/docker/docker-compose.poc.yml`.
   - Remove `deploy/docker/Dockerfile.admin` from the filesystem using `git rm`.
3. **Migrate Automation Consumers**:
   - Ensure all automated tasks use the secure management API at `http://localhost:8090/api/v1/` by supplying an API Bearer token in the `Authorization` header.
4. **Update Operations Guide and Runbooks**:
   - Clean up [docs/OPERATIONS_GUIDE.md](../../docs/OPERATIONS_GUIDE.md) and any runbook docs to ensure they do not reference the legacy `admin-api` or port `8091`.
5. **Add Regression Test**:
   - Create `test_admin_api_absent_from_all_compose_files` in `tests/unit/test_container_config.py` asserting that `admin-api` and port `8091` references do not appear in any compose file.

## Test Strategy

- **Regression Test Suite**: Run `pytest tests/unit/test_container_config.py` to assert that the `admin-api` service is absent and port `8091` is no longer declared.
- **Repository Search**: Verify that a recursive `grep` for `admin-api` and `8091` returns empty results across configuration and deployment directories.

## Acceptance Criteria

- [ ] `admin-api` container block is deleted from compose configurations.
- [ ] `Dockerfile.admin` is removed.
- [ ] Operational docs and runbooks are free of port `8091` and `admin-api` references.
- [ ] API-level unit test asserting the removal of the backdoor passes successfully.
- [ ] `make test` passes cleanly.
