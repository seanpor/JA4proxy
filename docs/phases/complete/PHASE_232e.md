---
phase: 232e
title: Legacy Management Module Removal
status: COMPLETE
size: SMALL
created: 2026-06-15
completed: 2026-06-15
audience: [developer]
dependencies: [232d]
---

# Legacy Management Module Removal

> **STATUS: COMPLETE (2026-06-15).**
> The deferred source-deletion tail of [PHASE_232d](../PHASE_232d.md). Phase 232d
> decommissioned the unauthenticated `admin-api` *container*; this phase deletes
> the now-orphaned `src/management/` *source module* it used to run.

## Goal

Delete the legacy `src/management/` package — the unauthenticated FastAPI app
(`app.py`) plus its `redis_client.py`, `schemas.py`, and `__init__.py` — and the
three test files that exercise it. After Phase 232d, nothing builds or runs this
code: it is dead, unauthenticated source that still passes through the static-
analysis gate and reads as a live management surface. Removing it eliminates the
last trace of the backdoor and the confusing `src/management/` vs `management/`
duplication, leaving a single management codebase (`management/`, the JWT-gated
service on port 8090).

## Grounding note (2026-06-15)

Verified against `main` before proposing:

1. **Nothing but tests imports `src.management`.** A repo-wide
   `grep -rn "src.management"` returns only `src/management/app.py` (internal)
   and three test files (below). No production module, Dockerfile, compose
   service, or script references it — Phase 232d removed the only runtime
   (`Dockerfile.admin` → `src.management.app:app`).
2. **The new `management/` service already covers what the legacy tests assert,
   with authentication** — so deletion loses no meaningful coverage:
   - `tests/unit/test_health_deep.py` (9 tests) → superseded by
     `management/api/routes/health.py` (`GET /api/v1/health/deep`, Auditor-role
     gated) and `management/tests/test_health.py`.
   - `tests/management/test_api.py` (6 tests, dial + JA4 list CRUD with **no
     auth**) → superseded by the authenticated `management/api/routes/dial.py`
     and `lists.py`, tested in `management/tests/test_lists.py` / `test_rbac.py`.
   - `tests/unit/management/test_redis_client.py` (19 tests) → superseded by
     `management/redis_client.py` and its coverage under `management/tests/`.
3. **The Makefile static-analysis targets reference `src/management/`** and must
   be updated or they will fail on the deleted directory: `lint-security`,
   `mypy`, `bandit`, `ruff`, and the dockerised `flake8` target all pass
   `src/management/` as a path (Makefile ~lines 357, 371, 374, 377, 395).
4. **Test directories empty out cleanly.** `tests/management/` holds only
   `test_api.py`; `tests/unit/management/` holds only `__init__.py` +
   `test_redis_client.py`. Both directories are removed entirely.

## Scope

### Files to delete:
- `src/management/` (entire package: `app.py`, `redis_client.py`, `schemas.py`,
  `__init__.py`).
- `tests/management/test_api.py` (and the now-empty `tests/management/` dir).
- `tests/unit/management/test_redis_client.py` and `tests/unit/management/__init__.py`
  (and the now-empty `tests/unit/management/` dir).
- `tests/unit/test_health_deep.py`.

### Files to modify:
- [Makefile](../../../Makefile) — drop `src/management/` from the `lint-security`,
  `mypy`, `bandit`, `ruff`, and dockerised `flake8` invocations (leave
  `src/analytics/` and the other paths intact).
- [deploy/docker/docker-compose.poc.yml](../../../deploy/docker/docker-compose.poc.yml)
  — simplify the Phase 232d tombstone comment so it no longer points at the
  deleted `src/management/app` path (it can just name the removed `admin-api`
  service). *(Minor; the tombstone is added by 232d.)*

### Out of scope:
- The production `management/` service (untouched — it is the secure replacement).
- The `admin-api` container, `Dockerfile.admin`, and runbook/inventory cleanup
  (all done in Phase 232d).

## Implementation Plan

1. **Confirm no new consumers.** Re-run `grep -rn "src\.management" --include=*.py`
   against the post-232d tree; abort if anything outside the deletion set appears.
2. **Delete the module and tests** with `git rm -r src/management/`,
   `git rm tests/management/test_api.py`,
   `git rm -r tests/unit/management/`, and
   `git rm tests/unit/test_health_deep.py`.
3. **Update the Makefile** static-analysis targets to drop the `src/management/`
   path argument.
4. **Tidy the tombstone comment** in `docker-compose.poc.yml`.
5. **Verify the gate is still green** (see Test Strategy).

## Test Strategy

- **Full suite:** `make test` passes with no new failures and no
  collection/import errors from the removed test files.
- **Static-analysis gate:** `make lint` (or the individual `mypy` / `bandit` /
  `ruff` targets) resolves cleanly without the deleted `src/management/` path.
- **Coverage preserved:** the `management/` service tests
  (`management/tests/test_health.py`, `test_lists.py`, `test_rbac.py`, and the
  `redis_client` coverage) continue to pass, demonstrating the authenticated
  equivalents are intact.
- **Residual-reference search:** `grep -rn "src.management\|src/management"`
  returns only historical completed-phase docs and intentional tombstones — no
  live code, build config, or test reference.

## Acceptance Criteria

- [ ] `src/management/` is deleted in full.
- [ ] The three legacy test files and their now-empty directories are removed.
- [ ] The Makefile static-analysis targets no longer reference `src/management/`
      and run cleanly.
- [ ] `grep -rn "src.management"` over Python/build files returns no live
      references (only history/tombstones remain).
- [ ] `make test` and `make lint` pass cleanly (no new failures).
