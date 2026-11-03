<!--
title: Python 3.15 Container Runtime & Toolchain Migration
audience: developer
last_reviewed: 2026-11-02
phase: 861
-->

# Python 3.15 Container Runtime & Toolchain Migration

> **Size:** MEDIUM  
> **Dependencies:** [859, 860]  
> **Branch:** `phase-861-python-3-15-migration`  
> **Related PR / Issues:** Dependabot PRs #677, #678, #680; Phase 801, Phase 89a  

---

## Goal

Plan and execute the project-wide upgrade from Python 3.14 to Python 3.15 across all 9 container images (both Alpine and Debian slim), build tooling (`Dockerfile.tools`), CI runner definitions, and consistency tests, ensuring security hardening and musl wheel binary parity are verified without regression.

---

## Background & Architecture Review

During Dependabot PR triage, automated bots opened PRs #677, #678, and #680 to bump base images:
- `src/tarpit/Dockerfile`: `python:3.14.6-alpine3.24` -> `3.15.0-alpine3.24`
- `src/analytics/Dockerfile`: `python:3.14.6-alpine3.24` -> `3.15.0-alpine3.24`
- `deploy/docker/Dockerfile.management`: (migrated to Alpine in Phase 801) `python:3.14.6-alpine3.24`

These PRs were blocked and deferred for three critical architectural reasons:

1. **Silent Security Hardening Failure:**
   - Production container images strip out `pip`, `setuptools`, and `ensurepip` to minimize attack surface:
     ```dockerfile
     rm -rf /usr/local/lib/python3.14/ensurepip /usr/local/lib/python3.14/site-packages/pip* /usr/local/bin/pip*
     ```
   - On a Python 3.15 image, hardcoded `python3.14` path deletions fail silently (`rm -rf` exits 0), leaving full build tools and vendored dependencies intact in production containers. Furthermore, `src/tarpit/Dockerfile` previously omitted pip stripping entirely.
2. **Alpine Musl C-Extension / Binary Wheel Availability:**
   - Alpine images require pre-built `musllinux` wheels for packages like `cryptography`, `bcrypt`, `lxml`, and `uvloop`.
   - Packages like `pytricia==1.3.0` and `xmlsec` have no pre-built `musllinux` wheels on PyPI and must be compiled from source. Their compilation under Python 3.15 C-API deprecations must be validated, and compiler toolchains (`build-base`, dev headers) must be strictly purged before shipping.
3. **CPython 3.15 ABI & Free-Threading:**
   - CPython 3.15 provides experimental free-threading (`python3.15t`). JA4proxy requires standard GIL-enabled CPython (`cp315` ABI) to maintain thread safety and binary extension compatibility.
4. **Complete Dockerfile Matrix:**
   - `tests/unit/test_docker_consistency.py` validates 9 Python Dockerfiles across the repo. All must be updated simultaneously.

---

## Scope

### In Scope
1. **Gate 0: Pre-flight Wheel & Compilation Audit:**
   - Probe `python:3.15-alpine3.24` in a scratch container for wheel availability (`cryptography`, `uvloop`, `bcrypt`) and C-extension compilation (`pytricia`, `xmlsec`).
   - If any core package fails to compile or resolve on musllinux, Phase 861 aborts and remains `PROPOSED`.
2. **All 9 Container Images Updated & Digest-Pinned:**
   - Alpine (5 images):
     - `deploy/docker/Dockerfile.management`
     - `deploy/docker/Dockerfile.test`
     - `deploy/docker/Dockerfile.trafficgen`
     - `src/analytics/Dockerfile`
     - `src/tarpit/Dockerfile`
   - Debian Slim (4 images):
     - `Dockerfile.tools`
     - `tests/docker/Dockerfile.recorder`
     - `tests/docker/Dockerfile.test-runner`
     - `tests/docker/Dockerfile.tls-backend`
   - *(Note: `Dockerfile.bandit` remains pinned to Python 3.11-slim due to upstream AST deprecations).*
3. **Hardening Path Generalization & Fail-Closed Assertions:**
   - Adopt version-agnostic dynamic path purges across all production images:
     ```dockerfile
     RUN rm -rf /usr/local/lib/python3.*/ensurepip \
                /usr/local/lib/python3.*/site-packages/pip* \
                /usr/local/lib/python3.*/site-packages/setuptools* \
                /usr/local/lib/python3.*/site-packages/wheel* \
                /usr/local/bin/pip* && \
         ! python3 -m pip --version 2>/dev/null
     ```
   - Add pip purge to `src/tarpit/Dockerfile`.
4. **CI & Policy Consistency:**
   - Update `AGENTS.md` container rules from Python 3.14 to 3.15.
   - Update `pyproject.toml` (`python_version = "3.15"`).
   - Update `tests/unit/test_docker_consistency.py` `_ALLOWED` lists.
   - Remove Python 3.15 ignore rules in `.github/dependabot.yml`.

### Out of Scope
- Go proxy compiler version updates.
- `Dockerfile.bandit` (retained at 3.11).

---

## Implementation Plan

1. **Step 1: Gate 0 Validation**
   - Run automated scratch probe for `musllinux` wheels and `pytricia`/`xmlsec` compilation on Alpine 3.24.

2. **Step 2: Update All Dockerfiles with Dynamic Hardening**
   - Update base images to pinned sha256 digests.
   - Implement version-agnostic purge and `RUN ! python3 -m pip` verification in all production Dockerfiles.

3. **Step 3: Update Test Suite & Policy Files**
   - Update `test_docker_consistency.py`.
   - Update `AGENTS.md`, `pyproject.toml`, and GitHub Actions workflows.

4. **Step 4: Full Preflight Verification**
   - Run `make preflight` (lint, scan, test).

---

## Test Strategy

- **Gate 0 Musl Probe:** Build test inside `python:3.15-alpine3.24`.
- **Hardening Assertions:** Enforce container inspection asserting `python3 -c "import pip"` raises `ModuleNotFoundError` across `management`, `analytics`, and `tarpit`.
- **Docker Consistency Test:** `pytest tests/unit/test_docker_consistency.py`.
- **Preflight Suite:** Full pass of `make preflight`.

---

## Acceptance Criteria

| # | Criterion | Verification |
|---|---|---|
| A1 | Gate 0 passed: binary wheels resolve and `pytricia`/`xmlsec` compile cleanly on Alpine musl | Scratch build logs |
| A2 | All 9 Python Dockerfiles updated to Python 3.15; `test_docker_consistency.py` green | `pytest tests/unit/test_docker_consistency.py` |
| A3 | Full packaging tool elimination in production images (`pip`, `setuptools`, `ensurepip` unimportable) | `python3 -c "import pip"` raises `ModuleNotFoundError` in all runtime containers |
| A4 | `uvloop` imports and passes event loop tests under 3.15 without fallback | Unit tests pass |
| A5 | `make preflight` exits 0 with zero warnings/errors | Terminal run |

---

## Rollback & Risk Analysis

- **Risk:** Upstream wheel incompatibilities cause compilation timeouts or runtime crashes under musl on Alpine.
  - **Mitigation:** Python 3.14 pins remain locked in `.github/dependabot.yml` until Phase 861 is executed. If blocking issues arise, rollback to 3.14 is immediate via git revert.
