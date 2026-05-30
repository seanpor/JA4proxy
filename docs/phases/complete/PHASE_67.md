# Phase 67 — Python 3.14 Base Image Upgrade

## Overview

With the compatibility report from Phase 66 in hand, this phase performs the actual
Dockerfile upgrade: all non-analytics containers move from `python:3.11.11-slim` to
`python:3.14.0-slim`. The analytics container is handled separately in Phase 70.

No application code changes. The only changes are image tags, one optional Dockerfile
build-dependency line (for `pytricia` if it lacks a wheel), and `pyproject.toml`
`target-version`.

**Expected outcome:** Full test suite passes unchanged; scoring path mean latency
improves by ≥ 10% vs the Phase 66 baseline; throughput ceiling increases.

---

## Prerequisites

- Phase 66 compatibility report shows no blocking incompatibilities, or documents
  `BUILD_FROM_SOURCE` fixes for any package that needs them.
- Phase 66 benchmark baseline (`reports/benchmark/python311-baseline.md`) exists.

---

## Work Plan

### A — Update Dockerfiles

Change `FROM python:3.11.11-slim` → `FROM python:3.14.0-slim` in:

```
docker/Dockerfile
docker/Dockerfile.test
docker/Dockerfile.mockbackend
docker/Dockerfile.trafficgen
tarpit/Dockerfile
tests/docker/Dockerfile.test-runner
tests/docker/Dockerfile.python-proxy
tests/docker/Dockerfile.tls-backend
tests/docker/Dockerfile.recorder
```

Change `FROM python:3.11-slim` → `FROM python:3.14-slim` in any remaining test
Dockerfiles using the floating tag.

If Phase 66 identified `pytricia` as requiring source build, add to the affected
Dockerfiles (proxy, test-runner, python-proxy):

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends gcc \
    && pip install pytricia==1.3.0 \
    && apt-get remove -y gcc && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*
```

Do **not** change `src/analytics/Dockerfile` — analytics is Phase 70.

### B — Update pyproject.toml

```toml
[tool.ruff]
target-version = "py314"   # was py311

[tool.mypy]
python_version = "3.14"    # if present
```

Run `make lint` to confirm zero new ruff violations.

### C — Build and Test

```bash
# Build all updated images
docker compose -f docker/docker-compose.poc.yml build
docker compose -f docker/docker-compose.test.yml build

# Run full test suite against the new images
make test
```

All 2687+ tests must pass with 0 failures. If any test fails due to a Python 3.14
deprecation (e.g., removed API), fix the call site before proceeding.

### D — Benchmark Validation

```bash
make bench 2>&1 | tee reports/benchmark/python314-stage1.md
```

Compare against `reports/benchmark/python311-baseline.md`. Document the delta table:

| Metric | Python 3.11 | Python 3.14 | Change |
|--------|-------------|-------------|--------|
| Bypass path (ms) | | | |
| Scoring path (ms) | | | |
| Full ALLOW (ms) | | | |
| Throughput (conn/s) | | | |

If scoring path improvement is < 10%, investigate whether:
- The Docker image is actually using the tail-call build (check `python3 -c "import sys; print(sys.version)"`)
- The JIT is activating (check `PYTHON_JIT=1` env var in Docker)

### E — Gate for Phase 69

Record the throughput ceiling from Step D. If it is ≥ 600 conn/s, the proxy is already
achieving the free-threading target and Phase 69 (free-threaded build) can be skipped
or deferred. Document the recommendation in `reports/benchmark/python314-stage1.md`.

---

## Files to Create / Modify

| File | Change |
|------|--------|
| `docker/Dockerfile` | 3.11.11-slim → 3.14.0-slim |
| `docker/Dockerfile.test` | 3.11.11-slim → 3.14.0-slim |
| `docker/Dockerfile.mockbackend` | 3.11.11-slim → 3.14.0-slim |
| `docker/Dockerfile.trafficgen` | 3.11.11-slim → 3.14.0-slim |
| `tarpit/Dockerfile` | 3.11.11-slim → 3.14.0-slim |
| `tests/docker/Dockerfile.test-runner` | 3.11-slim → 3.14-slim |
| `tests/docker/Dockerfile.python-proxy` | 3.11-slim → 3.14-slim |
| `tests/docker/Dockerfile.tls-backend` | 3.11-slim → 3.14-slim |
| `tests/docker/Dockerfile.recorder` | 3.11-slim → 3.14-slim |
| `pyproject.toml` | target-version py311 → py314 |
| `reports/benchmark/python314-stage1.md` (new) | After-upgrade benchmark results |
| `docs/phases/manifest.yaml` | Add Phase 67 |
| `CLAUDE.md` | Add Phase 67 to phase index |
| `CHANGELOG.md` | Phase 67 entry |

---

## Acceptance Criteria

- [x] All nine non-analytics Dockerfiles updated to `python:3.14.0-slim` (or `3.14-slim`)
- [x] `docker build` succeeds for all updated images
- [x] `make test` passes: 2687+ tests, 0 failures, 0 new skips
- [x] `make lint` passes with zero ruff violations under `target-version = "py314"`
- [x] Scoring path mean latency improves by ≥ 10% vs Phase 66 baseline
- [x] `reports/benchmark/python314-stage1.md` committed with before/after table
- [x] Phase 69 gate decision documented (proceed / defer based on throughput ceiling)
- [x] `CHANGELOG.md` entry for Phase 67

---

## What This Does Not Cover

- Application code changes — this is a pure image swap.
- Analytics container (`src/analytics/Dockerfile`) — Phase 70.
- Free-threaded build (`python:3.14t-slim`) — Phase 69.
- `uvloop` and JIT-aware code changes — Phase 68.
