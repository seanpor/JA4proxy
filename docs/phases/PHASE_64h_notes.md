# Phase 64h — MTTR baseline notes

> **Sub-phase of:** Phase 64 (Deployment Validation & Disaster Recovery)
> **Size:** M
> **Status:** COMPLETE

## Deliverable
- `scripts/measure_mttr.sh` — executable MTTR measurement script
- `tests/test_phase64h_mttr.py` — TDD structural tests (no Docker required)
- `make measure-mttr` target appended to Makefile
- `MTTR_BASELINE.md` generated at runtime when script is executed against a live stack

## What was done

1. Created `scripts/measure_mttr.sh` implementing all four automated scenarios:
   - Scenario 1: Redis failure (RTO 300s)
   - Scenario 2: Single proxy node failure (RTO 120s)
   - Scenario 4: Dial corruption (RTO 180s)
   - Scenario 5: Redis data loss (RTO 300s)
2. Scenario 3 (total fleet failure) is intentionally excluded — GameDay-only.
3. Created TDD test suite validating script structure without Docker:
   - File existence and executable permission
   - Shebang and strict mode
   - Docker Compose v2 usage (no v1 `docker-compose`)
   - `COMPOSE` variable used for all compose commands
   - `HEALTH_URL` with correct default
   - Dynamic Redis volume derivation (never hardcoded)
   - `require_healthy` function presence
   - All four scenarios present with correct RTO targets
   - Overall PASS/FAIL computation
4. Added `measure-mttr` Makefile target.

## Test results

Tests validate structural correctness only. Actual MTTR values are recorded
when the script runs against a live Docker Compose stack.

| Scenario | Measured MTTR | RTO Target | Result |
|----------|--------------|------------|--------|
| 1: Redis failure | (run against live stack) | 300s | — |
| 2: Single node failure | (run against live stack) | 120s | — |
| 4: Dial corruption | (run against live stack) | 180s | — |
| 5: Redis data loss | (run against live stack) | 300s | — |

## Decisions made
- Script exits 0 (skip) if no Redis volume is found, allowing CI to pass
  without a running Docker stack.
- Redis volume name derived dynamically via `$COMPOSE volume ls | grep redis`.
- All compose commands go through `$COMPOSE` variable for portability.

## Prerequisite verification
- Redis volume name: derived dynamically from `docker compose volume ls`
- Health endpoint: `http://localhost:8090/api/v1/health/deep`
- Script uses `python3 -c` for JSON parsing of health responses

## Phase 101 entries surfaced
- None at this time. RTO failures would be filed if/when the script runs.
