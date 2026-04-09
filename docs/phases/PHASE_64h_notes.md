# Phase 64h — MTTR baseline notes

> **Sub-phase of:** Phase 64 (Deployment Validation & Disaster Recovery)
> **Size:** M
> **Status:** NOT STARTED

## Deliverable
- `scripts/measure_mttr.sh`
- `make measure-mttr` target (append to bottom)
- `MTTR_BASELINE.md` (committed after running once)

## What was done
<!-- Record host CPU/RAM, Docker Compose version, and the four measured MTTR values. -->

## Test results

| Scenario | Measured MTTR | RTO Target | Result |
|----------|--------------|------------|--------|
| 1: Redis failure | — | 300s | — |
| 2: Single node failure | — | 120s | — |
| 4: Dial corruption | — | 180s | — |
| 5: Redis data loss | — | 300s | — |

## Decisions made
<!-- Note any deviations from the spec in PHASE_64.md. If any scenario failed its RTO,
file a Phase 101 entry rather than lowering the target. -->

## Prerequisite verification
<!-- Record:
- Redis volume name derived from `docker compose volume ls` (not hardcoded)
- `socat` availability in HAProxy container (for Scenario 2)
- Health endpoint path verified -->

## Phase 101 entries surfaced
<!-- File any RTO failures or infrastructure gaps. -->
