# Phase 64h — MTTR Baseline Notes

## Artifacts Created

| File | Purpose |
|------|---------|
| `scripts/measure_mttr.sh` | MTTR measurement script |
| `Makefile` target `measure-mttr` | Makefile entry point |

## Shellcheck Result

- `shellcheck scripts/measure_mttr.sh` — **PASS** (zero findings)

## Key Improvements Over Original Plan

1. **Dynamic proxy container name** — derives from `docker compose ps --format json` instead of hardcoding `ja4proxy-1`
2. **redis-cli pre-flight** — checks availability and connectivity before running, skips with install hint if missing
3. **Dynamic Redis volume name** — derives from `docker compose volume ls` instead of hardcoding
4. **All redis-cli calls redirect stderr** — avoids noisy output in measurement logs
5. **Scenario 1 uses flexible degraded-state detection** — checks for `redis != 'healthy'` instead of requiring exact `'unreachable'` value

## Acceptance Checklist

- [x] Script derives proxy container name from compose (not hardcoded)
- [x] Script checks `redis-cli` availability and connectivity before running
- [x] Script derives Redis volume name from `docker compose volume ls`
- [x] Script runs Scenarios 1, 2, 4, 5 (Scenario 3 is GameDay-only)
- [x] Script writes `MTTR_BASELINE.md` with results table
- [x] Script exits 0 if all scenarios within RTO, 1 otherwise
- [x] All `redis-cli` calls redirect stderr to `/dev/null`
- [x] `make measure-mttr` invokes the script
- [x] Shellcheck: zero findings
- [x] Uses `docker compose` (v2) throughout

## Out of Scope

- Scenario 3 (total fleet failure) automation — deliberately GameDay-only
- Running the script live (requires full Docker Compose stack) — done during validation
- K8s MTTR measurement (deferred until K8s deployment validated)
