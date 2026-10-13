---
phase: 819d
title: "Isolate measure-mttr on pentest-range"
status: PROPOSED
size: MEDIUM
created: 2026-10-13
audience: [developer, operations]
---

# Isolate measure-mttr on pentest-range

> **STATUS: PROPOSED — plan incorporating Systems Reliability Expert Review.**
>
> Split from original Phase 819b. This phase addresses **F8/F9** (measure-mttr isolation, container-strict execution, and dev lane blast radius elimination).

## Goal

Ensure `scripts/measure_mttr.sh` operates without host `redis-cli`, without modifying the developer's live dev lane, without leaving untracked repository artifacts, and targets the isolated `pentest-range` stack safely.

## Scope of Work (Junior Dev Checklist)

1. **Eliminate Host `redis-cli` Requirement & Container-Strict Execution**:
   - In `scripts/measure_mttr.sh`:
     - Replace all host `redis-cli` invocations with a helper function executing within the container:
       ```bash
       redis_cmd() {
           $COMPOSE exec -T redis redis-cli "$@"
       }
       ```
     - For health checks targeting internal network topologies where ports are not published to host, route probes via container exec (`$COMPOSE exec -T attacker curl ...` or direct container inspection).
2. **Project & Volume Isolation (Zero Dev-Lane Blast Radius)**:
   - Fix invalid `$COMPOSE volume ls` syntax (replace with `docker volume inspect` or `$COMPOSE config --volumes`).
   - Prefix and scope docker compose commands by project (`-p ja4range` when targeting pentest-range, or configurable `COMPOSE_PROJECT_NAME`).
   - Fix Scenario 5 volume teardown sequence: containers referencing the volume must be removed before volume deletion (`$COMPOSE stop redis && $COMPOSE rm -f -v redis && docker volume rm "$FULL_VOLUME_NAME"`).
3. **Clean Teardown, Trap & Artifact Management**:
   - Add bash `trap cleanup EXIT INT TERM` to capture original `config:dial` and ensure restoration on interruption or completion.
   - Redirect output report from root `MTTR_BASELINE.md` to `.pentest-range/evidence/MTTR_BASELINE.md` or gitignored path `.local/MTTR_BASELINE.md` to maintain a clean git tree.
4. **Verification**:
   - Run `bash -n scripts/measure_mttr.sh` for syntax verification.
   - Run shellcheck or static verification.
   - Verify `scripts/measure_mttr.sh` operates cleanly without touching default compose projects.

## Acceptance Criteria
- `scripts/measure_mttr.sh` executes without host `redis-cli` installed.
- No host commands modify default development stack (`ja4proxy_redis-data` or `.env` state).
- Working tree remains clean (`git status -s` empty after execution).
- `make lint` and all CI gates pass.
