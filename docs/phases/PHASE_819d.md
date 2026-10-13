---
phase: 819d
title: "Isolate measure-mttr on pentest-range"
status: PROPOSED
size: MEDIUM
created: 2026-10-13
audience: [developer, operations]
---

# Isolate measure-mttr on pentest-range

> **STATUS: PROPOSED — plan for junior developer execution.**
>
> Split from original Phase 819b. This phase addresses **F8/F9** (measure-mttr isolation and container execution).

## Goal

Ensure `measure-mttr` can run without modifying the developer's live dev lane, without running host `redis-cli` (complying with AGENTS.md container-strict rules), and using the completed `make pentest-range` isolated stack.

## Scope of Work (Junior Dev Checklist)

1. **Eliminate Host `redis-cli` Requirement**:
   - Update `scripts/measure-mttr.sh` to execute Redis operations inside the container (`docker compose exec redis redis-cli ...` or `docker run --rm ... redis:7-alpine redis-cli`).
2. **Project-Scoped Docker Commands**:
   - Fix `docker compose volume ls` to valid `docker compose volumes` or project-scoped checks.
   - Guard against teardown affecting active developer containers (ensure explicit `-p` project name targeting pentest range or isolated namespace).
3. **Clean Teardown & Trap**:
   - Add bash `trap` to restore any modified dial configuration (`config:dial`) on SIGINT/SIGTERM/exit.
   - Clean up any generated baseline Markdown without leaving untracked dirty tree state.
4. **Verification**:
   - Run `bash -n scripts/measure-mttr.sh` for syntax verification.
   - Verify `scripts/measure-mttr.sh` runs cleanly against `make pentest-range`.

## Acceptance Criteria
- `scripts/measure-mttr.sh` does not require host `redis-cli`.
- `measure-mttr` operates purely against isolated range without touching active dev lanes.
- Git working tree remains clean after execution.
