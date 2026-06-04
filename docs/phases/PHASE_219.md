---
phase: 219
title: "Restore Deleted Phase Documentation"
status: PROPOSED
size: SMALL
created: 2026-06-04
audience: [developer, devops]
---

# Restore Deleted Phase Documentation

## Goal

Restore the 98 phase documentation files deleted by Phase 144 ("Pruning &
Operational Excellence") to fix `make lint-phases` exit status. The manifest
still references these files; this phase reconciles reality with the manifest
by restoring the files from git history.

## Scope

| File | Change |
|------|--------|
| `docs/phases/complete/*.md` | Restore ~73 files from `c53ced20^` |
| `docs/phases/cancelled/*.md` | Restore ~10 files from `c53ced20^` |
| `docs/phases/PHASE_[101,214,215,216].md` | Restore ~4 files from `c53ced20^` |
| `docs/phases/manifest.yaml` | Register Phase 219 only |

## Implementation Plan

1. Extract the list of missing files from `python3 scripts/lint-phases.py`
2. Restore each from the commit before Phase 144 (`c53ced20^`)
3. Run `python3 scripts/lint-phases.py` — must exit 0
4. Run `python3 scripts/sync-roadmap.py`
5. Branch `phase-219-restore-phase-docs`, PR, merge

## Test Strategy

- `make lint-phases` must exit 0 after the restore
- Only `.md` files are touched — no code changes

## Acceptance Criteria

- [ ] `make lint-phases` exits 0
- [ ] All 98 missing files restored from git history
- [ ] No code or config changes beyond phase docs

## Out of Scope

- Auditing the content of restored docs for accuracy
- Moving active-phase docs (101, 214, 215, 216) to `complete/`
