---
phase: 210
title: "Makefile Help Restructuring & Housekeeping"
status: PROPOSED
size: MEDIUM
created: 2026-05-30
audience: [developer, operator]
dependencies: []
---

# Makefile Help Restructuring & Housekeeping

## Goal

Reduce `make help` output from 111 lines of flat text to ~50 lines by sub-dividing into four sub-helps (`lint-help`, `scan-help`, `legacy-help`, `dev-help`). Clean up the monolithic `.PHONY` line (single 1600+ char line → grouped multi-line form). Add missing help entries for targets that were in `.PHONY` but undocumented. Document `on_unknown_ja4` and `dial_fail_closed` in `config/proxy.yml`. Add `.coverage*` to `.gitignore` to catch parallel-mode coverage temp files.

## Scope

### Files to modify
- `Makefile` — rewrite help target, add sub-helps, split `.PHONY` into groups
- `.gitignore` — change `.coverage` to `.coverage*`
- `config/proxy.yml` — add `on_unknown_ja4` and `dial_fail_closed` keys
- `docs/phases/manifest.yaml` — register Phase 210

### Files to create
- `docs/phases/complete/PHASE_210.md` — this document
- `docs/MAKEFILE_TARGETS.md` — comprehensive reference documenting every target

### Not in scope
- Adding or removing Makefile build logic (only help text / metadata changes)
- Changing test or lint behaviour
- Modifying the CI pipeline

---

## Implementation Plan

1. **Split `.PHONY` line** into grouped `.PHONY` declarations (one per target category) for maintainability.
2. **Rewrite `help` target** from 111 lines of flat echo to ~50 lines with cross-references to four sub-helps: `lint-help`, `scan-help`, `legacy-help`, `dev-help`.
3. **Create sub-help targets** (`lint-help`, `scan-help`, `legacy-help`, `dev-help`) that group targets by category.
4. **Add missing help entries** for targets that had `.PHONY` entries but no help text.
5. **Update `.gitignore`** — `s/.coverage/.coverage*/` to catch parallel-mode temp files.
6. **Update `config/proxy.yml`** — document `on_unknown_ja4` and `dial_fail_closed` keys with phase 209 provenance.
7. **Create `docs/MAKEFILE_TARGETS.md`** — full reference doc with every target, its description, arguments, and prerequisites.
8. **Sync roadmap** (`python3 scripts/sync-roadmap.py`).
9. **Run lint-phases** (`make lint-phases`) to validate.

---

## Test Strategy

- **No functional tests needed** — no logic changed, only help text and metadata.
- **Lint check:** `make lint-phases` must exit 0 (manifest + phase doc integrity).
- **Visual check:** `make help` must display correctly and the sub-helps (`make lint-help`, `make scan-help`, etc.) must render.

---

## Acceptance Criteria

- [x] `make help` output reduced from 111 lines to ~50 lines.
- [x] `make lint-help`, `make scan-help`, `make legacy-help`, `make dev-help` each render a focused category list.
- [x] `.PHONY` split into ~20 grouped lines (no single 1600+ char line).
- [x] Every target in `.PHONY` has a corresponding help entry in at least one sub-help.
- [x] `.coverage*` in `.gitignore` excludes parallel-mode temp files.
- [x] `on_unknown_ja4` and `dial_fail_closed` documented in `config/proxy.yml`.
- [x] `docs/MAKEFILE_TARGETS.md` covers every target with description, args, and prerequisites.
- [x] `make lint-phases` exits 0.

---

## Out of scope

- Changing build, test, lint, or operational logic in the Makefile.
- Adding or removing actual targets.
- CI pipeline changes.
- Coverage thresholds or reporting changes.
