---
phase: 221
title: PDF Content Refresh — Reconcile Brochure, User Guide, Reference Manual
status: PROPOSED
size: LARGE
created: 2026-06-04
audience: [developer, documentation]
---

# PDF Content Refresh

## Goal

Reconcile the three LaTeX-based PDFs in `docs/pdf/` (brochure, user guide, reference manual) against the current state of the codebase and living documentation. The PDFs were authored around Phase 15 (April 5) and have not been refreshed through Phases 105, 200–219. Each PDF is a separate sub-phase with a handover note so the next sub-phase knows what changed.

A `%% Last updated: YYYY-MM-DD` comment line is added to the root `.tex` file of each PDF, tracking the most recent content edit (independent of the PDF build date).

## Sub-Phase Overview

| Sub-phase | Document | Files | Est. changes |
|-----------|----------|-------|-------------|
| **A** | Brochure | `brochure-body.tex` + `README.md` | ~10-15 line edits (light refresh) |
| **B** | User Guide | 5 chapter `.tex` files + `GETTING_STARTED.md` | ~50-80 line edits across 5 chapters |
| **C** | Reference Manual | 5 chapter `.tex` files | ~80-120 line edits across 5 chapters |

Each sub-phase is an atomic commit. The build (`make clean && make all`) is run after each sub-phase to confirm no regressions.

## Memory / Handover Notes

Between sub-phases, the agent writes a handover note at the bottom of this phase doc (under `## Handover Log`) recording:
- What files were edited
- Key substitutions or claims updated
- Any tricky sections or decisions made
- What the next sub-phase should be aware of

This avoids re-reading every living doc from scratch.

### A — Brochure Refresh

**Scope:**
- `docs/pdf/brochure/brochure-body.tex` — update security posture claims, add Phase 200-series hardening line, verify benchmark numbers
- `README.md` — update PDF table date marker
- `docs/pdf/brochure/brochure.tex` — add `%% Last updated: YYYY-MM-DD` line after the existing header comment

**Implementation:**
1. Read current `brochure-body.tex` to identify stale claims
2. Read `docs/performance/BENCHMARK_HISTORY.md` and relevant Phase 200-series docs to get current numbers
3. Edit `brochure-body.tex`: update claims, add hardening posture
4. Add `%% Last updated:` to `brochure.tex`
5. Edit `README.md` PDF table date
6. `cd docs/pdf && make clean && make all` — verify zero warnings
7. Commit: `docs/pdf/brochure/`, `README.md`

### B — User Guide Refresh

**Scope:**
- `docs/pdf/user-guide/chapters/ch01-introduction.tex` — remove Phase 15 framing, position as Go-production guide
- `docs/pdf/user-guide/chapters/ch02-installation.tex` — reflect current `Dockerfile.go-proxy` (non-root, USER directive), env-var credentials
- `docs/pdf/user-guide/chapters/ch04-configuration.tex` — reconcile against `config/proxy.yml`
- `docs/pdf/user-guide/chapters/ch05-operations.tex` — reconcile against `docs/OPERATIONS_GUIDE.md`
- `docs/pdf/user-guide/chapters/ch07-incident-response.tex` — reconcile against `docs/INCIDENT_RESPONSE.md`
- `docs/pdf/user-guide/user-guide.tex` — add `%% Last updated: YYYY-MM-DD`
- `docs/GETTING_STARTED.md` — add "Building PDFs" subsection

**Implementation:**
1. Read the 5 chapter `.tex` files + their living-doc counterparts in parallel
2. Apply edits per chapter
3. Add `%% Last updated:` to `user-guide.tex`
4. Add PDF build instructions to `GETTING_STARTED.md`
5. Build and verify
6. Commit: `docs/pdf/user-guide/`, `docs/GETTING_STARTED.md`

### C — Reference Manual Refresh

**Scope:**
- `docs/pdf/reference-manual/chapters/ch01-architecture.tex` — Go runtime as primary, Python as prototyping
- `docs/pdf/reference-manual/chapters/ch04-signals.tex` — add Phase 203 signals
- `docs/pdf/reference-manual/chapters/ch06-redis-schema.tex` — reconcile against `docs/REDIS_SCHEMA.md`
- `docs/pdf/reference-manual/chapters/ch09-security-ref.tex` — add Phase 200-series hardening
- `docs/pdf/reference-manual/chapters/ch10-compliance.tex` — reconcile against `docs/compliance/`
- `docs/pdf/reference-manual/reference-manual.tex` — add `%% Last updated: YYYY-MM-DD`

**Implementation:**
1. Read the 5 chapter `.tex` files + their living-doc counterparts in parallel
2. Apply edits per chapter
3. Add `%% Last updated:` to `reference-manual.tex`
4. Build and verify
5. Commit: `docs/pdf/reference-manual/`

## "Last Updated" Convention

Every root `.tex` file (`brochure.tex`, `user-guide.tex`, `reference-manual.tex`) gets a comment line after the existing header:

```latex
%% Last updated: 2026-06-04
```

This is a **human-maintained** date. It is updated only when the *text content* of that PDF's source files is edited (not on PDF-only rebuilds). This gives readers a quick way to check whether the content has been refreshed without comparing PDF build timestamps.

## Test Strategy

- **Build verification:** `cd docs/pdf && make clean && make all 2>&1` must exit 0 with zero LaTeX warnings, after each sub-phase
- **Render verification:** Spot-check PDF output for garbled text or missing sections
- **CI verification:** `Docs PDF Build` workflow must produce 3 artifacts on the final push

## Acceptance Criteria

1. `cd docs/pdf && make clean && make all` exits 0 with zero LaTeX warnings
2. All three PDFs produced with non-zero file sizes
3. Each root `.tex` has a `%% Last updated:` date matching the commit date
4. Brochure references Phase 200-series security posture
5. User-guide chapters 1, 2, 4, 5, 7 reconciled against living docs
6. Reference-manual chapters 1, 4, 6, 9, 10 reconciled; Phase 203 signals and Phase 200-series hardening present
7. `README.md` PDF table date updated
8. `docs/GETTING_STARTED.md` has "Building PDFs" subsection
9. `make lint-phases` exits 0
10. `make test` exits 0

## Out of Scope

- Switching LaTeX engine (no tectonic/latexmk migration)
- Adding new chapters or source files
- Non-PDF documentation beyond GETTING_STARTED.md
- PDF release workflow attachment

## Handover Log

*Appended after each sub-phase by the implementing agent.*
