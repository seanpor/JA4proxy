<!--
title: "ADR-105b — Link-Check Tool Selection"
audience: maintainers, contributors
last_reviewed: 2026-04-25
phase: 105
-->

# ADR-105b — Link-Check Tool Selection

> **Status:** Accepted
> **Phase:** 105
> **Date:** 2026-04-25
> **Decider:** Phase 105 maintainer

## Context

Phase 105 restructures the documentation corpus and moves/archives several
files. Without a link checker the team has no automated way to detect:

- Broken internal links after a doc move
- Stale references to archived reports (`GEMINI_CRITIQUE.md`,
  `ENTERPRISE_REVIEW.md`)
- Stub-redirect mistakes after consolidation (TESTING_*, blocking-*)

A link checker is required for the Wave 3 hardening sweep
(sub-task 105.10.1) and as a non-blocking CI check (105.10.3).

## Decision

Use **`lychee`** invoked via the GitHub Action `lycheeverse/lychee-action`
(SHA-pinned), with a `make link-check` target wrapping the offline mode for
local runs.

## Rationale

1. **Speed.** `lychee` is written in Rust and walks the whole `docs/` tree in
   under 5 seconds offline.
2. **Markdown + HTML aware.** Handles `.md` reference links, image links,
   relative paths, anchors, and embedded HTML — covers everything in this
   repo.
3. **SHA-pinnable Action.** `lycheeverse/lychee-action` is a published
   GitHub Action that accepts a 40-char SHA, satisfying the
   `tests/test_workflow_pinning.py` enforcement.
4. **Offline mode.** `lychee --offline` validates only relative links;
   external-URL flakiness (rate-limits, transient DNS) doesn't cause spurious
   CI failures during the 14-day non-blocking window.
5. **No new runtime dep.** `lychee` is a single binary; no Node/Python deps.

## Consequences

**Positive:**
- Catches broken internal links before merge
- Local `make link-check` matches CI behaviour exactly (same binary)
- Zero impact on test runtime (link-check is its own CI job)

**Negative:**
- `lychee` does not validate anchors against rendered HTML; it checks
  `#section` exists in the source markdown only. Acceptable: GitHub renders
  anchors deterministically from headings.
- External URL checking is opt-in. Network drift is detected only when
  `--offline` is dropped. Initial scope: offline only.

## Alternatives Considered

- **`markdown-link-check`** (Node): slower (~30s for our tree), heavier
  toolchain (npm install), less robust on relative paths. Rejected.
- **`mlc` (Marker's link checker):** less maintained, no SHA-pinned Action.
  Rejected.
- **Custom grep-based script:** brittle; cannot resolve `[text](path)` vs
  `[text]: path` reference styles uniformly. Rejected.
- **Skip link-checking, rely on review:** rejected — review misses stale
  links exactly because the eye glides over text it expects to be correct.

## Implementation

**Local target (`Makefile`, added in this phase):**

```make
link-check:
	@command -v lychee >/dev/null 2>&1 || { \
	  echo "lychee not installed. Install: cargo install lychee  OR  brew install lychee"; \
	  exit 1; }
	@lychee --offline --no-progress \
	  --exclude-path docs/pdf \
	  --exclude-path docs/reports/archive \
	  docs/ README.md CONTRIBUTING.md SECURITY.md AGENTS.md CLAUDE.md
```

`docs/pdf/` and `docs/reports/archive/` are excluded:
- PDF source contains LaTeX `\href{}` directives that lychee does not parse
- Archive contents are historical snapshots; their links may legitimately
  point to since-moved or deleted files

**CI integration:** sub-task 105.10.3 — separate workflow, SHA-pinned
action, `continue-on-error: true` for 14 days.

## References

- `docs/phases/PHASE_105.md` §105j cross-cutting
- `docs/phases/PHASE_105_review.md` findings T1, T2
- `tests/test_workflow_pinning.py` — SHA-pin enforcement (applies to CI step)
