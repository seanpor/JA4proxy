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

## Discovery

While auditing existing tooling I found the repo already has a working
`make link-check` target (Makefile:903) using `markdown-link-check`
(Node-based) with offline configuration in `.mlc.json` (ignores `https://`
and `http://localhost` patterns). The PHASE_105_review.md finding T1
recommended `lychee` without knowing this tool was already in place.

## Decision

**Retain `markdown-link-check`.** Add a CI job that invokes
`make link-check` (non-blocking for 14 days per the phase plan), rather
than introducing a parallel tool.

## Rationale

1. **It already works.** The existing target is wired up, configured, and
   produces useful output. Switching tools is scope creep.
2. **No CI gap.** The reason it lacked CI integration is the lack of a
   workflow file, not a tool inadequacy. Sub-task 105.10.3 closes that.
3. **Single source of truth.** A second tool would mean two configs
   (`.mlc.json` + `.lycheeignore`) drifting independently.
4. **Speed is not the bottleneck.** `markdown-link-check` finishes the
   docs tree in well under the 10-minute soft timeout for the new
   non-blocking job; sub-second matters for unit tests, not for a
   nightly/PR-triggered docs check.

## Consequences

**Positive:**
- Zero churn on existing tooling
- Engineers running `make link-check` locally already get the right answer
- `.mlc.json` already excludes external URLs, matching the offline-mode
  intent of the original ADR draft

**Negative:**
- `markdown-link-check` is unmaintained-ish (last release 2024); a future
  ADR may revisit `lychee` if `markdown-link-check` breaks on a Node
  version bump.
- Lychee's SHA-pinned Action would be marginally simpler than installing
  Node + npm in CI; but the existing CI already installs Node for
  policy-bundle work, so this cost is absorbed.

## Alternatives Considered

- **Switch to `lychee` (original review recommendation):** rejected. Tool
  already in place; replacing it is unjustified scope expansion. Recorded
  here so a future maintainer who hits a breakage has the alternative
  documented.
- **`mlc` (Marker's link checker):** less maintained, no SHA-pinned Action.
  Rejected.
- **Skip link-checking, rely on review:** rejected — review misses stale
  links exactly because the eye glides over text it expects to be correct.

## Implementation

**Local target (already in `Makefile:903`):**

```make
link-check:
	@echo "Checking internal documentation links..."
	@find docs/ -name '*.md' | xargs markdown-link-check --config .mlc.json
```

**Config (`.mlc.json`):**

```json
{
  "ignorePatterns": [
    {"pattern": "^https://"},
    {"pattern": "^http://localhost"}
  ],
  "retryOn429": true,
  "retryCount": 3,
  "timeout": "20s",
  "aliveStatusCodes": [200, 206]
}
```

**CI integration (sub-task 105.10.3):** add a job to the new
`docs-pdf.yml` workflow (or a separate `link-check.yml`) that:

- Uses Node setup action (SHA-pinned) → `npm install -g
  markdown-link-check@<pinned-version>`
- Runs `make link-check`
- `continue-on-error: true` for 14 days post-merge
- Triggered on `paths: ['docs/**', '*.md']`

## References

- `Makefile:903` — existing `link-check` target
- `.mlc.json` — link-check configuration
- `docs/phases/PHASE_105.md` §105j cross-cutting
- `docs/phases/PHASE_105_review.md` finding T1 (superseded by this ADR)
- `tests/test_workflow_pinning.py` — SHA-pin enforcement (applies to CI step)
