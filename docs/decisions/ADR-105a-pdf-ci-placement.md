<!--
title: "ADR-105a — PDF Build Workflow Placement"
audience: maintainers, contributors
last_reviewed: 2026-04-25
phase: 105
-->

# ADR-105a — PDF Build Workflow Placement

> **Status:** Accepted
> **Phase:** 105
> **Date:** 2026-04-25
> **Decider:** Phase 105 maintainer
> **Consulted:** none (low-risk DevOps decision)

## Context

Phase 105 refreshes three PDF artefacts (`brochure.pdf`, `user-guide.pdf`,
`reference-manual.pdf`) sourced from LaTeX in `docs/pdf/{brochure,user-guide,
reference-manual}/`. Acceptance criterion §105h calls for CI to rebuild the
three PDFs on every change under `docs/pdf/**` and publish them as workflow
artefacts.

Two placements are viable:

- **Option A:** Add a new dedicated workflow `.github/workflows/docs-pdf.yml`
  triggered on `paths: ['docs/pdf/**']`.
- **Option B:** Extend the existing `.github/workflows/ci.yml` with a new job.

## Decision

**Option A** — new dedicated workflow `.github/workflows/docs-pdf.yml`.

## Rationale

1. **Don't slow every PR.** A LaTeX install (~1 GB TeXLive container, even with
   a pinned action) adds ~2–3 minutes to job runtime. `ci.yml` runs on every
   PR; adding a job that runs only when `docs/pdf/**` changes would still
   trigger the runner spin-up cost.
2. **Path filter precision.** `paths:` filters at the workflow level are
   simpler to reason about than per-job `if:` guards inside `ci.yml`.
3. **Initial non-blocking window.** Per phase doc §Notes, the PDF build is
   non-blocking for 14 days post-merge. Isolating it in its own workflow
   makes "non-blocking" trivially enforceable (the workflow either runs or
   doesn't; nothing to wire into existing required-status-checks config).
4. **Future room.** The same workflow can later attach the PDFs to GitHub
   Releases (acceptance criterion in 105h) without bloating `ci.yml`.

## Consequences

**Positive:**
- Zero impact on PR feedback latency for non-PDF changes
- Clean separation of concern; PDF build failures don't block code merges
- Easy to promote to required check after the 14-day grace period

**Negative:**
- Two workflows to maintain instead of one
- Cross-workflow status visibility is slightly worse (operators need to
  remember a separate workflow exists)

**Mitigations:**
- Workflow is referenced from `QUALITY_PLAN.md`
- Pre-existing pattern: `process-metrics.yml` (Phase 106) already proves the
  "narrow-scope dedicated workflow" pattern works for this repo

## Alternatives Considered

- **Option B (extend `ci.yml`):** rejected. Slows every PR; harder to enforce
  the 14-day non-blocking window without conditional `continue-on-error`
  logic that survives the policy clock.
- **No CI rebuild (manual):** rejected. The phase explicitly calls for drift
  detection between LaTeX source and committed PDFs; manual rebuild won't
  catch divergence until release.
- **Switch to `tectonic` for single-binary builds:** out of scope. Current
  Makefile uses `pdflatex` + `makeindex`; toolchain change is a separate
  decision and can be revisited in a future ADR.

## Implementation

- New workflow: `.github/workflows/docs-pdf.yml`
- Pinned actions: `actions/checkout` (SHA-pinned), `xu-cheng/latex-action`
  (SHA-pinned) — matches the pinning policy enforced by
  `tests/test_workflow_pinning.py`
- `continue-on-error: true` on the build job for the 14-day grace period
  ending **2026-05-09**; promote to required after that date
- Triggers: `pull_request` and `push` to `main`, both filtered to
  `docs/pdf/**`
- Artefacts uploaded with names `brochure`, `user-guide`, `reference-manual`

## References

- `docs/phases/complete/PHASE_105.md` §105h
- `docs/phases/complete/PHASE_105_review.md` findings D1, D2, D3, S5
- `tests/test_workflow_pinning.py` — SHA-pin enforcement
