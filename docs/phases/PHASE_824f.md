<!--
title: Journey_CI_Tiering_And_Branch_Protection
audience: developer
last_reviewed: 2026-10-15
phase: 824f
-->

# Phase 824f — CI Tiering and Branch Protection

> **Status:** PROPOSED
> **Size:** SMALL
> **Dependencies:** Phase 824d, Phase 824e
> **Part of:** Phase 824 (umbrella) — see `docs/phases/PHASE_824.md`

---

## Goal

Wire the new UI checks into CI, and make only the **cheap, deterministic** tiers
required on `main`. Expensive or stateful checks run on a schedule or on demand.

---

## Scope

**In:** a CI job for the T1 checks (824b/824c/824d); a non-required job for T2
(824e); updating `scripts/branch_protection.sh` to match.

**Out:** changing the T2/T3 scripts; anything that requires repository settings
beyond the branch-protection context sync.

---

## 824f.1 T1 is required, T2 is not

| Tier | Workflow | Required on `main`? |
|---|---|---|
| T1 (static: route/endpoint contract) | `.github/workflows/ci.yml` | **yes** — fast, deterministic, no stack |
| T2 (live journeys) | `.github/workflows/` (new job) | no — `continue-on-error`, nightly + on demand |

Rule: a check that brings up a stack and can flake must **not** be required.
A flaky required check blocks every merge and is disabled within a week. Only
add T2 to the required set if it has been stable for a sustained period.

## 824f.2 Keep the branch-protection context list in sync

`tests/test_workflow_pinning.py:318`
(`test_branch_protection_contexts_match_ci_job_names`) asserts that the contexts
listed in `scripts/branch_protection.sh` equal ci.yml's non-`continue-on-error`
job names plus the declared external contexts. Any new **required** job must be
added to that script in the same change, or the test fails.

Do not add the T2 job to `scripts/branch_protection.sh` — it is not required.

## 824f.3 Pin actions

Every `uses:` must be SHA-pinned (repo convention; enforced by
`tests/test_workflow_pinning.py`). Copy the pins from an adjacent job.

---

## Acceptance Criteria

- [ ] A CI job runs the T1 checks (824b/824c/824d) and is required.
- [ ] The T2 job runs the journey scripts, is `continue-on-error`, and is
      scheduled nightly plus `workflow_dispatch`.
- [ ] `scripts/branch_protection.sh` matches the required job set exactly.
- [ ] `python -m pytest tests/test_workflow_pinning.py` passes.
- [ ] YAML has no duplicate job names (verify with `rg` after editing).
- [ ] `make lint` passes.
- [ ] A fragment exists at `docs/fragments/phase-824f-*.md`.

---

## Files to Modify

| File | Change |
|------|--------|
| `.github/workflows/ci.yml` | Add the T1 required job |
| `.github/workflows/journeys.yml` | New file — T2 nightly + `workflow_dispatch` |
| `scripts/branch_protection.sh` | Register the new required T1 context |
| `docs/fragments/phase-824f-ci-tiering.md` | New file — changelog fragment |

---

## Notes for Implementer

- This is the only Phase 824 sub-phase that affects `main`'s protection. Change
  the workflow and the protection script in the **same PR**; landing one without
  the other leaves the repo red for everyone.
- Verify the pinning test locally before pushing — it is the exact check that
  fails when the context list drifts.
