---
phase: 218
title: "SHA-Pin Preflight Check & Scorecard Fix"
status: PROPOSED
size: SMALL
created: 2026-06-04
audience: [developer, devops]
---

# SHA-Pin Preflight Check & Scorecard Fix

## Goal

Fix the post-merge Scorecard CI failure caused by Phase 217 SHA-pinning
(annotated tag SHAs used instead of commit SHAs), and add a local preflight
check to prevent this class of error from reaching CI in the future.

## Scope

| File | Change |
|------|--------|
| `.github/workflows/scorecard.yml` | Replace 3 annotated tag SHAs with real commit SHAs |
| `.github/workflows/ci.yml` | Replace 1 annotated tag SHA with real commit SHA |
| `scripts/check-action-shas.py` | New script — validates all SHA-pinned `uses:` lines |
| `Makefile` | Add `lint-action-shas` target; add to `lint-all` |

## Implementation Plan

1. Fix `.github/workflows/scorecard.yml` SHAs:
   - `actions/checkout`: `34e1148…` → `b4ffde6…` (v4 → v4.1.1 commit)
   - `ossf/scorecard-action`: `e93faf2…` → `0864cf1…` (annotated tag → commit)
   - `github/codeql-action/upload-sarif`: `1521896…` → `7fd177f…` (annotated tag → commit)
2. Fix `.github/workflows/ci.yml` SHA:
   - `codecov/codecov-action`: `cddd853…` → `e79a696…` (annotated tag → commit)
3. Add `scripts/check-action-shas.py` — parses `uses: org/repo@SHA`, queries GitHub API, rejects annotated tag SHAs
4. Add `make lint-action-shas` and wire into `make lint-all`
5. Register Phase 218 in `manifest.yaml`
6. Branch `phase-218-sha-pin-preflight`, commit, PR, merge

## Test Strategy

- Run `python3 scripts/check-action-shas.py` on all workflow files — must exit 0
- Run `make lint-action-shas` — must exit 0
- Verify Scorecard workflow passes on the PR's CI run

## Acceptance Criteria

- [ ] `make lint-action-shas` exits 0
- [ ] Scorecard CI run on the PR branch passes
- [ ] All 4 annotated tag SHAs replaced with commit SHAs
- [ ] Preflight catches annotated tag SHAs before push

## Out of Scope

- Other pre-existing Scorecard failures unrelated to SHA verification
- Fixing the 98 pre-existing `lint-phases` violations
- Other workflow files whose SHAs were already correct
