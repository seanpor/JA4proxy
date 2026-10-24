<!--
title: Verify Main After An App-Authored Merge
audience: developer
last_reviewed: 2026-10-23
phase: 849
-->

# Phase 849 — Verify `main` after an app-authored merge

> **Size:** SMALL
> **Dependencies:** 847c
> **Branch:** `phase-849-verify-main-after-app-merge`
> **Fixes:** issue #622

---

## Goal

Close the one hole in "every commit on `main` has been through CI": a PR merged
by the GitHub Actions app lands with **no `push` run at all**.

## Why it happens

GitHub suppresses workflow triggers for events caused by the default
`GITHUB_TOKEN` (the anti-recursion rule). Auto-merge performed by a workflow —
`dependabot-automerge.yml`, `maintainer-automerge.yml`, and any bot that calls
`gh pr merge` with that token — therefore pushes the squash commit to `main` as
`app/github-actions`, and `ci.yml`'s `push: branches: [main]` trigger never
fires. The PR's own checks were green *before* the merge commit existed; the
commit that is actually on `main` was never built or scanned.

Evidence on this repository: PR #620's merge commit (`fd592b98`) has no CI run
on `main`; the human-merged commits around it do. Merges performed with a
personal token (as an agent session or maintainer does) are unaffected, which
is why the gap appears intermittent.

## Why not fix the root cause

The root cause is a GitHub platform rule. Removing it needs a long-lived
personal access token (or a GitHub App with `workflows: write`) stored as a
secret and used for every merge — a standing credential with repo-wide write
that buys nothing the check below does not, and which would itself need
rotation and review. The report-and-repair loop is smaller, needs no new
credential, and — unlike the token — is testable offline.

## Scope

### 1. A pure decision, and a thin executor

New script `scripts/ensure_main_verified.py`:

```text
main tip (or --sha X)  ->  gh run list --commit SHA  ->  decide()
                                                          |
        +-- a CI run for that commit (any status)  -> verified, exit 0
        +-- no CI run, --apply                     -> gh workflow run ci.yml --ref main
        +-- no CI run, no --apply                  -> report, exit 1
```

`decide(runs, sha, workflow_name="CI")` is pure and is the whole test surface.
"Verified" means **the workflow ran against that commit**, not that it passed: a
failed run is a real, already-visible signal, and re-dispatching it would loop
forever. A queued/in-progress run also counts — a dispatch would duplicate it.

`--sha` implies report-only: dispatching `ci.yml --ref main` verifies *today's*
tip, so pretending it verifies an arbitrary old commit would be a lie in a log.
That mode exists to prove the gap on a known app-merged commit.

### 2. The loop that closes it

New workflow `main-verification.yml`:

| Trigger | Why |
|---|---|
| `workflow_run` completed for `Dependabot auto-merge` and `Maintainer auto-merge` | The exact merges that skip `push` — repaired within a minute, not at the next sweep |
| `schedule` every 30 minutes (offset slot) | Catches every other app-token merge path, including a future bot nobody wired up |
| `workflow_dispatch` | So a maintainer can ask "is main verified?" and get an answer |

`permissions: contents: read, actions: write`; `concurrency` so overlapping
triggers cannot dispatch twice; the job is never required and cannot block a
merge. It reuses the same reporting convention as the other scheduled jobs.

### 3. Make the report legible

The script prints one line: the commit, the verdict, and — when dispatching —
the run URL it created. On failure (gh unavailable, no permission) it exits 2
with the reason, because "the verifier could not run" must never read as
"main is verified".

## Implementation plan

| Step | Change | File |
|---|---|---|
| 1 | `decide()` + `main()` with `--sha`, `--apply`, `--workflow-name` | `scripts/ensure_main_verified.py` |
| 2 | Workflow: `workflow_run` + `schedule` + `workflow_dispatch`, SHA-pinned actions | `.github/workflows/main-verification.yml` |
| 3 | Tests: decision table (including "failed CI still counts") and the four `main` outcomes with a fake `gh` | `tests/unit/test_ensure_main_verified.py` |
| 4 | Docs: `SCRIPTS.md`, `MAINTENANCE_CALENDAR.md` (slot + why), fragment | `docs/` |
| 5 | Prove the gap live: run the script with `--sha fd592b98` (app merge → exit 1) and with no args (human-merged tip → exit 0), paste both in the PR | PR body |

## Test strategy

1. **Decision table**, one assertion each: no runs → not verified; completed
   success → verified; in-progress → verified (no duplicate dispatch); completed
   **failure** → verified (do not loop); a different workflow's run only → not
   verified; a run for another SHA → not verified.
2. **Executor**: `--apply` on an unverified tip dispatches exactly once with the
   expected argv; without `--apply` it exits 1 and dispatches nothing; `--sha`
   never dispatches even with `--apply`; a failing `gh` exits 2.
3. **Workflow lint**: `actionlint` + `yamllint` (`make lint`) and the
   SHA-pinning test (`tests/test_workflow_pinning.py`) cover the YAML.
4. The live proof in step 5 is the acceptance test: the detector must flag a
   commit that genuinely has no run, or it is testing nothing.

## Acceptance criteria

- [x] `python3 scripts/ensure_main_verified.py --sha <app-merged SHA>` exits 1
      and names the missing run (verified live on `fd592b98`).
- [x] The same command for a human-merged `main` commit exits 0.
- [x] `--apply` dispatches `ci.yml` against `main` when the tip is unverified,
      and does not when it is not.
- [x] No dispatch loop: a run that exists but failed is not re-dispatched.
- [x] The job is not a required check; a broken verifier cannot block a merge.
- [x] `make preflight` green.

## Out of scope

- Replacing the app token with a PAT (rejected above, with the reason).
- Re-running a *failed* CI (that is a human decision, and the failing run is
  already visible on the commit).
- Verifying commits that were force-pushed away — they are not on `main`.

---

## Close-out

**Status:** COMPLETE (2026-10-23) — PR #645 (`f05ebcea`).

### Outcome

| Property | Before | After |
|---|---|---|
| Does an app-authored merge get verified on `main`? | no — GitHub suppresses `push` for `GITHUB_TOKEN` | yes — `ensure_main_verified.py` detects unverified tips |
| How quickly is a missed run repaired? | never | ~1 min via `workflow_run` on auto-merge workflows, backstopped by :13/:43 sweep |
| Can the verifier loop indefinitely? | n/a | no — `decide()` treats any completed run (success or fail) or in-progress run as verified |
| Can a broken verifier block merging? | n/a | no — not a required check |
| Local inspection | n/a | `make verify-main` / `python3 scripts/ensure_main_verified.py` |

### Evidence

- `tests/unit/test_ensure_main_verified.py` — decision matrix tests + executor CLI tests with fake `gh`.
- Live demonstration on `fd592b98`: correctly identified missing push run (exit 1).
- Live verification on current `main` tip `f05ebcea`: exit 0 (verified by run `39958242845`).
- Workflow `main-verification.yml` executed successfully in production (run `39958401449`).

### Honest limits
- The verifier triggers `ci.yml` against the current tip of `main` via `workflow_dispatch`; it does not run retrospective builds for older, superseded commits.
- A failing CI run is intentionally not re-dispatched to avoid infinite loops; failures require maintainer attention.
