# Automated Cascading Rebase for Dependabot PRs

## Goal
Eliminate manual toil in processing Dependabot PRs by creating an automated cascading rebase mechanism in GitHub Actions, maintaining strict branch protection (`strict: true`) on `main` without stalling the merge queue.

## Background
- `main` is protected by `require_status_checks.strict: true`. Every PR must be tested against the latest commit of `main` before squash-merging.
- Dependabot generates batches of PRs against an identical base commit.
- Once the first PR merges into `main`, all other open PRs transition to `mergeStateStatus: BEHIND`.
- Because GitHub Merge Queue is unavailable for personal accounts (Phase 332), PRs in state `BEHIND` sit idle indefinitely unless rebased.
- Phase 812 (812-D) implemented `.github/workflows/dependabot-pr-refresh.yml` to refresh stale failing PRs on `main` pushes via close/reopen, but explicitly skips passing or un-updated PRs and does not issue server-side branch updates for `BEHIND` PRs.

## Scope
1. **Extend `scripts/dependabot_pr_refresh.py`**: Support evaluating PR currency (`behind` / `clean` / `blocked`) and return an `UPDATE_BRANCH` action when a Dependabot PR is mergeable but `BEHIND`.
2. **Update `.github/workflows/dependabot-pr-refresh.yml`**:
   - Query PR mergeable state via GitHub API (`mergeable_state`).
   - If a PR is `behind` (and not in conflict / `dirty`), call `PUT /repos/{owner}/{repo}/pulls/{number}/update-branch`.
   - Update only the oldest eligible PR per push to prevent thundering-herd CI stampedes. Once that PR passes and merges, the resulting push to `main` automatically triggers the next PR in the cascade.
   - If a PR is `dirty` (conflicted), post `@dependabot rebase`.
3. **Unit Tests**: Update `tests/unit/test_dependabot_pr_refresh.py` to cover `UPDATE_BRANCH` decision logic and state transitions.

## Implementation Plan

### Step 1: Decision Logic (`scripts/dependabot_pr_refresh.py`)
Add support for `--merge-state` (e.g. `behind`, `clean`, `dirty`, `blocked`, `unknown`):
- If `merge_state == "behind"` and checks are not pending: emit `UPDATE_BRANCH`.
- If `merge_state == "dirty"`: emit `CONFLICT_REBASE`.
- Maintain existing `REFRESH` behavior for failing checks.

### Step 2: Workflow Enhancement (`.github/workflows/dependabot-pr-refresh.yml`)
- Fetch `mergeable_state` for open Dependabot PRs.
- Execute server-side rebase `gh api -X PUT repos/${{ github.repository }}/pulls/$number/update-branch`.
- Break after triggering the first update to serialize the pipeline cleanly.

### Step 3: Tests & Validation
- Run unit tests in `ja4proxy-tools` container: `pytest tests/unit/test_dependabot_pr_refresh.py`.
- Run meta-lint and phase validation: `make lint-phases`.

## Acceptance Criteria
1. `scripts/dependabot_pr_refresh.py` correctly distinguishes between `REFRESH` (failing check) and `UPDATE_BRANCH` (`behind`).
2. Unit tests in `tests/unit/test_dependabot_pr_refresh.py` pass 100%.
3. Workflow YAML passes syntax and lint validation.
4. When pushed to `main`, the workflow automatically advances the next eligible `BEHIND` Dependabot PR.

## Out of Scope
- Disabling `strict: true` on `main` (declined in favor of guaranteed semantic safety).
- Removing manual review for major semver bumps (governed by Phase 302 policy).
