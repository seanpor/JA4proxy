# Autonomous PR Cascade Dispatcher & Zero-Babysitter Automation

## Goal
Eliminate manual babysitting of pull requests by deploying an autonomous PR cascading rebase engine and maintainer auto-merge workflow. Under GitHub strict branch protection (`required_status_checks.strict: true`), any PR merge causes open sibling PRs to enter `mergeStateStatus: BEHIND`, which blocks GitHub's native auto-merge engine. This phase introduces an automated cascade dispatcher that detects behind PRs with active auto-merge and rebases them automatically on every push to `main` (and periodic fallback), maintaining a fully automated, continuous delivery queue without manual intervention.

## Scope
1. **Autonomous PR Cascade Dispatcher Workflow (`.github/workflows/pr-cascade.yml`)**:
   - Trigger on every `push` to `main` (when any PR lands) and periodically (`cron: '*/30 * * * *'`).
   - Query GitHub GraphQL/CLI for open PRs where `autoMergeRequest != null` and `mergeStateStatus == "BEHIND"`.
   - Issue `gh pr update-branch <PR_NUMBER> --rebase` automatically to unblock the PR and re-trigger CI.
   - Support manual execution (`workflow_dispatch`).
2. **Maintainer Auto-Merge Opt-In Workflow (`.github/workflows/auto-merge-maintainer.yml`)**:
   - Trigger on `pull_request_target` (`opened`, `ready_for_review`, `reopened`).
   - For pull requests created by repository maintainers (e.g. `seanpor`) or designated automated agents, automatically enable squash auto-merge (`gh pr merge --auto --squash`).
3. **Workflow Modernization & Cleanup**:
   - Modernize `.github/workflows/dependabot-pr-refresh.yml` or consolidate into the universal cascade engine so Dependabot, maintainer, and agent PRs are processed uniformly.
   - Register pinned action SHAs in `tests/test_workflow_pinning.py` to maintain 100% security pinning standards.
4. **Validation & Regression Testing**:
   - Add unit tests verifying workflow syntax, permissions, pin enforcement, and dispatch rules.
   - Run `make preflight` (`make lint`, `make scan`, `make test`) to ensure zero-defect gate compliance.

## Implementation Plan
1. Create `docs/phases/PHASE_838.md` and update `docs/phases/manifest.yaml` with `status: IN_PROGRESS`.
2. Implement `.github/workflows/pr-cascade.yml` with strict least-privilege permissions (`contents: write`, `pull-requests: write`).
3. Implement `.github/workflows/auto-merge-maintainer.yml` for maintainer auto-merge activation.
4. Update `tests/test_workflow_pinning.py` with all action SHAs used in the new workflows.
5. Create regression tests in `tests/unit/test_pr_cascade_workflow.py` validating workflow triggers, permissions, and script behavior.
6. Run `make lint-phases`, `make lint`, and `make test`.
7. Add news fragment `docs/fragments/phase-838-pr-cascade-dispatcher.md`.

## Test Strategy
- Unit tests verify that the new workflow files parse cleanly, enforce pinned SHAs, specify minimal token permissions, and avoid unbounded loops.
- `make lint-phases` verifies manifest and phase documentation integrity.
- Full local preflight (`make preflight`) verifies all lint, security scan, and test invariants.

## Acceptance Criteria
- [ ] Remote branch lease claimed and manifest marked `IN_PROGRESS`.
- [ ] `.github/workflows/pr-cascade.yml` deployed with minimal permissions and full SHA pinning.
- [ ] `.github/workflows/auto-merge-maintainer.yml` deployed with minimal permissions.
- [ ] `tests/test_workflow_pinning.py` passes with zero unpinned or unregistered actions.
- [ ] New unit tests in `tests/unit/test_pr_cascade_workflow.py` pass.
- [ ] `make preflight` passes 100% green.
- [ ] Manifest updated, phase documentation finalized, news fragment provided.

## Out of Scope
- Converting personal GitHub user account to an Organization account.
- Disabling branch protection or loosening strict check requirements on `main`.
