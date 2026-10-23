- **`main` is now verified after an app-authored merge** (Phase 849, issue #622).
  GitHub does not dispatch workflows for events caused by the default
  `GITHUB_TOKEN` (anti-recursion), so a PR merged by the Actions app landed on
  `main` with no `push` run — the commit that was now the tip had never been built
  or scanned, while the PR's own checks were green *before* it existed. The new
  `main-verification.yml` runs on the auto-merge workflows, every half hour, and on
  demand; `scripts/ensure_main_verified.py` decides purely whether a commit has a CI
  run and dispatches `ci.yml` against `main` when it does not. It is never a required
  check, and a run that exists but failed is left alone (re-dispatching it would loop).
- `make verify-main` runs the same check locally (`APPLY=1` repairs a gap).
