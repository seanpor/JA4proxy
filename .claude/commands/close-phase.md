# Close Phase

Orchestrate the full phase close-out and merge to main. This command enforces
every gate that agents have historically skipped, in order, blocking on failures.

## Steps — execute in order, do not skip

### 1. Pre-flight checks
- Confirm you are on a feature branch (not `main`). If on main, abort.
- Run `git status` — confirm working tree is clean or all changes are staged.
- Confirm CHANGELOG.md has been updated for this phase.
- Confirm docs/phases/manifest.yaml has `status: COMPLETE` for this phase.
- Archive the phase doc (AGENTS.md Rule 5): `git mv docs/phases/PHASE_XX.md docs/phases/complete/`
  (or `cancelled/` if cancelled) and update that phase's `action_plan:` path in the
  manifest in the same commit. Only active phases (PROPOSED/IN_PROGRESS/DEFERRED) stay
  at the top of docs/phases/. `make lint-phases` verifies the moved path resolves.

### 2. Local gate (mechanical — run until green)
Run `bash scripts/close-phase.sh`. This executes:
- ruff check
- gofmt + go vet
- go test ./...
- make test (mypy + bandit + ruff + pip-audit + pytest)
- sync-roadmap.py

If ANY step fails: fix the issue, commit the fix, and re-run the script.
**Do not proceed until the script exits 0.** Paste the last 10 lines of
output into the PR description as evidence.

### 3. Independent critical review
Before creating the PR, do a self-review:
- `git diff main...HEAD --stat` — scan every changed file for:
  - Ambiguous variable names (l, O, I — ruff E741)
  - Unmocked external services in unit tests (Redis, HTTP, cloud SDKs)
  - `os.access` mocks using `==` instead of `&` for bitmask matching
  - Missing `pathlib.Path.mkdir` patches when `os.stat` is mocked (Python 3.14)
  - Hardcoded paths or secrets
- `ruff check . && gofmt -l .` — one final lint pass on the exact tree you'll push.

If you find issues: fix, commit, re-run `scripts/close-phase.sh`, repeat.

### 4. Push and create PR
```
git push -u origin <branch-name>
gh pr create --title "<type>(phase-XX): <description>" --body "..."
```
Include the `scripts/close-phase.sh` output tail in the PR body.

### 5. Wait for CI green
```
gh pr checks <PR-number> --watch --interval 20
```
**Every check must be green** (except `Dependency review (PR gate)` which is
`continue-on-error: true` due to GHAS gating). If any check fails:
- Fetch logs: `gh run view <run-id> --log-failed`
- Fix the issue locally
- Re-run `scripts/close-phase.sh`
- Push the fix
- Wait for CI green again

**Do not merge with any red check.** Not even if you think it's flaky.

### 6. Merge
```
gh pr merge <PR-number> --squash --delete-branch
```

### 7. Post-merge verification
```
git checkout main && git pull --ff-only
gh run list --branch main --limit 1
```
Wait for the post-merge CI run to complete. Confirm all green:
```
gh run watch <run-id> --exit-status
```
If main is red after merge: **fix it immediately** — you own it until main is green.

### 8. Done
Report to the user: phase closed, PR merged, main CI green.
