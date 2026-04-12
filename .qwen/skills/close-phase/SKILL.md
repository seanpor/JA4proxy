---
name: close-phase
description: Orchestrate full phase close-out: pre-flight checks, run all gates, self-review, push, create PR, watch CI, merge, post-merge verify.
---

# Close Phase

Orchestrate the full phase close-out and merge to main. This skill enforces
every gate that agents have historically skipped, in order, blocking on failures.

**Invocation:** `/close-phase`

**Pre-condition:** You are on a phase branch (not `main`), with all changes
committed and ready to close out.

---

## Step 1 — Pre-flight checks

Execute these checks. If any fail, abort and tell the user what's wrong.

1. **Branch check:** Run `git branch --show-current`. If the result is `main`,
   abort with: *"You are on main. Switch to your phase branch first."*
2. **Working tree:** Run `git status --porcelain`. If there are unstaged
   modifications (lines not starting with `??`), tell the user to commit or
   stash them first. Untracked files (`??`) are OK.
3. **CHANGELOG check:** `git diff main...HEAD -- CHANGELOG.md` must be non-empty.
   If empty, abort: *"CHANGELOG.md has not been updated for this phase."*
4. **Manifest check:** Run `git diff main...HEAD -- docs/phases/manifest.yaml` and
   confirm the phase being closed has `status: COMPLETE` and a `completed:` date.
   If not, update `docs/phases/manifest.yaml` and re-commit.

If all pass, proceed to Step 2.

## Step 2 — Local gate (mechanical — fix until green)

Run:

```bash
bash scripts/close-phase.sh
```

This executes (in order):
1. `ruff check .` — Python lint
2. `gofmt` — Go formatting
3. `go vet` — Go static analysis
4. `go test ./...` — Go unit tests
5. `make test` — Python static analysis + full test suite
6. `make lint-phases` — phase doc validation
7. `make check-scores` — signal score parity (only if scores were touched)
8. `sync-roadmap.py` — regenerate TODO.md and PROJECT_STATUS.md

**If ANY step fails:** Fix the issue, commit, and re-run the script.
**Do not proceed until the script exits 0.** Save the output — you'll paste
the last 10 lines into the PR description in Step 4.

## Step 3 — Independent critical review

Before creating the PR, review the diff yourself:

```bash
git diff main...HEAD --stat
git diff main...HEAD
```

Check for these known recurring patterns:

| Pattern | What to look for |
|---------|-----------------|
| Ambiguous names | Variables named `l`, `O`, `I` (ruff E741) |
| Unmocked externals | Unit tests hitting Redis, HTTP, cloud SDKs without mocks |
| `os.access` mocks | Using `==` instead of `&` for bitmask matching |
| Python 3.14 `pathlib` | `os.stat` mocked without patching `pathlib.Path.mkdir` |
| Hardcoded paths/secrets | Absolute paths, API keys, tokens in code |

Run one final lint pass on the exact tree you'll push:

```bash
ruff check .
gofmt -l . | grep -vE '^\.claude/|^\.qwen/|^vendor/' || true
```

If you find issues: fix, commit, re-run `scripts/close-phase.sh`, repeat.

## Step 4 — Push and create PR

Push the branch:

```bash
git push -u origin $(git branch --show-current)
```

Create the PR with a descriptive body:

```bash
gh pr create \
  --title "<type>(phase-XX): <description>" \
  --body "## Summary

<2-3 sentence description of what this phase delivers.>

## Gate evidence

\`\`\`
$(tail -10 <(bash scripts/close-phase.sh 2>&1))
\`\`\`

## Checklist

- [x] scripts/close-phase.sh exits 0
- [x] Self-review completed (step 3 of /close-phase)
- [ ] CI green (watching)
"
```

Include the `scripts/close-phase.sh` output tail in the PR body as evidence.

## Step 5 — Wait for CI green

```bash
gh pr checks $(gh pr view --json number --jq .number) --watch --interval 20
```

**Every check must be green.** The only exception is `Dependency review (PR gate)`
which is `continue-on-error: true` due to GHAS gating.

**If any check fails:**
1. Fetch logs: `gh run view <run-id> --log-failed`
2. Fix the issue locally
3. Re-run `scripts/close-phase.sh` to confirm locally green
4. Push the fix
5. Wait for CI green again

**Do not merge with any red check.** Not even if you think it's flaky.

## Step 6 — Merge

```bash
gh pr merge --squash --delete-branch
```

## Step 7 — Post-merge verification

```bash
git checkout main && git pull --ff-only
RUN_ID=$(gh run list --branch main --limit 1 --json databaseId --jq .[0].databaseId)
gh run watch $RUN_ID --exit-status
```

Wait for the post-merge CI run to complete. Confirm all green.

**If main is red after merge: fix it immediately.** You own it until main is green.

## Step 8 — Done

Report to the user:
- Phase number and name
- PR number and URL
- Confirmation that main CI is green
