# Branch Hygiene and Stale Remote Cleanup

## 1. Goal (plain language)
The repository currently has a large number of stale, unmerged remote branches (predominantly from past completed phases, e.g. Phase 118, Phase 220, etc.). Because the project uses a squash-and-merge workflow, Git does not recognize these branches as merged since their commit hashes differ from those on `main`, leaving them to clutter the remote repository. This phase introduces a repeatable, automated branch hygiene process and script for a junior engineer to safely identify, audit, and purge stale remote and local branches, and documents this process in a permanent developer maintenance runbook.

## 2. Why this phase exists / background
- A simple `git branch -r --no-merged` lists dozens of branches that have actually already had their work merged via squash commits or retired.
- Manually verifying the status of each branch against GitHub pull requests and code diffs is slow and error-prone.
- Leaving stale branches makes it difficult for developers to distinguish active, ongoing feature branches from obsolete, historical ones.
- Creating a standardized, automated tool and documenting the methodology ensures that branch hygiene can be easily maintained by junior engineers in the future.

## 3. Key decisions (and why)

| # | Decision | Why |
|---|---|---|
| D1 | **Use a combined Git Diff & GitHub API (via `gh` CLI) check** to classify branches. | Git alone cannot detect squash-merges. We must verify if the associated PR is `MERGED` or `CLOSED`, or if `git diff main...branch` has 0 changes. |
| D2 | **Classify branches into three clear categories**: `Active` (worth keeping/retrieving), `Stale/Garbage` (safe to delete), and `Dependabot`. | Dependabot branches are common and transient; keeping them grouped separately helps developers audit them quickly without cluttering feature work. |
| D3 | **Implement a dry-run flag (`--dry-run`) by default** in the hygiene script. | Deleting remote branches is a destructive action. The script must require an explicit `--delete` flag to actually perform deletions, preventing accidental data loss. |
| D4 | **Publish the methodology and script usage in a permanent developer maintenance guide** (`docs/developer/BRANCH_HYGIENE.md`). | Ensures the process is documented and easily discoverable for junior engineers onboarding to repository maintenance tasks. |

## 4. Design / flow
```
scripts/branch_hygiene.py [--delete] [--dry-run]
  │
  ├─ fetch latest remote branches (git fetch --prune)
  ├─ get list of remote branches not merged into origin/main
  ├─ for each branch:
  │     ├─ check if git diff origin/main...<branch> is empty
  │     ├─ check GitHub PR status using `gh pr list --head <branch>`
  │     └─ classify as:
  │          - Active: PR is OPEN, or has diff and no PR, and committer date < 30 days old
  │          - Stale/Garbage: PR is MERGED/CLOSED, or has no diff with main
  │          - Dependabot: branch name contains "dependabot/"
  ├─ print summary report of all branches
  └─ if --delete is set (and not --dry-run):
        └─ delete stale remote branches (git push origin --delete <branch>)
           and delete stale local tracking branches
```

## 5. Files to Modify

| File | Change |
|------|--------|
| `docs/phases/complete/PHASE_329.md` | New file — Phase 329 work plan |
| `docs/developer/BRANCH_HYGIENE.md` | New file — Permanent developer maintenance guide and runbook |
| `scripts/branch_hygiene.py` | New file — Python script to automate branch audits and deletions |
| `tests/unit/test_branch_hygiene.py` | New file — Unit tests for branch hygiene script |
| `docs/phases/manifest.yaml` | Add Phase 329 entry |
| `CHANGELOG.md` | Add Phase 329 to the change log |

## 6. Implementation plan (in order)

### A — Core Script Development
1. Write the Python tool at `scripts/branch_hygiene.py` to fetch, audit, classify, and optionally delete stale branches.
2. Ensure it utilizes `subprocess.run(..., shell=False)` for safety and parses GitHub CLI JSON output.

### B — Documentation
1. Create `docs/developer/BRANCH_HYGIENE.md` defining squash-merge issues, classification methodology, and step-by-step instructions for junior engineers.
2. Outline developer safety check protocols to rescue branches if needed.

### C — Validation & Tests
1. Create `tests/unit/test_branch_hygiene.py` covering classification logic, CLI mocks, and deletion functions.
2. Verify all tests pass and are type-checked under mypy and ruff.

### D — Manifest Integration
1. Add Phase 329 to `docs/phases/manifest.yaml` and regenerate the roadmap via `make sync`.

## 7. Test strategy
- **Script Unit Tests:** Add a Python test suite `tests/unit/test_branch_hygiene.py` to verify the classification logic of `scripts/branch_hygiene.py` using mocked `subprocess.run` responses for git and GitHub CLI.
- **Dry-Run Safety:** Assert that the script does not attempt to execute deletions unless `--delete` and `--no-dry-run` are explicitly provided.
- **Static Analysis:** Ensure `scripts/branch_hygiene.py` and its tests pass `ruff` and `mypy` check gates.

## 8. Acceptance criteria
- The automated script `scripts/branch_hygiene.py` successfully classifies all remote branches into `Active`, `Stale`, and `Dependabot` categories.
- The permanent documentation `docs/developer/BRANCH_HYGIENE.md` is added and details the methodology and script commands.
- `make lint-phases` exits 0.
- All unit tests pass with 100% success rate.

## 9. Out of scope
- Automatically merging any active branches.
- Deleting branches that have active open pull requests or contain unmerged work not present on `main`.

## 10. Methodology & Future Replication Notes
- **Analysis Methodology:** We discovered that standard git tools fail to detect squashed PRs due to commit SHA rewriting. We designed the logic to combine PR metadata (`gh pr list`) and three-way diffs (`git diff origin/main...<branch>`) to solve this.
- **Junior Engineer Execution Plan:** A junior engineer can execute this cleanup at the beginning of each sprint or monthly using the runbook at `docs/developer/BRANCH_HYGIENE.md`. The default dry-run ensures they can review branch classifications before running with actual deletion flags.
