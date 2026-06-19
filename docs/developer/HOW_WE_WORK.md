<!--
title: "How We Work — Team Process"
audience: developer
last_reviewed: 2026-04-25
phase: 105
-->

# How We Work

This is the team process doc. It defines the trunk-based development flow,
branch and commit conventions, the keep-main-green policy, and PR/review
etiquette. The rules here are the contract every contributor — human or
agent — works under.

For agent-specific orchestration rules (mandatory planning protocol, phase
close-out automation), see [`../../AGENTS.md`](../../../AGENTS.md). For the
architectural context behind these rules, see
[`../../CLAUDE.md`](../../../CLAUDE.md) §Multi-Agent Coordination.

---

## Branching

The repository is **trunk-based**:

- `main` is the only long-lived branch. All work happens on short-lived
  feature branches and merges back to `main`.
- Phase work uses `phase-NN-short-description` (e.g.
  `phase-105-docs-restructure`).
- Non-phase work uses `feat/short-description`, `fix/short-description`, or
  `chore/short-description`.
- Branches are short-lived: open a PR within a day or two of branching, merge
  within a week. A branch open for more than two weeks is a smell — rebase or
  abandon it.

> **Never commit directly to `main`.** This rule is restated in
> [`CLAUDE.md`](../../../CLAUDE.md) §Git Rules. Direct pushes are blocked by
> branch protection; the keep-main-green policy below assumes every change
> arrives via PR.

The orchestrator (or maintainer) handles merging branches to `main`. Do not
self-merge unless your role explicitly authorises it.

---

## Commits

### Format

Commit messages follow `type(scope): brief description` for non-phase work
(see `git log --oneline`). Phase work uses the prefix `phase-NN: description`:

```
phase-105: Track E — developer onboarding docs + main-is-red runbook
fix(security): tighten SNI DGA scoring threshold
docs(runbooks): add main_is_red.md
```

Focus on **why**, not **what** — the diff already shows what.

### Co-author trailer

All commits include a `Co-Authored-By:` trailer. For agent commits, this
identifies the model:

```
Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
```

### Cadence

Commit often — after each meaningful chunk of work. A reviewer reading 30
small commits will spot mistakes a single 800-line commit hides. Atomic
commits also make `git revert` safe; see Keep-main-green policy below.

### File ownership

Each phase agent owns only the files in `src/`, `tests/`, and
`docs/phases/` relevant to its phase. Shared files have specific rules — see
[`CLAUDE.md`](../../../CLAUDE.md) §File Ownership for the table (Makefile,
README.md, CHANGELOG.md, requirements.txt, config/proxy.yml, etc.). Do not
restate the table here; CLAUDE.md is the source of truth.

---

## Pull requests

### Size

Aim for **≤400 lines of diff** per PR (excluding generated files, test
fixtures, and lockfiles). Large PRs hide bugs and exhaust reviewer attention.
If your work cannot be split, label the PR `large` in the description and
guide the reviewer through the diff in commit order.

### One concern per PR

A PR addresses one phase, one bug, or one focused refactor. Bundling an
unrelated cleanup with feature work makes revert risky and review noisy. If
you spot a drive-by fix, open a separate PR for it.

### Description

Every PR description includes:

- **Summary** — 1–3 bullets, plain language, focused on intent.
- **Test plan** — markdown checklist of how to verify the change.
- **Linked issue / phase** — `Closes #NNN` or `Phase 105 (Track E)`.

The `gh pr create` template in `CLAUDE.md` is the canonical format.

### Reviews

- Reviewers focus on **correctness, test coverage, and the keep-main-green
  risk** of the change. Style nits should be caught by linters; if a
  reviewer is fixing whitespace, the linter has a gap — file an issue.
- Authors respond to every comment, even with `Done` or `Resolved here:
  <SHA>`.
- A PR with a red required CI check does not merge. Fix the failure or
  document why the check is genuinely unrelated (rare; almost always a real
  bug).

---

## Keep-main-green policy

**`main` must never stay red.** A red required CI job on `main` blocks every
other contributor's work — they cannot merge their own green PRs without
inheriting an unrelated failure. This policy makes `main` red an incident,
not a normal state.

### Required CI jobs (the gate)

Required jobs — a failure on any of these is a blocking incident:

| Job | Workflow | Purpose |
|-----|----------|---------|
| `Go tests` (`test-go`) | `.github/workflows/ci.yml` | `go test ./...` |
| `Python tests` (`test-python`) | `.github/workflows/ci.yml` | `pytest ... -x` |
| `Lint (go vet + gofmt + ruff)` (`lint`) | `.github/workflows/ci.yml` | All three linters |
| `Secrets scan (TruffleHog)` (`secrets-scan`) | `.github/workflows/ci.yml` | Verified-only secret scan |
| `SAST (Semgrep)` (`sast`) | `.github/workflows/ci.yml` | `p/ci`, `p/security-audit`, `p/secrets` |
| `Python dependency audit (pip-audit)` (`dependency-audit-python`) | `.github/workflows/ci.yml` | CVEs in `requirements.txt` |
| `Go dependency audit (govulncheck)` (`dependency-audit-go`) | `.github/workflows/ci.yml` | CVEs in `go.mod` |

Non-required (`continue-on-error: true` or PR-only): `Smoke test (Docker
Compose)`, `Dependency review (PR gate)`, `Traceability matrix check` (until
the 2026-05-08 cutoff). A red non-required job is a notification, not an
incident.

The authoritative list of required vs non-required jobs is encoded in
`tests/test_workflow_pinning.py::test_branch_protection_contexts_match_ci_job_names`
and `scripts/branch_protection.sh`. If you change the gate, update both.

### SLA

| Phase | Target | Trigger |
|-------|--------|---------|
| Acknowledge | within 15 min during working hours | Post in `#engineering` that you have eyes on the failure |
| Decide | within 30 min | Revert vs fix-forward; revert is the default |
| Restore green | within 1 hour | Either the revert is merged or the fix-forward PR is merged green |

If `main` is red for **≥15 minutes during working hours**, it is a tracked
incident. Outside working hours, the next person on shift owns it; the SLA
clock starts at the start of their working hours.

### Revert-first preference

A failure on `main` from a recent merge is almost always cheaper to revert
than to debug under time pressure. Default to revert; the original author
re-opens with a fix on a fresh branch.

```bash
git revert <commit-sha>
git push origin main   # via PR — same gate applies
```

Fix-forward only if the failure is trivially obvious (typo, missing import,
one-line config) and you can land the fix faster than a revert can be reviewed.

### Responsible party

| Failure type | Owner |
|--------------|-------|
| PR regression on `main` | The PR author owns the revert/fix |
| Weekly CVE sweep (`schedule:` Mondays 06:00 UTC) red | Maintainer on rotation; dependency-update PR within 24 h |
| Flaky test (intermittent) | The test owner; quarantine with a tracked issue, do not just retry |

A maintainer is the backstop in every case; if the author is unavailable, the
maintainer reverts.

### Operational response

The step-by-step for the on-call response — detect, acknowledge, decide,
act, post-incident — lives in
[`../runbooks/main_is_red.md`](../runbooks/main_is_red.md). This policy doc
defines the contract; the runbook is the playbook.

---

## Local merge gate

Before merging any PR (yours, an agent's, or a Dependabot bump):

1. `make test` is green locally — all four static analyses (mypy, bandit,
   ruff, pip-audit) plus full pytest. Paste the tail into the PR description
   as evidence.
2. Every required CI check on the PR is green. Do not click merge with red
   checks "because it's flaky" — the keep-main-green policy applies.
3. The branch is up to date with `main` (rebased, not merged) so the green
   CI run reflects the post-merge state.

Skipping this is the single most common cause of breakages on `main`. The
[`AGENTS.md`](../../../AGENTS.md) §`make test` must be green locally before every
merge to main section is the canonical statement.

---

## Cross-references

- Architectural rules and decision log: [`../../CLAUDE.md`](../../../CLAUDE.md)
- Agent-orchestration variant of phase protocol:
  [`../../AGENTS.md`](../../../AGENTS.md)
- Day-1 mechanics, code style, project layout:
  [`../../CONTRIBUTING.md`](../../../CONTRIBUTING.md)
- TDD loop and test-category matrix:
  [`TESTING_STRATEGY.md`](TESTING_STRATEGY.md)
- Per-workflow CI gate descriptions:
  [`QUALITY_PLAN.md`](QUALITY_PLAN.md)
- Operational response when `main` is red:
  [`../runbooks/main_is_red.md`](../runbooks/main_is_red.md)
