<!--
title: "main is red Runbook"
audience: oncall, maintainers, developers
last_reviewed: 2026-04-25
phase: 105
-->

# Runbook: main_is_red

## Severity

WARNING (any required CI job on `main` red for ≥15 min during working hours)
→ CRITICAL (≥1 hour red, or weekly CVE sweep red and unaddressed for 24 h).

## What is happening

A required CI job on the default branch (`main`) is failing. Until it is
restored to green, every other contributor's PR cannot merge cleanly because
their branches will inherit the same failure when rebased onto `main`. This
is a **shared resource outage**, not a personal-PR problem.

The keep-main-green policy ([`../HOW_WE_WORK.md`](../HOW_WE_WORK.md)
§Keep-main-green policy) defines the required CI jobs and the response SLA.
This runbook is the operational playbook.

## Impact

- **High (CRITICAL):** The team is blocked from merging any work; releases
  cannot be cut. Weekly CVE sweep failures additionally mean a known
  vulnerability is unfixed in a shipped dependency.
- **Medium (WARNING):** New PRs cannot land cleanly; rebases pull in the
  red state. Acknowledge and decide a course of action quickly.

## Detect

The team finds out `main` is red in three ways:

1. **GitHub Checks UI** — the commit on `main` shows a red X in the branch
   status indicator at `https://github.com/<org>/JA4proxy/commits/main`.
2. **Workflow run notifications** — GitHub emails / Slack hooks the
   commit author and anyone watching the repo when a workflow on `main`
   fails.
3. **Blocked PRs** — contributors notice their rebased PRs fail the same
   job.

Run a quick check from the terminal:

```bash
gh run list --branch main --limit 5
gh run view <run-id> --log-failed
```

Identify the failing job (one of the required jobs in
[`../QUALITY_PLAN.md`](QUALITY_PLAN.md)
§Required jobs) and the commit SHA that introduced it.

## Acknowledge

Within **15 minutes** during working hours:

1. Post in `#engineering` with the failing job, the offending commit SHA,
   and your handle as the owner of the response. Template:

   ```
   :rotating_light: main is red — `<job_name>` failing on `<short_sha>`
   <link to GitHub Actions run>
   I have eyes on this. Decision (revert vs fix-forward) within 30 min.
   ```

2. If you are not the PR author of the offending commit, ping the author.
   The author owns the response by default; you are the backstop only if
   they are unavailable.

Acknowledgement happens before diagnosis. The team needs to know someone
is on it; the diagnosis can take longer.

## Decide

Within **30 minutes** of acknowledgement, decide between two responses.
**Revert is the default.**

### Revert (default)

Use revert when:

- The failure is non-trivial to debug (more than one obvious cause).
- The PR author is unavailable.
- The failure is in a job whose root cause needs investigation (intermittent
  test, environmental drift, supply-chain CVE).

### Fix-forward

Use fix-forward only when:

- The failure is a trivial typo / missing import / one-line config issue
  that you can patch and review faster than a revert can be reviewed.
- The fix is unambiguously local to the offending change.
- You can land the fix on a fresh branch (not by direct push) within 30
  minutes.

If unsure, revert. The original author re-opens the work on a fresh branch
with a passing test that pins the regression.

## Act

### Revert

```bash
git fetch origin main
git checkout main
git pull
git revert <bad-commit-sha>
git push origin HEAD:revert/<bad-commit-sha>

gh pr create \
  --title "Revert: <original-pr-title>" \
  --body "Reverts <bad-commit-sha>. main is red — keep-main-green response. Original PR will be re-opened with a regression test once root cause is understood."
```

The revert PR runs the same gate as any other PR. **Do not bypass branch
protection.** A revert PR with red checks is the same problem you just
created — fix the revert, do not force-merge it.

If the offending commit is a merge commit, use `git revert -m 1
<merge-sha>`.

### Fix-forward

```bash
git checkout -b fix/main-is-red-<short-sha>
# Apply the minimal fix.
# Add a regression test that pins the failure.
git commit -m "fix: <one-line description> (main-is-red response)"
git push -u origin fix/main-is-red-<short-sha>
gh pr create
```

Watch CI green. If the fix introduces a second failure, **revert immediately**
— do not chain fixes.

### Weekly CVE sweep red

The Mondays-06:00-UTC scheduled run failing means a newly disclosed CVE
hits an already-merged dependency. The maintainer on rotation owns:

1. Identify the vulnerable package from the failed `pip-audit` or
   `govulncheck` log.
2. Open a `chore/cve-<id>` PR with the dependency bump and test impact.
3. Land within 24 hours; if a clean upgrade is not available, file a
   risk-accepted exception in `docs/security/EXCEPTIONS.md` per
   [`../../AGENTS.md`](../../AGENTS.md) §Approved Exception Workflow.

## Verify

After the revert or fix-forward merges:

1. Watch the post-merge CI run on `main`. Every required job must be green.
2. Tail the Actions UI until the run completes. **Do not walk away** — a
   "fix" that itself goes red on `main` is the worst-case outcome of this
   runbook.
3. Post in `#engineering`:

   ```
   :white_check_mark: main is green — <job_name> restored on <short_sha>
   <link to passing CI run>
   Post-incident note: <link to incident issue, if filed>
   ```

## Post-incident note

For any outage that exceeded the 1-hour SLA, file an incident issue in
the repo using this template:

```markdown
## main is red — <date>

**Duration:** <start UTC> → <end UTC> (<minutes> minutes)
**Failing job:** <job_name> in <workflow.yml>
**Offending commit:** <full SHA> (`<short title>` by @<author>)
**Detect → Ack:** <minutes>
**Ack → Decision:** <minutes>
**Decision → Green:** <minutes>

### Root cause
<1–3 sentences; cite logs/diff>

### Why local `make test` did not catch this
<dev-vs-CI divergence? skipped local run? mock gap? cite the AGENTS.md section that already warns about this class>

### Action items
- [ ] <test or guard added to prevent recurrence>
- [ ] <doc updated, owned by author>
- [ ] <process change, owned by maintainer>
```

The post-incident note is the trigger for **process improvement**, not
blame. Most main-is-red incidents on this repo recur because the same
class of failure (e.g. unmocked Redis, gofmt drift in a new directory) is
not yet covered by an automated check. The note should propose that check.

## Escalation

- After **30 minutes** with no acknowledgement: any contributor pages a
  maintainer.
- After **1 hour** still red: the maintainer reverts unilaterally.
- After **24 hours** red on a weekly CVE sweep: CISO is informed; risk
  acceptance or scheduled patch window is documented in
  `docs/security/EXCEPTIONS.md`.

## Related

- Policy and SLA:
  [`../HOW_WE_WORK.md`](../HOW_WE_WORK.md)
  §Keep-main-green policy
- What every CI job enforces:
  [`../QUALITY_PLAN.md`](QUALITY_PLAN.md)
- Local merge gate (must be green before any merge):
  [`../HOW_WE_WORK.md`](../HOW_WE_WORK.md)
  §Local merge gate
- Approved exceptions process:
  [`../../AGENTS.md`](../../AGENTS.md) §Approved Exception Workflow
