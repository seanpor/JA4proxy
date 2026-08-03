---
phase: 812
title: "CI/CD automation hardening — stop recurring manual-toil failure modes"
status: PROPOSED
created: 2026-08-03
audience: [developer]
---

# CI/CD automation hardening — stop recurring manual-toil failure modes

## Goal (plain language)

This session's cleanup (Phase 809 aftermath) surfaced the same shape of
problem four separate times: a CI gate goes red for a reason that is
mechanical, predictable, and was fixed by hand each time rather than by the
system. The user asked, in effect, "how do we stop this from being something
I have to notice and ask about every morning." This phase makes each of the
four recurring failure modes self-healing or pre-empted, instead of
reactive.

The four failure modes observed today, in the order they bit:

1. **Nightly Benchmark bootstrap bugs** — three independent, sequential bugs
   (missing `.env` vars, missing `deploy/secrets/redis_password.txt`,
   `AGENT_CPU_SET` assuming 16 cores) in `scripts/start-poc.sh` /
   `docker-compose.poc.yml`, each discovered one night at a time because
   nothing exercises that exact cold-start path at PR time.
2. **`.trivyignore` exception cliff** — a batch of dated exceptions
   (Phase 226 policy, max 7-day window) all expired on the same calendar
   day, so `Security Scan` went red on `main` and on every open PR
   simultaneously, for reasons unrelated to any of those PRs' actual diffs.
3. **`KNOWN_ACTION_SHAS` manual allowlist** — `tests/test_workflow_pinning.py`
   hand-maintains a SHA-vs-tag truth table. Every single GitHub Actions
   version bump (PR #379, then again PR #390 today) fails CI until a human
   adds the new entry by hand, verified via `git ls-remote`.
4. **Dependabot PR staleness** — today's 7 open Dependabot PRs all needed a
   manual `@dependabot rebase` (or close/reopen) nudge because their CI had
   run before an unrelated main-branch fix (PR #389) landed. Dependabot's
   own periodic rebase cadence doesn't react to main changing.

## Scope

In scope: four independent, additive changes — one CI job, one test-file
behavior change, one new scheduled workflow, one new lightweight workflow.
None of them touch proxy hot-path code (`internal/`, `cmd/ja4pd/`) or
existing signal-scoring logic.

Out of scope: fixing any *specific* currently-open CVE or SHA (those are
already resolved on `main` as of PR #389/#390); replacing
`prom/haproxy-exporter` with HAProxy's built-in exporter (tracked separately,
see PHASE_810.md); changing the Phase 226 7-day exception-window policy
itself (only when renewal happens, not the window length).

## Implementation plan

### 812-A — PR-time cold-start smoke test for the PoC stack

**Problem:** `scripts/start-poc.sh` + `docker-compose.poc.yml` is only ever
exercised end-to-end by the nightly benchmark workflow, on a schedule, after
the fact. The existing "Smoke test (Docker Compose)" job in `ci.yml` is
`continue-on-error: true` (non-blocking) and tests the *root*
`docker-compose.yml`, a different file with different bootstrap code —
it would not have caught any of the three bugs fixed today.

**Change:** add a new **required** job to `ci.yml`, `poc-cold-start`,
gated to run only when a PR touches `scripts/start-poc.sh`,
`scripts/lane-env.sh`, `deploy/docker/docker-compose.poc.yml`, or
`scripts/generate-backend-cert.sh` (path filter, so it doesn't add latency
to unrelated PRs). It:
1. Checks out on a clean runner (no `.env`, no `deploy/secrets/` — this is
   already true on a fresh Actions runner, but assert it explicitly with a
   guard step so a future change to actions/checkout defaults can't silently
   reintroduce stale state).
2. Runs `./scripts/start-poc.sh`.
3. Curls the proxy's `/health` endpoint once services report ready.
4. Tears the stack down (`docker compose down -v --remove-orphans`),
   `if: always()`.

### 812-B — Proactive `.trivyignore` renewal workflow

**Problem:** exceptions are renewed reactively, whenever someone happens to
touch the file, so they cluster on one calendar day and cause a
simultaneous, unrelated-PR-blocking cliff (today's case: 42 entries expired
on the same day).

**Change:** new scheduled workflow `.github/workflows/trivyignore-renewal.yml`,
same shape as `process-metrics.yml` (branch + PR + auto-merge, since direct
push to `main` is rejected):
1. Runs weekly (`cron: '0 5 * * 1'`, Monday 05:00 UTC — one hour before the
   existing weekly CI sweep at 06:00, so a renewal lands *before* the sweep
   would otherwise hit the cliff).
2. Runs `scripts/scan_exceptions.py --within-days 5` (new flag — lists
   entries expiring within 5 days, not just already-expired ones).
3. For each image with a soon-to-expire entry, re-scans it and checks
   upstream (Docker Hub / GCR tags API) for a newer tag, same manual process
   used today for cadvisor/grafana/prometheus/etc.
4. Where a newer tag genuinely clears the CVE with no worse regressions,
   proposes the version bump instead of renewing the ignore (this step
   requires judgment the script can't fully automate — see Acceptance
   Criteria: the workflow opens a PR either way, a human still reviews
   before merge, but the false-cliff timing problem is gone).
5. Opens a PR with the renewed exceptions/bumps; does **not** auto-merge
   (unlike process-metrics.yml) — CVE-exception judgment calls stay
   human-reviewed, per Phase 226's own "NO blanket ignores" rule.

### 812-C — Live SHA verification for GitHub Actions pins, scoped to Dependabot PRs

**Problem:** `tests/test_workflow_pinning.py`'s `KNOWN_ACTION_SHAS` table
exists because "tests cannot reach the network" (the file's own docstring).
That constraint is real for local/offline test runs, but not for GitHub
Actions runners, which have normal internet egress. Every Actions-group
Dependabot bump currently fails this gate until a human manually adds a
table entry — this has now happened twice in one session for the same
class of change.

**Change:** rather than removing the offline safety net (flipping the test
itself to always hit the network would make it flaky/non-deterministic for
every contributor, including local runs in the sandboxed `ja4proxy-tools`
container which may not always have egress), add a narrow, additive
autofix path:
1. New job `pin-table-autofix` in `ci.yml`, gated
   `if: github.actor == 'dependabot[bot]'`.
2. Diffs the PR against `main` for `uses:` line changes in
   `.github/workflows/*.yml`.
3. For each changed `(action, SHA, tag)` triple not already in
   `KNOWN_ACTION_SHAS`, runs `git ls-remote <repo> refs/tags/<tag>`
   (falling back to `refs/tags/<tag>^{}` for annotated tags, per the
   `ossf/scorecard-action` gotcha hit in PR #379) and compares to the SHA in
   the diff.
4. If every new entry matches: commits an addition to
   `tests/test_workflow_pinning.py` directly onto the Dependabot PR branch,
   citing the PR number, and re-triggers CI.
5. If any entry does **not** match: does *not* autofix — fails loudly with
   the mismatch details. This is the actual supply-chain-hole case the
   table exists to catch, and must never be silently patched over.
6. The static table remains authoritative for local/offline runs and for
   any non-Dependabot contributor's PR — this only automates the one
   specific, high-frequency, low-risk case.

### 812-D — Auto-nudge stale Dependabot PRs on main-branch changes

**Problem:** when a main-branch fix changes CI's pass/fail state (e.g.
PR #389 today), every open Dependabot PR whose CI ran *before* that fix
keeps failing on the stale snapshot until someone notices and comments
`@dependabot rebase` (or closes/reopens) by hand. Today this was all 7 open
PRs, discovered only because the user asked "why are there still 7 open
PRs?"

**Change:** new lightweight workflow
`.github/workflows/dependabot-rebase-nudge.yml`:
1. Triggers on `push` to `main`.
2. Lists open PRs authored by `dependabot[bot]` via `gh pr list`.
3. For each with a failing required check, posts `@dependabot rebase`.
4. `continue-on-error: true` on the whole job — a notifier must never
   itself become a required, blockable check (same rule already documented
   for `notify-scheduled-failure` in `ci.yml`).

## Test strategy

- 812-A: the new `poc-cold-start` job *is* the test — validated by
  deliberately reverting one of the three bugs fixed today in a scratch
  branch and confirming the job fails, then re-fixing and confirming green.
- 812-B: unit test for the new `scan_exceptions.py --within-days` flag
  (`tests/unit/test_scan_exceptions.py`, extend existing coverage);
  workflow YAML validated via `actionlint` (already run in Meta-Lint).
- 812-C: unit test that feeds `pin-table-autofix`'s comparison logic a
  known-good triple (should pass) and a deliberately mismatched triple
  (should fail loudly, not autofix) — this is the security-critical path,
  gets the most test weight.
- 812-D: workflow YAML validated via `actionlint`; manually verified once
  against a real stale Dependabot PR (dry-run via `workflow_dispatch` with
  a `--dry-run` flag that lists what it *would* comment on, without
  posting).

## Acceptance criteria

- [ ] A PR touching `scripts/start-poc.sh` or `docker-compose.poc.yml` with
      a deliberately reintroduced cold-start bug fails CI at PR time.
- [ ] `scan_exceptions.py --within-days 5` correctly lists soon-to-expire
      entries; the new scheduled workflow opens a real PR against a test
      repo fork or via `workflow_dispatch` dry-run.
- [ ] A Dependabot Actions-bump PR with a *correct* new SHA gets an
      automatic fixup commit and goes green without human intervention.
- [ ] A Dependabot Actions-bump PR with a deliberately *wrong* SHA (test
      fixture, not real) fails loudly and is NOT auto-patched.
- [ ] After a main-branch CI-affecting fix lands, open Dependabot PRs get
      an automatic rebase nudge within one `push`-triggered workflow run,
      with no human comment required.
- [ ] `make test` and `make lint` pass with zero warnings.
- [ ] `docs/reference/REDIS_SCHEMA.md` unaffected (no new Redis keys this
      phase).

## Out of scope

- Changing the Phase 226 7-day exception-window maximum itself.
- Replacing `prom/haproxy-exporter` (tracked as its own follow-up, noted in
  PHASE_810.md).
- Any change to `internal/`, `cmd/ja4pd/`, or proxy scoring logic.
- Retroactively backfilling `KNOWN_ACTION_SHAS` entries for actions not
  currently pinned in this repo.
