---
phase: 812
title: "CI/CD automation hardening — stop recurring manual-toil failure modes"
status: IN_PROGRESS
created: 2026-08-03
audience: [developer]
---

# CI/CD automation hardening — stop recurring manual-toil failure modes

## Goal (plain language)

This session's cleanup (Phase 809 aftermath) surfaced the same shape of
problem four separate times: a CI gate goes red for a reason that is
mechanical, predictable, and was fixed by hand each time rather than by the
system. This phase makes each of the four recurring failure modes
self-healing or pre-empted, instead of reactive.

**Revision note:** this is a rewrite after a critical review surfaced five
concrete problems in the first draft. All five are addressed below, and one
of them (the cold-start smoke test needing Redis auth to actually work)
turned out to depend on a separate, production-impacting bug — see
**Phase 813**, which this phase now depends on.

The four failure modes observed, in the order they bit:

1. **Nightly Benchmark bootstrap bugs** — three sequential bugs (missing
   `.env` vars, missing `deploy/secrets/redis_password.txt`,
   `AGENT_CPU_SET` assuming 16 cores), each discovered one night at a time
   because nothing exercises that exact cold-start path at PR time. A
   *fourth*, deeper bug (invalid `--requirepass-file` directive, broken ACL
   template rendering) was masked by the first three and only surfaced once
   they were all fixed — see Phase 813.
2. **`.trivyignore` exception cliff** — a batch of dated exceptions
   (Phase 226 policy, max 7-day window) all expired on the same calendar
   day, so `Security Scan` went red on `main` and on every open PR
   simultaneously, for reasons unrelated to any of those PRs' actual diffs.
3. **`KNOWN_ACTION_SHAS` manual allowlist** — `tests/test_workflow_pinning.py`
   hand-maintains a SHA-vs-tag truth table. Every single GitHub Actions
   version bump (PR #379, then again PR #390) fails CI until a human adds
   the new entry by hand, verified via `git ls-remote`.
4. **Dependabot PR staleness** — 7 open Dependabot PRs all needed a manual
   `@dependabot rebase` (or close/reopen) nudge because their CI had run
   before an unrelated main-branch fix (PR #389) landed.

## Dependency

**This phase depends on Phase 813 (Redis ACL authentication fix).** 812-A's
smoke test brings up the real PoC stack and cannot pass — correctly — until
Redis authentication actually works end-to-end. Do not start 812-A's
implementation before Phase 813 merges. 812-B/C/D have no dependency on 813
and can be implemented in parallel.

## Scope

In scope: four independent, additive changes — one CI job, one test-file
behavior change, one new scheduled workflow, one new lightweight workflow.
None of them touch proxy hot-path code (`internal/`, `cmd/ja4pd/`) or
existing signal-scoring logic.

Out of scope: fixing any *specific* currently-open CVE or SHA (already
resolved on `main` as of PR #389/#390); replacing `prom/haproxy-exporter`
(tracked separately, see PHASE_810.md); changing the Phase 226 7-day
exception-window *maximum* itself (only when/how renewal happens).

## Implementation plan

### 812-A — PR-time cold-start smoke test for the PoC stack

**Problem:** `scripts/start-poc.sh` + `docker-compose.poc.yml` is only ever
exercised end-to-end by the nightly benchmark workflow, on a schedule, after
the fact. The existing "Smoke test (Docker Compose)" job in `ci.yml` is
`continue-on-error: true` (non-blocking) and tests the *root*
`docker-compose.yml`, a different file with different bootstrap code — it
would not have caught any of the bugs fixed in Phase 809's aftermath or in
Phase 813.

**Change:** add a new **required** job to `ci.yml`, `poc-cold-start`. Two
fixes from the original draft, addressing review issue #5 (path-filter gap):

- **Path filter, widened.** Trigger on changes to `scripts/start-poc.sh`,
  `scripts/lane-env.sh`, `deploy/docker/docker-compose.poc.yml`,
  `scripts/generate-backend-cert.sh`, **and now also**
  `deploy/docker/Dockerfile.*` (any of them — a build failure in the proxy,
  tarpit, analytics, or mockbackend Dockerfile is exactly the same failure
  surface) and `config/redis_acl.conf.template` / `deploy/docker/redis-entrypoint.sh`
  (post-Phase-813 paths). Measured cost from today's actual logs: bring-up
  is ~50s, full job including builds is 2–3 minutes — cheap enough that a
  slightly wider filter is the safe default; err on the side of "runs more
  often than strictly necessary" over "misses a real regression."
- Job steps:
  1. Checkout on a clean runner (no `.env`, no `deploy/secrets/` — already
     true on a fresh Actions runner; add an explicit guard step asserting
     this, so a future change to actions/checkout defaults can't silently
     reintroduce stale state without anyone noticing).
  2. Run `./scripts/start-poc.sh`. Its own exit code is the real gate — it
     already fails loudly on a broken Redis healthcheck (this is exactly
     what would have caught Phase 813's bug, and now will, going forward).
  3. Curl the proxy's `/health` endpoint once services report ready, as a
     second independent signal.
  4. Tear the stack down (`docker compose down -v --remove-orphans`),
     `if: always()`.

### 812-B — Proactive `.trivyignore` renewal workflow

**Problem:** exceptions are renewed reactively, whenever someone happens to
touch the file, so they cluster on one calendar day and cause a
simultaneous, unrelated-PR-blocking cliff (42 entries expired on the same
day this session).

**Change:** new scheduled workflow `.github/workflows/trivyignore-renewal.yml`,
same shape as `process-metrics.yml` (branch + PR, since direct push to
`main` is rejected). Three fixes from the original draft, addressing review
issues #4 (overstated automation) and the missing-monitoring gap:

- **Honest framing, not full automation.** This does not eliminate the
  CVE-judgment work — a human still decides "is a newer tag actually
  better" the same way it was done today (compare total CVE counts, check
  for regressions). What it *does* fix is the timing: renewal happens
  **5 days before** the earliest expiry (`cron: '0 5 * * *'`, daily), so
  there's slack to actually review it instead of a same-day fire drill that
  blocks unrelated PRs.

  > **Amended 2026-08-10 (Phase 800):** this was originally a weekly
  > Wednesday cron. That could not work: trivy suppresses only while
  > `today < exp`, so an entry renewed to `today+7` is already expired on
  > day 7 — the exact morning the weekly job was due to run. The result was
  > a guaranteed red window every Wednesday 00:00–05:00 UTC, and a
  > permanently red gate whenever a run failed. Now daily; the Phase 226
  > 7-day maximum window is unchanged.
- **Correct date arithmetic.** New `exp:` dates are computed as
  `today + 7 days`, never `old_exp + 7 days` — prevents windows silently
  drifting longer than the policy's stated maximum through repeated
  mechanical renewals. `scripts/scan_exceptions.py` gets a new
  `--within-days N` flag (lists entries expiring within N days, not just
  already-expired ones) with a unit test asserting this arithmetic
  specifically.
- **Wired into a failure-notification pattern of its own.** The
  `notify-scheduled-failure` job in `ci.yml` can't be reused directly (it's
  a job inside `ci.yml`, coupled to that workflow's own `needs:` list) —
  `trivyignore-renewal.yml` gets an equivalent self-contained step (same
  open-or-update-tracking-issue logic, `if: failure()`), so a broken
  renewal workflow doesn't become a fifth silent failure mode.
- **Implementation note (scope decision made while building this):**
  `scripts/renew_trivyignore.py` mechanically renews every entry expiring
  within the window to `today + 7d` and opens a PR — it does **not**
  attempt to query Docker Hub/GCR for a newer upstream tag itself.
  Automating registry lookups across every image/registry this repo touches
  is real, ongoing maintenance surface for a question a human reviewer can
  answer in the same PR review anyway (the exact manual process already
  used for every renewal to date — compare total CVE counts, check for
  regressions). The PR body explicitly instructs the reviewer to do that
  check before merging. This is *more* conservative than the original
  draft's "checks upstream... for a newer tag," judged not worth the added
  complexity/flakiness for a first version — a candidate follow-up
  enhancement, not silently dropped.
- Does **not** auto-merge (unlike `process-metrics.yml`) — CVE-exception
  judgment calls stay human-reviewed, per Phase 226's own "NO blanket
  ignores" rule. Explicitly out of scope: catching a *brand-new* CVE that
  appears mid-week with no prior exception — that's still caught by the
  existing Monday sweep, reactively, same as before. This workflow only
  fixes the *renewal-clustering* problem, not general CVE discovery.

### 812-C — Verified SHA autofix for GitHub Actions pins, scoped to Dependabot PRs

**Problem:** `tests/test_workflow_pinning.py`'s `KNOWN_ACTION_SHAS` table is
hand-maintained. Every Actions-group Dependabot bump fails this gate until a
human adds an entry, verified via `git ls-remote` — hit twice in one
session (PR #379, PR #390).

**Change, redesigned after review issue #1 (Dependabot token restrictions):**
GitHub runs `pull_request`-triggered workflows from Dependabot with a
**read-only `GITHUB_TOKEN`** regardless of the workflow's own `permissions:`
block — this is deliberate hardening since Dependabot PRs are semi-trusted.
The original design (`pull_request` + `if: github.actor ==
'dependabot[bot]'` + a push) would silently fail to push. Fixed design:

1. New workflow `.github/workflows/pin-table-autofix.yml`, triggered on
   `pull_request_target` (which runs with the *base* repo's permissions,
   not the PR's), scoped tightly: `if: github.event.pull_request.user.login
   == 'dependabot[bot]'` **and** the job checks out the **base** ref by
   default (the `pull_request_target` default, no `ref:` override) — it
   must never check out or execute code *from* the PR branch.
2. **Implementation note (simplified during building, more robust than the
   original draft):** rather than parsing a raw unified diff (`gh pr
   diff`), `scripts/pin_table_autofix.py` adds the PR's head branch as a
   second git worktree (fetched, never checked out over the primary
   working tree) and scans its `.github/workflows/*.yml` files directly for
   every `uses: owner/repo@SHA  # vTAG` triple — the exact same regex
   `tests/test_workflow_pinning.py` already uses. This is read as plain
   file *data*, never executed; the script doing the scanning is always the
   trusted base-ref copy invoked by the workflow, never something read from
   the PR. Comparing the full triple set against `KNOWN_ACTION_SHAS`
   (parsed via `ast.literal_eval` on just the dict literal, not `exec()` on
   the file — belt-and-suspenders, since this file could theoretically
   differ from main's copy) finds exactly the same "new or changed" set a
   diff would, without the added surface of a diff-format parser.
3. For each changed `(action, SHA, tag)` triple not already in
   `KNOWN_ACTION_SHAS`, runs `git ls-remote <repo> refs/tags/<tag>`
   (falling back to `refs/tags/<tag>^{}` for annotated tags — the
   `ossf/scorecard-action` gotcha from PR #379) and compares to the SHA
   found in the workflow file. This is a pure network read via
   `subprocess.run` with an argument list (never `shell=True`, so no
   shell-injection risk even before validation), with the action name/tag
   string additionally checked against a strict `owner/repo` + semver-tag
   pattern first for a clear early error.
4. If **every** new entry matches: appends a line to the matching action's
   existing block in `tests/test_workflow_pinning.py` (on the worktree
   checkout of the PR branch), commits, and pushes to the PR's head ref
   (using the `contents: write` permission `pull_request_target` grants
   against the base repo — this works because Dependabot branches live in
   the same repo, not a fork), citing the PR number, and re-triggers CI.
   This second push re-triggers this same job — it's naturally idempotent,
   since the re-run's triple-set comparison now finds it already present
   and no-ops (explicit test case in Test Strategy). If the action has no
   existing block at all (a genuinely new action, not just a new version of
   a tracked one), the script deliberately does *not* auto-create one —
   reported as a failure needing a one-time manual entry, after which every
   future bump for that action takes the fast path.
5. If **any** entry does not match: does not autofix anything in the PR
   (all-or-nothing, not partial — avoids a confusing half-patched state) —
   fails loudly with the mismatch details. This is the actual
   supply-chain-hole case the table exists to catch, and must never be
   silently patched over.
6. The static table remains authoritative for local/offline runs and any
   non-Dependabot contributor's PR — this only automates the one specific,
   high-frequency, low-risk case, and only ever *adds* verified-correct
   entries, never modifies existing ones.

### 812-D — Auto-nudge stale Dependabot PRs on main-branch changes

**Problem:** when a main-branch fix changes CI's pass/fail state (e.g.
PR #389), every open Dependabot PR whose CI ran before that fix keeps
failing on the stale snapshot until someone notices and nudges it. Today
this was all 7 open PRs.

**Change, redesigned after review issue #3 (spam risk + observed
unreliability):**

- New lightweight workflow `.github/workflows/dependabot-pr-refresh.yml`,
  triggered on `push` to `main`.
- Lists open PRs authored by `dependabot[bot]` via `gh pr list`.
- **Dedup guard:** for each PR, checks whether its current head SHA has
  already been nudged (a label, e.g. `nudged:<short-sha>`, applied after
  nudging, removed on the next real commit to the branch). If already
  nudged for this exact head SHA, skip it — this is the fix for the spam
  risk: a PR failing for a **real, non-stale** reason gets nudged **once**
  per head SHA, not on every subsequent main push.
- **Close/reopen as the primary mechanism, not the comment.** We directly
  observed `@dependabot rebase` sit inert for 8+ minutes on PR #390 this
  session, while `gh pr close` + `gh pr reopen` triggered an immediate
  fresh CI run. The workflow does the latter directly via `gh pr close` /
  `gh pr reopen`, not by posting a comment and hoping Dependabot acts on
  it promptly.
- `continue-on-error: true` on the whole job — a notifier/nudger must never
  itself become a required, blockable check (same rule already documented
  for `notify-scheduled-failure` in `ci.yml`).

## Test strategy

- 812-A: the new `poc-cold-start` job *is* the test — real end-to-end
  verification happens the first time a PR touches one of its watched
  paths; the job itself proves the point by construction (it runs the same
  `start-poc.sh` already verified in Phase 813).
- 812-B: `tests/unit/test_scan_exceptions.py` and
  `tests/unit/test_renew_trivyignore.py` (11 tests) specifically assert the
  `today + 7d` (not `old_exp + 7d`) arithmetic, that NO-EXP/EXPIRED entries
  are always surfaced regardless of window, and that comments/unrelated
  entries are never touched. Workflow YAML validated via `actionlint`
  (clean) and `yaml.safe_load`.
- 812-C: `tests/unit/test_pin_table_autofix.py` (7 tests) covers a
  known-good triple (autofix proceeds), a deliberately mismatched triple
  (fails loudly, no autofix — the security-critical path), an idempotency
  case (already-patched table no-ops without even calling `git
  ls-remote`), the `ossf/scorecard-action`-style annotated-tag fallback,
  the "brand-new action, no existing block" case (reported, not
  auto-created), and that a malformed action name is rejected by the
  explicit validation gate. `git ls-remote` is mocked throughout (no real
  network calls in tests, per CLAUDE.md's testing standards).
- 812-D: `tests/unit/test_dependabot_pr_refresh.py` (8 tests) covers the
  dedup rule directly: passing checks never refresh, a first failure
  refreshes and labels, the same head SHA is not re-refreshed (the
  anti-spam case), and a genuinely new head SHA is eligible again. Workflow
  YAML validated via `actionlint`; a `workflow_dispatch` `dry_run` input
  lets it report what it *would* do without acting.
- All new Python scripts pass `make lint` (ruff/mypy/bandit) and `make
  test` alongside the rest of the suite.

## Acceptance criteria

- [x] Phase 813 is merged before 812-A implementation begins.
- [ ] A PR touching `scripts/start-poc.sh`, `docker-compose.poc.yml`, or
      any `deploy/docker/Dockerfile.*` with a deliberately reintroduced
      cold-start bug fails CI at PR time, including on a 4-core runner.
      (Real verification happens on the first PR that touches one of these
      paths after this phase merges — `poc-cold-start` itself runs
      `start-poc.sh`, already end-to-end verified in Phase 813.)
- [x] `scan_exceptions.py --within-days 5` lists soon-to-expire entries
      with dates computed from today, not the old expiry (unit-tested).
      Live verification of the scheduled workflow opening a real PR happens
      on its first Wednesday run, or via manual `workflow_dispatch`.
- [ ] A Dependabot Actions-bump PR with a *correct* new SHA gets an
      automatic fixup commit via `pull_request_target` and goes green
      without human intervention; confirmed idempotent on re-run. (Unit
      logic verified with mocked `git ls-remote`; live confirmation
      pending the next real Dependabot Actions-group bump PR.)
- [x] A Dependabot Actions-bump PR with a deliberately *wrong* SHA (test
      fixture, not real) fails loudly and is NOT auto-patched — unit-tested
      directly (`test_mismatched_sha_fails_loudly_and_does_not_patch`);
      confirmed the script only ever reads the PR branch's files as data
      (a git worktree), never executes anything from it.
- [ ] After a main-branch CI-affecting fix lands, open Dependabot PRs get
      exactly one close/reopen refresh per head SHA — dedup rule
      unit-tested directly; live confirmation pending the next real
      main-branch fix that leaves Dependabot PRs stale.
- [x] `make test` and `make lint` pass with zero warnings.
- [x] `docs/reference/REDIS_SCHEMA.md` unaffected (no new Redis keys this
      phase — that's Phase 813).

## Out of scope

- Changing the Phase 226 7-day exception-window maximum itself.
- Replacing `prom/haproxy-exporter` (tracked as its own follow-up, noted in
  PHASE_810.md).
- Any change to `internal/`, `cmd/ja4pd/`, or proxy scoring logic.
- Retroactively backfilling `KNOWN_ACTION_SHAS` entries for actions not
  currently pinned in this repo.
- General CVE discovery for brand-new, never-before-seen exceptions — that
  remains the existing Monday CI sweep's job.
