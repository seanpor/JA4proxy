---
phase: 810
title: "Security-scan gate CVE fix + Dependabot Actions-bump review"
status: COMPLETE
created: 2026-07-27
audience: [developer]
---

# Security-scan gate CVE fix + Dependabot Actions-bump review

## Goal (plain language)

Two things are blocking routine CI/CD flow right now:

1. Issue #364 — the weekly scheduled `make scan` run failed. Root cause
   identified (see Investigation): a newly-indexed CRITICAL CVE in
   `grafana/grafana:13.0.2-ubuntu`'s vendored `kin-openapi` dependency, with
   no upstream fix available in any published Grafana tag. This isn't a
   one-off — it will fail **every** PR's Security Scan check (including
   PR #347, see below) until `.trivyignore` is updated, per the repo's
   dated-exception policy (`docs/runbooks/security_scan_exceptions.md`,
   Phase 226).
2. PR #347 — Dependabot's grouped GitHub Actions bump (13 actions, includes
   two majors: `actions/checkout` 6→7, `actions/github-script` 7→9). It's
   currently `BLOCKED`/30 commits behind `main` and its auto-merge workflow
   correctly skipped it (major bumps are manual-review-only per
   `.github/workflows/dependabot-automerge.yml`). Needs a compatibility
   review of the two breaking changes, then a rebase and merge once CI is
   green — which requires (1) to land first.

Issue #292 (purge the 25 MB `ja4-tap` blob from git history via
`git filter-repo` + force-push to `main`) is **explicitly out of scope for
this phase** — see "Out of scope" below.

## Investigation (already done, informing the plan)

**Issue #364 root cause:**
- `Security Scan (make scan)` job failed at the `scan-images` third-party
  image step: `grafana/grafana:13.0.2-ubuntu` now reports
  `GHSA-r277-6w6q-xmqw` (CRITICAL, CVSS 9.1) — `kin-openapi`
  `ValidationHandler.Load()` silently substitutes a no-op auth function when
  none is set, allowing an OpenAPI-declared-protected endpoint to be called
  unauthenticated. Fixed upstream in `kin-openapi` 0.144.0; Grafana vendors
  v0.133.0.
- Confirmed via direct Trivy scan: the newest published Grafana tag,
  `13.0.4-ubuntu`, **still** vendors `kin-openapi` v0.133.0 — no fixed tag
  exists yet. This needs a `.trivyignore` exception, not a version bump.
- However, bumping `grafana/grafana:13.0.2-ubuntu` → `13.0.4-ubuntu` (in
  `deploy/docker/docker-compose.monitoring.yml` and
  `docker-compose.prod.yml`) is a separate, strictly-positive move: full
  Trivy diff shows 18 fewer CRITICAL/HIGH findings on the Grafana image
  itself, **zero new findings**. All 18 are still needed in `.trivyignore`
  regardless (they also affect `loki:3.7.2`/`promtail:3.6.11`/
  `alertmanager:v0.33.1`, which aren't being touched here), so no existing
  `.trivyignore` entries can be deleted — this bump reduces real vulnerable
  surface in the running Grafana container without changing the exception
  list's size.
- Remaining Grafana-only findings after the bump (`CVE-2026-21728`,
  `CVE-2026-28377`, `CVE-2026-42151`, `GHSA-hrxh-6v49-42gf`,
  `CVE-2026-27145`, `CVE-2026-39822`, `CVE-2026-42504`) are all already
  covered by existing dated `.trivyignore` entries.

**PR #347 compatibility review (already done):**
- `actions/checkout` v7 blocks fork-PR checkout under `pull_request_target`/
  `workflow_run`. Grepped `.github/workflows/`: **neither trigger is used
  anywhere in this repo.** Not applicable — safe.
- `actions/github-script` v9 breaks `require('@actions/github')` and
  `const/let getOctokit` redeclaration. Grepped all workflows: the only
  `actions/github-script` step (`ci.yml`, the scheduled-failure tracking
  issue creator — the exact automation that filed #364) uses only the
  injected `github` object, no `require(...)`, no `getOctokit` redeclare.
  Safe.
- No other workflow-breaking patterns found for the remaining 11 (minor/patch)
  bumps.
- Conclusion: PR #347 is safe to merge once rebased onto a `main` that has
  the `.trivyignore` fix (so its own Security Scan check goes green).

## Scope

**In scope:**
1. Add a dated `.trivyignore` entry for `GHSA-r277-6w6q-xmqw`, following the
   file's established format (comment block: what/why-no-fix/why-not-
   exploitable-here, then `GHSA-... exp:2026-08-03` — 7 days out, matching
   the file's max-window policy).
2. Bump `grafana/grafana:13.0.2-ubuntu` → `13.0.4-ubuntu` in
   `deploy/docker/docker-compose.monitoring.yml` and
   `deploy/docker/docker-compose.prod.yml`.
3. Update the existing `.trivyignore` comment blocks that currently say
   "Affects grafana:13.0.2-ubuntu" to say "13.0.4-ubuntu" where Grafana is
   still one of the affected images (accuracy only — no entries removed).
4. Run `make scan` locally to confirm the gate is green before pushing.
5. Once merged to `main`: comment `@dependabot rebase` on PR #347, wait for
   Dependabot to rebase, verify all required checks pass (especially
   Security Scan), then `gh pr merge --auto --squash --delete-branch`.

**Out of scope:**
- **Issue #292 (git history rewrite).** The issue's own text flags this as
  needing explicit coordination: a temporary lift of `main`'s branch
  protection, a `git filter-repo` rewrite, a force-push that invalidates
  every existing clone/branch/open-PR, and an announce-before/after step —
  none of which are appropriate to bundle into an unattended CI fix. I'll
  raise this separately once #810 and #347 are out of the way, and want an
  explicit go-ahead on timing (e.g., "no other phase branches/PRs in
  flight" — right now there's other `IN_PROGRESS` work per the manifest:
  phases 519 and 800) before touching it.
- Re-basing Loki/Promtail/Alertmanager to newer tags (they don't clear any
  of their own waived CVEs per a quick cross-check — separate effort, not
  blocking anything today).
- Anything beyond the two breaking-change checks on PR #347 — the other 11
  action bumps are patch/minor version-only.

## Scope expansion during implementation (user-approved)

Implementing the `.trivyignore` fix and doing basic due diligence on the
Grafana bump prompted a bigger question: how do we stop `TRIVY_IMAGES` (the
Makefile's third-party scan list) from silently drifting from the compose
files again? Answering it properly — deriving the list from the compose
files instead of hand-copying it — required actually running that derivation,
which immediately surfaced that **three images in
`docker-compose.monitoring.yml` had never been in the hand-maintained list at
all**: `tecnativa/docker-socket-proxy:0.3.0`, `gcr.io/cadvisor/cadvisor:v0.47.2`,
`prom/haproxy-exporter:v0.15.0`. Between them: 113 real HIGH/CRITICAL
findings, never scanned, never waived, never reviewed.

Presented this to the user with the options (bump what can be bumped now and
waiver the rest vs. defer entirely vs. also redesign the haproxy-exporter
sidecar away). Approved: **bump + waiver now, architecture change deferred.**
Added to scope:

4. `scripts/check_image_versions.py`: new `third_party_image_refs()` +
   `--list-third-party` CLI mode — the single source of truth for
   `TRIVY_IMAGES`, replacing the hand-maintained Makefile list. Raises
   `ValueError` on cross-file version drift (can't pick one version to scan)
   instead of silently choosing one.
5. `Makefile`: `TRIVY_IMAGES` is now `$(shell $(PYTHON)
   scripts/check_image_versions.py --list-third-party)` (lazy `=`, not `:=`,
   so it only runs when a recipe references it). `scan-images` derives its
   own copy directly (not through the Make variable) with an explicit guard:
   the script's exit code is checked (`||`) and the result is checked
   non-empty — an error or empty list fails loudly instead of silently
   scanning zero images. Verified by inducing a real version-drift condition
   (temporarily mismatching Grafana's tag between the two compose files) and
   confirming `make scan-images` fails with a clear message rather than
   passing.
6. Bumped `tecnativa/docker-socket-proxy` `0.3.0` → `v0.5.0` (scans
   completely clean — no waiver needed) and `gcr.io/cadvisor/cadvisor`
   `v0.47.2` → `v0.52.1` (57 findings → 41).
7. `.trivyignore`: 37 new dated entries for what's left in cadvisor (xz-libs,
   moby, runc, grpc, plus the shared Go stdlib/x-net/x-crypto/x-oauth2 DoS
   backlog) and all of `prom/haproxy-exporter:v0.15.0` (confirmed abandoned
   upstream — last published tag is from 2023-02-15, no newer tag exists to
   bump to). Three existing entries (`CVE-2026-34040`, `CVE-2026-41567`,
   `CVE-2026-42306`) and `GHSA-hrxh-6v49-42gf` updated to add cadvisor to
   their affected-image list with cadvisor-specific exploitability reasoning
   (it does hold a read-only Docker socket mount, unlike promtail post-Phase
   0017 — reasoning had to be written per-image, not copy-pasted).
8. Verified all three previously-unscanned images are internal-network-only
   (no `ports:` mapping in `docker-compose.monitoring.yml` — reachable only
   from Prometheus/other containers on `ja4proxy-monitoring`), which grounds
   every "why not exploitable" justification in that file for these images.
9. Unit tests added: `tests/unit/test_check_image_versions.py`
   `TestThirdPartyImageRefs` (first-party exclusion, cross-file dedup,
   sorted output, missing-file handling, version-drift `ValueError`, custom
   first-party set).
10. `docs/reference/DOCKER_IMAGES.md` Grafana row updated (tag + date + note).

**Follow-up, not done here:** replace `prom/haproxy-exporter` with HAProxy
2.8's built-in Prometheus exporter (already running `haproxy:2.8.26-alpine`),
which would eliminate the abandoned-upstream sidecar and its 54 CVEs
entirely rather than re-justifying dated waivers for it indefinitely. Needs
its own phase (haproxy.cfg change, Prometheus scrape-config change, checking
Grafana dashboards/Alertmanager rules for `haproxy_exporter`-specific metric
names) — not scoped here.

## Implementation plan

1. `.trivyignore`: insert new entry near the other Grafana-image entries,
   following file conventions exactly (comment block above, `exp:` 7 days
   from today).
2. `docker-compose.monitoring.yml` line 77, `docker-compose.prod.yml` line
   297: bump the tag string.
3. Text-only edits to ~7 existing `.trivyignore` comment blocks that name
   `grafana:13.0.2-ubuntu` (image-version accuracy, not logic changes).
4. `make scan-exceptions` to confirm the new entry parses and isn't already
   expired; `make scan` (full, containerized) to confirm the gate is green.
5. No application code, tests, or config schema changes — this phase touches
   only ops/security-exception files, so no new unit tests are needed. The
   existing `tests/unit/test_makefile_targets.py`-style guard already covers
   `.trivyignore` format (`scan_exceptions.py`'s own regex) — no gap to fill.
6. CHANGELOG fragment at `docs/fragments/phase-810-scan-gate-cve.md`.
7. Manifest entry for phase 810, `status: COMPLETE` at close.

## Test strategy

- `make scan-exceptions` — new entry parses, not expired, respects the 7-day
  cap.
- `make scan` (containerized, full) — the actual failing gate from issue
  #364, run locally before pushing, must exit 0.
- `docker compose -f deploy/docker/docker-compose.monitoring.yml config` and
  the `.prod.yml` equivalent — confirms the tag bump doesn't break compose
  file parsing.
- CI itself (Security Scan, Full Lint, Full Test, Meta-Validation — the four
  required checks) on the PR.

## Acceptance criteria

- [x] `make scan` passes locally with the new `.trivyignore` entries
      (verified full containerized run — all 12 derived third-party images
      + all 7 first-party images clean).
- [x] `grafana/grafana:13.0.4-ubuntu` in both compose files; `make
      lint-docker` (`docker compose config`) validates both, plus
      `docker-compose.test.yml`/`.scale.yml` overlay.
- [x] No pre-existing `.trivyignore` entries deleted (verified none of the
      18 Grafana-only-in-13.0.2 CVEs are exclusively Grafana's — all also
      hit Loki/Promtail/Alertmanager).
- [x] `TRIVY_IMAGES` now derived from the compose files, not hand-maintained
      (`scripts/check_image_versions.py --list-third-party`); verified the
      drift-guard actually fails loudly by inducing real drift.
- [x] The three previously-unscanned images (`tecnativa/docker-socket-proxy`,
      `gcr.io/cadvisor/cadvisor`, `prom/haproxy-exporter`) are now in the
      scan gate, with real findings either fixed (version bump) or waived
      (dated, justified).
- [x] Issue #364 root cause fixed — will be closed by referencing this PR.
- [ ] PR #347 rebased onto the fixed `main`, all required checks green,
      merged. (Next step after this phase's PR merges.)
- [x] Issue #292 explicitly deferred with a comment explaining why, not
      silently dropped.
- [x] New unit tests (`TestThirdPartyImageRefs`, 6 cases) pass; full
      `make test-unit` (1682 + 755 items) and `make lint` both green.

## Redis / config / observability impact

None. Touches `.trivyignore`, two Docker Compose image tags,
`scripts/check_image_versions.py`, `Makefile` (`TRIVY_IMAGES` derivation),
`docs/reference/DOCKER_IMAGES.md`, and their test coverage — no Redis keys,
no `config/proxy.yml` keys, no new metrics.
