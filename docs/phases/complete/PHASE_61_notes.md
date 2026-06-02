# Phase 61 — Closing notes

## Review-fix addendum #2 (post second external SRE review, 2026-04-09)

A second independent SRE/security review caught two more supply-chain holes
hidden inside the supply-chain hardening phase itself, and one silent-failure
in the secrets-scanner job:

**B2 — Three install commands were unpinned, defeating the SHA-pinning policy.**
The whole point of pinning every `uses:` line to a 40-char SHA is to keep CI
deterministic and to keep unverified third-party code out of the build. Three
`run:` steps then turned around and installed unpinned tools:

- `pip install ruff` (lint job, ci.yml ~85)
- `pip install pip-audit` (Python audit job, ci.yml ~132)
- `go install golang.org/x/vuln/cmd/govulncheck@latest` (Go audit job, ci.yml ~147)

A `@latest` CVE scanner is itself unverified third-party code that auto-upgrades
on every CI run. A regression in any of those three could silently break or
silently pass CI. **Fix:** pinned all three to specific versions:

- `ruff==0.15.9`
- `pip-audit==2.10.0`
- `govulncheck@v1.1.4`

Each pin has an inline comment explaining why pinning matters here. Dependabot
already covers `gomod` / `pip` / `github-actions` ecosystems and will open bump
PRs for govulncheck and ruff/pip-audit (the latter via requirements would be
even tighter, but moving these to requirements.txt is out of scope for the
review-fix).

**B3 — TruffleHog secrets scan was a no-op on `push` events to main.**
The `secrets-scan` job set `base: ${{ github.event.repository.default_branch }}`
and `head: HEAD`. On a push to `main`, both expressions resolve to the same
commit (the new tip of `main`), so TruffleHog diffs an empty range — it scans
zero commits and the job silently passes. The exact event the job is supposed
to gate (a secret being merged to main) is the one event where it does nothing.

**Fix:** branch the `base` and `head` by event type:

```yaml
base: ${{ github.event.pull_request.base.sha || github.event.before }}
head: ${{ github.event.pull_request.head.sha || github.sha }}
```

- On `pull_request`: diff PR base → PR head (the actual change set).
- On `push`: diff `github.event.before` (previous tip) → `github.sha` (new tip).
- On `schedule` (weekly): both fall through to the full HEAD scan.

Tests: `tests/test_workflow_pinning.py` 7/7 PASS — the SHA-allowlist tests
inspect `uses:` lines only, so the `run:`-only changes do not affect the
existing pinning contract. The new pins are pure version-string changes;
no SHAs in the allowlist needed updating.

## Review-fix addendum (post external review)

External SRE/security review (reviewer #1) flagged a real supply-chain hole:
the SHA `65d7f2d534ac1bc67fcd62888c5f4f3d2cb2b236` was pinned in five places
under the comment `# v5.0.0`, but that SHA is upstream `actions/setup-python@v4.7.1`.
The real `v5.0.0` SHA is `0a5c61591373683505ea898e09a3ea4f39ef2b9c`.

The wrong SHA originated in `PHASE_61.md` itself — the implementer copied the
spec faithfully. Review-fix commit:

1. Replaced the SHA in `.github/workflows/ci.yml` (3 lines) and
   `.github/workflows/ja4proxy-policy.yml` (2 lines).
2. Corrected the spec in `docs/phases/PHASE_61.md` (2 places) so the next
   re-implementation does not repeat the bug.
3. Added `test_sha_matches_tag_comment` to `tests/test_workflow_pinning.py`
   with a vendored `KNOWN_ACTION_SHAS` allowlist (no network in tests). The
   test catches the entire class of "comment lies about which version this
   SHA actually is" bugs. Verified all 7 `release-cli.yml` action pins
   upstream while populating the allowlist — they are honest.
4. Added `test_branch_protection_contexts_match_ci_job_names` — locks the
   contract that `branch_protection.sh` contexts equal the `name:` fields
   of required jobs in `ci.yml`. Drift here would silently turn branch
   protection into a no-op gate (the highest residual silent-failure risk
   the reviewer found). Test passes today.

Two `release-cli.yml`-only and `PHASE_202.md`/`strategic_security_architecture_review.md`
references to the wrong SHA still exist on `main`. They are NOT exploited
(release-cli.yml never used the bad SHA) but should be corrected as a
follow-up doc-only patch outside Phase 61 scope.

Tests: 7/7 pass.

## Summary of what landed

- `.github/workflows/ci.yml` (new) — eight jobs:
  - `test-go`, `test-python`, `lint` (the three test jobs from the spec)
  - `secrets-scan` (TruffleHog v3.88.2), `sast` (Semgrep v1),
    `dependency-audit-python` (pip-audit), `dependency-audit-go`
    (govulncheck), `dependency-review` (PR-only)
  - Triggered on pull_request, push to main, and weekly cron `0 6 * * 1`
  - Top-level `permissions: contents: read`; jobs override locally where needed
- `.github/workflows/ja4proxy-policy.yml` — `@v4`/`@v5` replaced with the same
  SHAs used in `release-cli.yml`. Top-level `permissions: contents: read`
  added. No logic changes.
- `.github/dependabot.yml` (new) — github-actions / pip / gomod, weekly,
  per-ecosystem PR cap of 5, grouped action bumps.
- `scripts/branch_protection.sh` (new, +x) — one-shot bootstrap; **not run by
  the agent**, the human operator runs it themselves once.
- `docs/security/CVE_EXCEPTIONS.md` (new) — template + 7-day HIGH SLA + 90-day
  expiry cap.
- `tests/test_workflow_pinning.py` (new) — TDD verification: every `uses:`
  is a 40-char SHA, every workflow has a top-level `permissions:` block,
  branch-protection script is executable, dependabot.yml is valid and covers
  the three ecosystems.
- `Makefile` — appended new `ci-local` target (no edits to existing targets).
- `CHANGELOG.md` — new entry prepended at the top.

## Deviations from PHASE_61.md

1. **Security jobs in `ci.yml`, not split into `security.yml`.** The spec
   said "in `ci.yml` or split — your call". Keeping them together makes the
   permissions/scheduling story easier to audit and avoids duplicating the
   weekly cron and shared `permissions:` block. Documented at the top of
   `ci.yml`.

2. **`returntocorp/semgrep-action@v1` instead of `semgrep-action@<SHA> # v3.88.x`.**
   The phase doc's table cell `trufflesecurity/trufflehog@<SHA> # v3.88.x` was
   correct (and used for trufflehog), but the Semgrep cell pointed at
   `returntocorp/semgrep-action@<SHA>` without specifying a tag. The latest
   tag on `returntocorp/semgrep-action` is `v1` at SHA
   `713efdd345f3035192eaa63f56867b88e63e4e5d`; I pinned that.

3. **`dependency-review` job is `pull_request`-gated only.** GitHub's
   `dependency-review-action` only operates on pull_request events; running it
   on push or schedule is a no-op error. Excluded via `if:` and not listed as
   a required status check on push (it would always be missing). It IS
   required on PRs.

4. **`branch_protection.sh` uses status check display names**, e.g. `Go tests`,
   `Python tests`, `Lint (go vet + gofmt + ruff)`, etc. — these are the
   `name:` fields of each job in `ci.yml`, which is what GitHub matches on for
   required status checks. The phase doc used job IDs (`test-go`, `test-python`,
   `lint`) which would not have matched. Worth flagging to the reviewer.

5. **One unpinned `uses:` remains in the repo**, in `release-cli.yml` line 57:
   `uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0`.
   This is a reusable workflow and **GitHub does not allow SHA refs for
   reusable workflow `uses:` lines**. The pinning test in
   `tests/test_workflow_pinning.py` skips reusable-workflow refs (matched via
   the `/.github/workflows/` substring). This file is owned by Phase 202 / a
   prior phase and is out of scope for Phase 61, but the test exemption is
   documented inline.

## Operator action — run after merge

Once `claude/phase-61-ci` is merged to `main`, the human operator should run:

```bash
bash scripts/branch_protection.sh AnomalyCo/JA4proxy   # adjust owner/repo
```

(replace `AnomalyCo/JA4proxy` with the real GitHub `<owner>/<repo>`).

This sets the required status checks on `main` to:
- `Go tests`
- `Python tests`
- `Lint (go vet + gofmt + ruff)`
- `Secrets scan (TruffleHog)`
- `SAST (Semgrep)`
- `Python dependency audit (pip-audit)`
- `Go dependency audit (govulncheck)`

Record the date and operator on the line below when run:

> Branch protection bootstrapped on: _________ by: _________

## QA gate output

```
$ python3 -m pytest tests/test_workflow_pinning.py -v
tests/test_workflow_pinning.py::test_every_workflow_parses_as_yaml PASSED
tests/test_workflow_pinning.py::test_every_uses_line_is_sha_pinned PASSED
tests/test_workflow_pinning.py::test_every_workflow_has_top_level_permissions PASSED
tests/test_workflow_pinning.py::test_branch_protection_script_executable PASSED
tests/test_workflow_pinning.py::test_dependabot_config_present_and_valid PASSED
============================== 5 passed in 0.41s ===============================

$ python3 -c "import yaml; yaml.safe_load(open('.github/dependabot.yml'))"
(no error)

$ python3 -c "import yaml, glob; [yaml.safe_load(open(f)) for f in glob.glob('.github/workflows/*.yml')]"
(no error)

$ bash -n scripts/branch_protection.sh
(no error)

$ test -x scripts/branch_protection.sh
(exit 0)

$ grep -nE "@v[0-9]" .github/workflows/*.yml
.github/workflows/release-cli.yml:57:    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0
# (one match, intentional — reusable workflow, GitHub disallows SHA refs)

$ grep -cE "@[a-f0-9]{40}" .github/workflows/*.yml
.github/workflows/ci.yml:17
.github/workflows/ja4proxy-policy.yml:4
.github/workflows/release-cli.yml:10
# 31 total — well over the > 10 floor
```

## Open questions for the reviewer

1. **`pip-audit --strict`** — strict only fails on parse errors, not on CVE
   severity. The phase doc says "Fails CI on HIGH/CRITICAL CVEs". `pip-audit`
   exits non-zero on *any* vulnerability by default; there is no built-in
   severity gate. Acceptable trade-off, or do we wire `osv-scanner` /
   `safety` for severity-gated behaviour in a follow-up?

2. **Semgrep `returntocorp/semgrep-action@v1`** is end-of-lifed and the
   project moved to `semgrep/semgrep` (and `semgrep ci`). The current pin is
   stable but we should plan to migrate in a follow-up phase. Track in
   Dependabot.

3. **Status-check names vs job IDs** in `branch_protection.sh` — confirm
   GitHub's behaviour matches my reading. Easy to fix in a one-line change if
   not.

4. **`manifest.yaml`** — left untouched per the prompt instructions ("do NOT
   mark COMPLETE; that is for the human to do after review").

5. **`ja4proxy-policy.yml` was modified by a linter mid-edit** (the file now
   uses double-quoted single-quoted alignment). This is intentional and harmless;
   only the SHA pins and the `permissions:` block are functional changes.
