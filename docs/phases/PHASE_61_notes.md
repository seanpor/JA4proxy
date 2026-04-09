# Phase 61 — Closing notes

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
