<!--
title: "CI and Quality Gates"
audience: developers
last_reviewed: 2026-04-25
phase: 105
-->

# CI and Quality Gates

This page describes **what every CI workflow enforces** and **how to reproduce
a failure locally**. It does not transcribe YAML — every rule cites the
authoritative file by line range. If a CI rule appears here that contradicts
the workflow file, the workflow file wins; open a PR to fix this page.

> **Production runtime is the Go proxy.** Every gate that exists for both
> Python and Go applies to both, but the production blast-radius of a Python
> regression is limited to the Python prototyping surface and the analytics /
> management services that remain in Python.

---

## Workflow inventory

The repository has **five** workflows under `.github/workflows/`. Each
section below describes the purpose and gate behaviour of one workflow.

### `ci.yml` — fast-feedback PR + push gate

`.github/workflows/ci.yml` runs on every PR and every push to `main`. The
workflow header (lines 1–32) documents the trigger contract: PR, push to
`main`, and a weekly cron at `0 6 * * 1` (Mondays 06:00 UTC) for the CVE
sweep. Default `permissions` is `contents: read`; jobs that need broader
scope override at the job level.

The jobs in `ci.yml` are described below. Only the **required** jobs gate
merges to `main`; non-required jobs are notifications.

#### Required jobs

- **`test-go`** — `Go tests` (lines 34–45). Runs `go test ./...` with
  `GOFLAGS: "-count=1"` to defeat the test result cache. Pinned to Go
  `1.25.9`.
- **`test-python`** — `Python tests` (lines 47–62). Runs the pytest suite
  on Python 3.14 with `-x` (stop on first failure), `--timeout=60`, and
  excludes `tests/integration/test_docker_stack.py` and `tests/management/`
  (those need a live stack and run only via `make test-docker`).
- **`lint`** — `Lint (go vet + gofmt + ruff)` (lines 64–94). Three
  sub-checks: `gofmt -l` filtered to exclude agent worktrees and vendored
  code, `go vet` with the same exclusions, and `ruff check .` pinned to
  ruff `0.15.9`.
- **`secrets-scan`** — `Secrets scan (TruffleHog)` (lines 96–118). Uses
  `--only-verified`. Branches the diff base by event type so push-to-main
  diffs against `github.event.before` (otherwise base and head collapse to
  the same commit and the scan silently passes).
- **`sast`** — `SAST (Semgrep)` (lines 120–134). Runs Semgrep `1.67.0`
  with the rule packs `p/ci`, `p/security-audit`, `p/secrets`, and
  `--error` so any finding fails the job.
- **`dependency-audit-python`** — `Python dependency audit (pip-audit)`
  (lines 136–151). Pinned to pip-audit `2.10.0` with `--strict`.
- **`dependency-audit-go`** — `Go dependency audit (govulncheck)` (lines
  153–168). Pinned to `golang.org/x/vuln/cmd/govulncheck@v1.1.4`.

#### Non-required jobs

- **`dependency-review`** — `Dependency review (PR gate)` (lines 170–184).
  PR-only; `continue-on-error: true` because GHAS is required on private
  repos and the workflow must not block when GHAS is unavailable. Denies
  `GPL-2.0`, `GPL-3.0`, `AGPL-3.0`, `SSPL-1.0`. Fails on severity `high`.
- **`traceability`** — `Traceability matrix check` (lines 186–214).
  Non-blocking until `2026-05-08T00:00:00Z`; after the cutoff the step
  exits non-zero and fails the build. The date gate lives inside the step
  because GitHub Actions does not support event-timestamp expressions in
  `continue-on-error` cleanly.
- **`smoke-docker`** — `Smoke test (Docker Compose)` (lines 216–233).
  `continue-on-error: true`; calls `scripts/smoke/test_docker_compose.sh`.
  Promotion to required is gated on a 14-day green window per the workflow
  comment.

The required-vs-non-required split is also enforced by
`tests/test_workflow_pinning.py::test_branch_protection_contexts_match_ci_job_names`
against `scripts/branch_protection.sh`. A drift between the two would
silently turn a required check into a no-op gate; the test catches that.

### `go-proxy-image.yml` — production image build, scan, sign, push

`.github/workflows/go-proxy-image.yml` triggers on changes to
`deploy/docker/Dockerfile.go-proxy`, `cmd/proxy/**`, `internal/**`,
`go.mod`, or `go.sum`, plus `v*-go-proxy` tags and `workflow_dispatch`
(lines 7–17). The flow is:

1. `test` — `go test -race ./...` (lines 28–42).
2. `build-scan-sign-push` (lines 44–149). Builds locally, scans with Trivy
   (`CRITICAL` only, fails on findings, `ignore-unfixed: true`), generates a
   CycloneDX SBOM with `anchore/sbom-action`, pushes to GHCR, then signs
   keyless with Cosign via Fulcio OIDC. The signing backend decision is
   ADR-202d.

`id-token: write` is required for keyless cosign and is scoped to that job
only.

### `release-cli.yml` — tagged release pipeline

`.github/workflows/release-cli.yml` triggers on semver tags
(`v[0-9]+.[0-9]+.[0-9]+`, lines 3–6). Three sequential jobs:

1. `goreleaser` (lines 14–47) — imports the GPG signing key, runs
   GoReleaser `~> v2`.
2. `provenance` (lines 49–61) — calls the SLSA reusable workflow
   `slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml`,
   pinned per ADR-202a Path A. Reusable workflows cannot be SHA-pinned by
   GitHub rules; the SHA appears as a trailing `# vTAG` comment and
   `tests/test_workflow_pinning.py` allows this exact form.
3. `container` (lines 63–105) — builds and pushes the multi-arch CLI image
   to `ghcr.io/anomalyco/ja4proxy-cli`.

### `ja4proxy-policy.yml` — policy-as-code apply pipeline

`.github/workflows/ja4proxy-policy.yml` triggers on changes to any
`**/ja4proxy-policy.yaml` file (lines 30–36). Two jobs:

1. `validate` (lines 39–55) — schema + TTL + dial-increase check via
   `python3 scripts/ja4proxy-policy.py validate`. Runs on every branch.
2. `apply` (lines 57–88) — applies the policy to the production
   Management API via `JA4PROXY_TOKEN`. Gated to `main` push only
   (`if: github.ref == 'refs/heads/main' && github.event_name == 'push'`).
   The token is passed via `env`, never on the command line, to avoid
   leakage into `/proc/<pid>/cmdline` or step-summary echoes
   (JA4PROXY-2026-0018, see lines 77–87).

### `process-metrics.yml` — monthly engineering-metrics regeneration

`.github/workflows/process-metrics.yml` runs on a cron (`0 6 1 * *` —
06:00 UTC on the 1st of each month, lines 14–17) plus `workflow_dispatch`.
The job runs `scripts/process_metrics.py`; if
`docs/engineering-method/retrospectives/latest-metrics.md` changed, it
commits the regenerated file back to `main` as `github-actions[bot]`. This
workflow is the only place where automated commits to `main` are allowed.

---

## Reproduce CI locally

When a CI job fails, reproduce it locally **before** pushing a fix. Fixing
the first failure under `pytest -x` only to discover a second on the next
CI run is wasted cycle time; see [`HOW_WE_WORK.md`](HOW_WE_WORK.md) §Local
merge gate.

```bash
# Equivalent to `lint` + `test-go` + `test-python` (and more).
make test

# Equivalent to `lint` job — every linter the repo runs.
make lint-all

# Full quality bar — lint-all + coverage gates + go-coverage check.
make quality

# Reproduce the CVE jobs locally before the next Monday cron.
pip install pip-audit==2.10.0 && pip-audit -r requirements.txt --strict
GOROOT=/snap/go/current go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
GOROOT=/snap/go/current "$(GOROOT=/snap/go/current go env GOPATH)/bin/govulncheck" ./...
```

`make test` is the most important command — it runs four static analyses
(`mypy`, `bandit`, `ruff`, `pip-audit`) **before** pytest. Any `✗` or `[!]`
in the output is a blocking failure equivalent to a red CI job. See
[`../../AGENTS.md`](../../AGENTS.md) §What `make test` actually checks.

`make test` does **not** catch dev-vs-CI environment divergence (e.g. a
test that silently uses your local Redis). For that class, the only reliable
gate is the CI run on the PR itself.

---

## SHA-pinning rule

Every `uses:` line in every workflow must reference a **40-character commit
SHA**, with a trailing `# vTAG` comment for human readability. Tags are not
trusted because tags can be moved.

The rule is enforced by `tests/test_workflow_pinning.py`:

- `test_every_uses_line_is_sha_pinned` — every `uses:` is a 40-char hex SHA
  (the one allowed exception is reusable workflows, where GitHub requires
  a ref).
- `test_sha_matches_tag_comment` — the `# vTAG` comment matches the
  vendored allowlist `KNOWN_ACTION_SHAS`. A wrong-SHA-with-lying-comment
  bug found in the Phase 61 review prompted this check.
- `test_every_workflow_has_top_level_permissions` — every workflow declares
  a top-level `permissions:` block so the default `GITHUB_TOKEN` scope is
  explicitly narrowed.

When Dependabot opens an action SHA bump, **also update `KNOWN_ACTION_SHAS`
in `tests/test_workflow_pinning.py`**. To verify a SHA by hand:

```bash
git ls-remote https://github.com/<owner>/<repo> refs/tags/<tag>
```

The procedure for adding a new action — pin SHA, add allowlist row, leave
the tag as a trailing comment — is documented in the `ci.yml` header
(lines 10–17) using `release-cli.yml` as the canonical template.

---

## Weekly CVE sweep

The cron schedule `0 6 * * 1` (Mondays 06:00 UTC, see `ci.yml` line 26) re-runs
`pip-audit`, `govulncheck`, `secrets-scan`, and `sast` against `main` so a
newly-disclosed CVE that affects an already-merged dependency is flagged
within seven days of disclosure rather than waiting for the next PR.

A red weekly-sweep run is a tracked incident under the keep-main-green
policy ([`HOW_WE_WORK.md`](HOW_WE_WORK.md) §Keep-main-green policy). The
maintainer on rotation owns a dependency-update PR within 24 hours.

---

## What a green PR looks like

- All required `ci.yml` jobs green (the seven listed above).
- A `make test` log tail (or equivalent evidence) in the PR description.
- A test plan checklist with at least one entry per category that applies.
- Co-author trailer, conventional commit format (see
  [`HOW_WE_WORK.md`](HOW_WE_WORK.md) §Commits).
- Any new `uses:` line in a workflow accompanied by a row in
  `KNOWN_ACTION_SHAS`.

If any of these is missing, the reviewer requests changes.

---

## Cross-references

- Branch flow, keep-main-green policy: [`HOW_WE_WORK.md`](HOW_WE_WORK.md)
- Test discipline: [`TDD_AND_TESTING.md`](TDD_AND_TESTING.md)
- Operational response when `main` is red:
  [`../runbooks/main_is_red.md`](../runbooks/main_is_red.md)
- Phase close-out (which runs the full gate via `/close-phase`):
  [`PHASE_LIFECYCLE.md`](PHASE_LIFECYCLE.md)
- Full agent test rules: [`../../AGENTS.md`](../../AGENTS.md)
