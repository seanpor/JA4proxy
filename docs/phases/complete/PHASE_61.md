# Phase 61 — CI Test Pipeline + Repo Hardening

> **Status:** PROPOSED
> **Size:** M
> **Owner files:** `.github/workflows/ci.yml`, `.github/workflows/ja4proxy-policy.yml`, `.github/dependabot.yml`, `scripts/branch_protection.sh`, `docs/security/CVE_EXCEPTIONS.md`
> **Independent of:** Phase 62, 63, 64
> **Last rewritten:** 2026-04-09

---

## What this phase is

Add a GitHub Actions CI pipeline that runs the Go and Python test suites on
every pull request, plus the supply-chain hygiene this repo has never had:
SHA-pinning, Dependabot, branch protection, dependency review, secrets scan,
and SAST.

## What this phase is NOT

This phase **does not** build container images, generate SBOMs, sign images
with cosign, or produce SLSA provenance for the Go binary. All of that lives
in [Phase 202](PHASE_202.md), which was written more recently and is more
focused. Read 202 first if you want to know who owns the image pipeline.

The boundary is sharp:

| Concern | This phase (61) | Phase 202 |
|---|---|---|
| Run tests on every PR | ✅ | ❌ |
| SHA-pin existing workflow | ✅ (`ja4proxy-policy.yml`) | ✅ (re-states this for symmetry) |
| Dependabot for actions / pip / gomod | ✅ | ❌ |
| Secrets scan / SAST / dependency audit | ✅ | ❌ |
| Branch protection bootstrap | ✅ | ❌ |
| Build & push `ja4proxy` Go proxy image | ❌ | ✅ |
| Generate SBOM (Syft / CycloneDX) | ❌ | ✅ |
| Cosign keyless image signing | ❌ | ✅ |
| SLSA provenance for Go binary | ❌ | ✅ (`release-cli.yml` already does this for the CLI) |
| Remove default credentials from compose | ❌ | ✅ |

If a PR touches files in both columns, the orchestrator should pick one phase
to land first; the second phase rebases on it.

---

## What already exists on disk

Before writing any code, read what is already there:

- **`.github/workflows/release-cli.yml`** — fully SHA-pinned, includes
  `goreleaser`, cosign keyless, SLSA L3 generator, docker build/push for the
  `ja4check` CLI image. **Use this file as the SHA-pinning template** for
  every action below. It is the canonical pattern in this repo.
- **`.github/workflows/ja4proxy-policy.yml`** — exists, validates
  `ja4proxy-policy.yaml` files. **Currently uses `actions/checkout@v4` and
  `actions/setup-python@v5` (not SHA-pinned).** This phase fixes that.
- **No `.github/workflows/ci.yml`** — does not exist. This phase creates it.
- **No `.github/dependabot.yml`** — does not exist. This phase creates it.
- **No `docs/security/CVE_EXCEPTIONS.md`** — does not exist. This phase
  creates it.

Verify with:

```bash
ls .github/workflows/
ls .github/dependabot.yml 2>&1 || echo "missing — phase 61 will create"
```

---

## Implementation checklist

### Step 1 — Create `.github/workflows/ci.yml`

Triggered on every PR and every push to `main`. Three jobs run in parallel:

**Job `test-go`:** the production proxy test suite. Required status check.

```yaml
test-go:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
    - uses: actions/setup-go@3041bf56c941b39c61721a86cd11f3bb1338122a  # v5.2.0
      with:
        go-version: "1.22"
    - run: go test ./...
      env:
        GOFLAGS: "-count=1"
```

**Job `test-python`:** the experimental proxy + Management API + analytics
tests. Required status check. Excludes `tests/integration/test_docker_stack.py`
because it requires a live backend on port 8443 (run locally via `make
test-integration`). Excludes any test that needs Docker.

```yaml
test-python:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
    - uses: actions/setup-python@0a5c61591373683505ea898e09a3ea4f39ef2b9c  # v5.0.0
      with:
        python-version: "3.11"
    - run: pip install -r requirements.txt
    - run: python3 -m pytest tests/ --ignore=tests/integration/test_docker_stack.py -x -q --timeout=60
```

**Job `lint`:** `go vet ./...` + `gofmt -l .` + `ruff check .`. Required
status check. The full Go static analysis (`make lint-go-full`) is heavier
and runs locally; CI runs the fast subset.

```yaml
lint:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
    - uses: actions/setup-go@3041bf56c941b39c61721a86cd11f3bb1338122a
      with:
        go-version: "1.22"
    - run: test -z "$(gofmt -l .)" || (gofmt -l . && exit 1)
    - run: go vet ./...
    - uses: actions/setup-python@0a5c61591373683505ea898e09a3ea4f39ef2b9c
      with:
        python-version: "3.11"
    - run: pip install ruff && ruff check .
```

**Top-level `permissions:` block** — minimum required:

```yaml
permissions:
  contents: read
```

### Step 2 — Add a `security` job set in `ci.yml` (or split file)

Four jobs, all required status checks. SHA-pin every action via
`release-cli.yml` as template.

| Job | Tool | Action ref (template) | Fails CI on |
|---|---|---|---|
| `secrets-scan` | TruffleHog | `trufflesecurity/trufflehog@<SHA> # v3.88.x` | Any verified secret |
| `sast` | Semgrep | `returntocorp/semgrep-action@<SHA>` | HIGH severity |
| `dependency-audit-python` | `pip-audit` | n/a (pip install) | HIGH/CRITICAL CVEs |
| `dependency-audit-go` | `govulncheck` | n/a (go install) | Any known vuln |
| `dependency-review` | `actions/dependency-review-action@<SHA>` | n/a | HIGH severity, GPL/AGPL/SSPL |

Use `fetch-depth: 0` on the secrets-scan checkout so the full history is
scanned on PRs.

Add a weekly cron at `0 6 * * 1` so newly-disclosed CVEs that affect already-merged
dependencies are caught:

```yaml
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "0 6 * * 1"
```

The `dependency-review` job catches a vulnerable dependency at PR time
*before* it merges. The weekly scan catches a vulnerability disclosed *after*
the dependency was merged. Both are needed.

### Step 3 — SHA-pin `.github/workflows/ja4proxy-policy.yml`

The policy workflow currently uses `actions/checkout@v4` and
`actions/setup-python@v5` — both unpinned. Replace with the same SHAs used in
`ci.yml` and `release-cli.yml`. No other changes.

How to look up the SHA for any action:

```bash
git ls-remote https://github.com/actions/checkout refs/tags/v4.2.2
# 11bd71901bbe5b1630ceea73d27597364c9af683  refs/tags/v4.2.2
```

Always pin with a trailing tag comment for human readability:

```yaml
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

### Step 4 — Create `.github/dependabot.yml`

```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule: { interval: "weekly" }
    groups:
      actions:
        patterns: ["*"]

  - package-ecosystem: "pip"
    directory: "/"
    schedule: { interval: "weekly" }
    open-pull-requests-limit: 5

  - package-ecosystem: "gomod"
    directory: "/"
    schedule: { interval: "weekly" }
    open-pull-requests-limit: 5
```

Dependabot PRs for `github-actions` updates include both the new SHA and the
new tag in the commit message; CI runs against the PR before merge.

### Step 5 — Create `scripts/branch_protection.sh`

A standalone script the orchestrator runs **once** when the repo is first
configured (and again whenever the set of required status checks changes).

```bash
#!/usr/bin/env bash
# scripts/branch_protection.sh — bootstrap GitHub branch protection rules.
# Run once with: bash scripts/branch_protection.sh <owner>/<repo>
set -euo pipefail
REPO="${1:?Usage: branch_protection.sh <owner>/<repo>}"

gh api "repos/${REPO}/branches/main/protection" \
  --method PUT \
  --field required_status_checks='{
    "strict": true,
    "contexts": [
      "test-go",
      "test-python",
      "lint",
      "secrets-scan",
      "sast",
      "dependency-audit-python",
      "dependency-audit-go"
    ]
  }' \
  --field enforce_admins=false \
  --field required_pull_request_reviews=null \
  --field restrictions=null
```

| Setting | Value | Why |
|---|---|---|
| `required_status_checks.strict` | `true` | PRs must be up to date with main before merge |
| `required_pull_request_reviews` | `null` | This is an AI-agent project; the gate is CI, not human review |
| `enforce_admins` | `false` | Allows emergency hotfix via admin override with full audit trail |
| Direct push to `main` | blocked | All changes via PR |

### Step 6 — Create `docs/security/CVE_EXCEPTIONS.md`

A short policy file with the exception template. The CI failing on a HIGH CVE
needs an escape hatch for cases where the vendor patch is unreleased; this
file is where exceptions are recorded with an expiry date.

```markdown
# CVE Exceptions

CVEs that fail CI can be temporarily accepted by adding an entry below. Each
entry must have an expiry date no more than 90 days in the future. Expired
entries are removed and the CVE re-blocks CI until upgraded.

CVE triage SLA:
- HIGH / CRITICAL: addressed (upgrade or accepted exception) within 7 days
- MEDIUM: addressed within 30 days

## Template

## CVE-YYYY-NNNNN
- **Severity**: HIGH
- **Component**: <package name and version>
- **Accepted by**: <name>
- **Date accepted**: YYYY-MM-DD
- **Expiry**: YYYY-MM-DD (max 90 days)
- **Rationale**: <why this is acceptable and what mitigates the risk>
```

### Step 7 — Permission minimisation

Every workflow file gets a top-level `permissions:` block that grants only
what that workflow needs. Default `GITHUB_TOKEN` permissions are too broad.

| Workflow | Required permissions | Why |
|---|---|---|
| `ci.yml` | `contents: read` | Only checks out source |
| security jobs in `ci.yml` (or split file) | `contents: read`, `security-events: write` | SARIF upload to Security tab |
| `ja4proxy-policy.yml` | `contents: read` | Already minimal — verify only |

Image-build workflows (`build.yml`, `release-cli.yml`, the new
`go-proxy-image.yml`) need `packages: write` and `id-token: write` — those
live in Phase 202.

---

## Out of scope (call these out explicitly to junior contributors)

- **Container image build / SBOM / cosign / SLSA** — Phase 202
- **Default credential removal from compose files** — Phase 202
- **`Dockerfile.go-proxy` USER directive** — already done (line 51:
  `USER ja4proxy`)
- **The `.github/workflows/release-cli.yml` workflow** — already exists,
  already SHA-pinned, already does cosign + SLSA for the CLI image. Do not
  touch it.
- **SBOM generation** — Phase 202 owns the proxy image SBOM. CLI SBOM is
  already generated by `release-cli.yml`. There is no Python SBOM phase
  scheduled because the Python proxy is deprecated.
- **Licence inventory** — out of scope for 61. If a procurement question
  needs it, add a `make licence-check` target in a follow-up; do not block
  this phase on it.

---

## Acceptance criteria

- [ ] `.github/workflows/ci.yml` exists with `test-go`, `test-python`, and `lint` jobs
- [ ] All three jobs pass on a PR against current `main`
- [ ] `.github/workflows/ja4proxy-policy.yml` has all actions SHA-pinned (no `@v4` / `@v5` left)
- [ ] `secrets-scan`, `sast`, `dependency-audit-python`, `dependency-audit-go`, `dependency-review` jobs exist (in `ci.yml` or a split `security.yml`)
- [ ] Weekly cron `0 6 * * 1` is configured
- [ ] `.github/dependabot.yml` exists and covers `github-actions`, `pip`, `gomod`
- [ ] `scripts/branch_protection.sh` exists and is executable
- [ ] `docs/security/CVE_EXCEPTIONS.md` exists with the template
- [ ] Every workflow file has a top-level `permissions:` block scoped to the minimum
- [ ] `make ci-local` (new target) runs `go test ./...` + `python3 -m pytest tests/ --ignore=tests/integration/test_docker_stack.py -x -q` so contributors can reproduce CI before pushing
- [ ] `CHANGELOG.md` entry written
- [ ] Branch protection rules applied via the script (manual one-shot, recorded in `PHASE_61_notes.md` with date and operator)

## Verify

```bash
gh workflow list                                    # ci, ja4proxy-policy, release-cli should be present
gh workflow run ci.yml --ref claude/phase-61-ci    # smoke-run on the working branch
grep -nE "@v[0-9]" .github/workflows/*.yml         # should return zero lines
grep -nE "@[a-f0-9]{40}" .github/workflows/*.yml | wc -l  # should be > 10
```

## Out of scope — handed to other phases

| Concern | Phase that owns it |
|---|---|
| Build & push the `ja4proxy` Go proxy image | [202](PHASE_202.md) |
| SBOM for the Go proxy image | [202](PHASE_202.md) |
| Cosign signing of the Go proxy image | [202](PHASE_202.md) |
| SLSA provenance for the Go proxy binary | [202](PHASE_202.md) |
| Remove default `:-admin` credentials from `docker/docker-compose.*.yml` | [202](PHASE_202.md) |
| `Dockerfile.go-proxy` non-root USER directive | already done |
| `release-cli.yml` cosign + SLSA + goreleaser for the CLI image | already done |

If you find yourself editing files in the right column, stop and reassign to
the correct phase.
