# Phase 61: Supply Chain Security & Build Integrity

---

## 1. Overview

The project has no CI pipeline. All testing is run locally via `make test`. Before the
enterprise sales motion (phases 79–86), a repeatable, automated pipeline must exist that
runs on every pull request and push to `main` — one that a procurement team can inspect
and verify. This phase delivers that pipeline as four GitHub Actions workflows covering
core tests, security scanning, artifact building, and release management.

This phase also delivers SBOM generation, container image signing, and build provenance
— the three artifacts that enterprise security teams require before approving deployment.
None of these exist today. Without them, any procurement questionnaire asking "how do you
ensure the software we deploy has not been tampered with?" cannot be answered.

This phase does NOT re-do: linting/mypy (Phase 37, complete), Docker image CVE scanning
(Phase 25, complete), or performance benchmarking (Phases 26–30, complete).

---

## 2. GitHub Actions CI Pipeline

### 2.1 Directory Structure

```
.github/
  workflows/
    ci.yml           # Run on every PR and push to main
    security.yml     # Security scanning — run on every PR and push to main
    build.yml        # Build and sign artifacts — run on push to main and tags
    release.yml      # Create releases with signed artifacts and SBOM
```

### 2.2 `ci.yml` — Core Test Pipeline

Triggered: `on: [pull_request, push]` to any branch.

Jobs (run in parallel where possible):

1. `test-python`: `python3 -m pytest tests/ --ignore=tests/integration/test_docker_stack.py -x -q --timeout=60`
2. `test-go`: `go test ./...` (with `GOFLAGS: "-count=1"`)
3. `lint-python`: `ruff check . && mypy src/ proxy.py --ignore-missing-imports`
4. `lint-go`: `gofmt -l . && go vet ./...`

```yaml
# .github/workflows/ci.yml
name: CI
on:
  pull_request:
  push:
    branches: [main]

jobs:
  test-python:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -r requirements.txt
      - run: python3 -m pytest tests/ --ignore=tests/integration/test_docker_stack.py -x -q --timeout=60

  test-go:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.22"
      - run: go test ./...
        env:
          GOFLAGS: "-count=1"

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install ruff mypy
      - run: ruff check . && mypy src/ proxy.py --ignore-missing-imports
      - uses: actions/setup-go@v5
        with:
          go-version: "1.22"
      - run: test -z "$(gofmt -l .)" && go vet ./...
```

Both `test-python` and `test-go` are required status checks — PRs cannot be merged if
either fails. `lint` is also a required status check.

The Docker integration test (`tests/integration/test_docker_stack.py`) is excluded from
CI because it requires a live backend on port 8443. It continues to run locally via
`make test-integration`.

### 2.3 `security.yml` — Security Scanning

Triggered: `on: [pull_request, push]` to main, and on a weekly Monday cron for
newly-disclosed CVEs.

Jobs:

1. **`secrets-scan`**: TruffleHog scans the full commit history for accidentally
   committed secrets and API keys. Fails the PR immediately if any verified secrets are
   found. Uses `fetch-depth: 0` to scan the entire history on PRs.

2. **`sast`**: Semgrep with `p/python`, `p/golang`, and `p/secrets` rulesets. Fails CI
   on HIGH severity findings. MEDIUM findings are reported but do not block merge.

3. **`dependency-audit-python`**: `pip-audit` against `requirements.txt`. Fails CI on
   HIGH or CRITICAL CVEs.

4. **`dependency-audit-go`**: `govulncheck ./...`. Fails CI on any known-vulnerable Go
   module dependencies.

```yaml
# .github/workflows/security.yml
name: Security Scanning
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "0 6 * * 1"   # Weekly Monday scan for newly-disclosed CVEs

jobs:
  secrets-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          extra_args: --only-verified

  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: returntocorp/semgrep-action@v1
        with:
          config: "p/python p/golang p/secrets"

  dependency-audit-python:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install pip-audit && pip-audit -r requirements.txt --severity high

  dependency-audit-go:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.22"
      - run: go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...
```

**CVE triage policy:** HIGH and CRITICAL CVEs must be addressed within 7 days of
discovery — by upgrading the dependency, applying a patch, or filing a documented risk
acceptance in `docs/security/CVE_EXCEPTIONS.md`. MEDIUM CVEs must be addressed within
30 days. The `CVE_EXCEPTIONS.md` format is:

```markdown
## CVE-YYYY-NNNNN
- **Severity**: HIGH
- **Component**: <package name and version>
- **Accepted by**: <name>
- **Date accepted**: YYYY-MM-DD
- **Expiry**: YYYY-MM-DD (max 90 days)
- **Rationale**: <why this is acceptable and what mitigates the risk>
```

### 2.4 `build.yml` — Build and Sign Artifacts

Triggered: `on: push` to `main` and on version tags (`v*`).

Jobs:

1. Build the Go proxy binary for `linux/amd64` and `linux/arm64`.
2. Build Docker images for `proxy`, `analytics`, and `tarpit` containers.
3. Push images to `ghcr.io`.
4. Sign each image with Cosign keyless signing (see Section 4).
5. Generate SBOMs and attach them as image attestations (see Section 3).

### 2.5 `release.yml` — Release Artifacts

Triggered: `on: push` to version tags (`v*`).

Creates a GitHub release with:
- Go binary for `linux/amd64` and `linux/arm64` (compressed with `tar.gz`)
- `sbom-python.json` (CycloneDX 1.4)
- `sbom-go.json` (CycloneDX 1.4)
- `sbom-container.json` (CycloneDX 1.4, from Syft)
- `licence-inventory-python.json`
- `licence-inventory-go.csv`
- SLSA provenance attestation (`.intoto.jsonl`) for the Go binary

---

## 3. SBOM Generation

A Software Bill of Materials (SBOM) lists every dependency, its version, and its
licence. Enterprise security teams require an SBOM at procurement. Without one, the
question "what open-source components are in this product?" cannot be answered
systematically.

### 3.1 Python SBOM

Generate a CycloneDX 1.4 SBOM from `requirements.txt`:

```bash
pip install cyclonedx-bom
cyclonedx-py requirements requirements.txt \
  --output sbom-python.json \
  --format json \
  --schema-version 1.4
```

Generated in `build.yml` and `release.yml`. Attached to GitHub releases as
`sbom-python.json`.

### 3.2 Go SBOM

Generate a CycloneDX 1.4 SBOM from the Go module graph:

```bash
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
cyclonedx-gomod app -main cmd/proxy/ -output sbom-go.json -json
```

Generated in `build.yml` and `release.yml`. Attached to GitHub releases as
`sbom-go.json`.

### 3.3 Container SBOM

For each Docker image built in CI, generate a Syft SBOM and attach it as an OCI image
attestation. This means the SBOM travels with the image and can be retrieved by any
consumer with `cosign download attestation`:

```yaml
# In build.yml — after docker build and push
- uses: anchore/sbom-action@v0
  with:
    image: ghcr.io/org/ja4proxy:${{ github.sha }}
    artifact-name: sbom-container.json
    output-file: sbom-container.json
    format: cyclonedx-json
```

The `sbom-container.json` is also attached to GitHub releases.

### 3.4 Licence Compliance

Generate a licence inventory for all dependencies before each release. Flag any
GPL-2.0, GPL-3.0, AGPL-3.0, or SSPL licences — these can conflict with commercial
distribution.

```bash
# Python
pip install pip-licenses
pip-licenses --format=json --output-file=licence-inventory-python.json

# Go
go install github.com/google/go-licenses@latest
go-licenses report ./cmd/proxy/ --template=csv > licence-inventory-go.csv
```

Any flagged licence must be documented in `docs/security/LICENCE_EXCEPTIONS.md` with
a legal justification before the release is published. The format is:

```markdown
## <package name> — <licence>
- **Version**: <version>
- **Used by**: Python proxy / Go proxy / both
- **Legal review**: <name, date>
- **Justification**: <why this licence is acceptable for this use case>
```

---

## 4. Container Image Signing

All proxy Docker images built in CI are signed using **Cosign** with keyless signing via
Sigstore. Keyless signing means no long-lived private key is stored as a GitHub secret —
instead, the GitHub Actions OIDC token is used at signing time to obtain a short-lived
certificate from Fulcio, and the signature is recorded in the Rekor transparency log.

This provides a verifiable chain: the image digest was signed by a certificate issued to
the GitHub Actions workflow running at a specific commit on the `main` branch of this
repository.

```yaml
# In build.yml — after docker build and push to ghcr.io
- name: Install Cosign
  uses: sigstore/cosign-installer@v3

- name: Sign proxy image
  run: |
    cosign sign --yes \
      ghcr.io/org/ja4proxy@${{ steps.push.outputs.digest }}
  env:
    COSIGN_EXPERIMENTAL: 1

- name: Sign analytics image
  run: |
    cosign sign --yes \
      ghcr.io/org/ja4proxy-analytics@${{ steps.push-analytics.outputs.digest }}
  env:
    COSIGN_EXPERIMENTAL: 1
```

**Operator verification command** (documented in `docs/operator/TROUBLESHOOTING.md` and
the RHEL deployment guide from Phase 76):

```bash
cosign verify ghcr.io/org/ja4proxy:latest \
  --certificate-identity-regexp "https://github.com/org/ja4proxy/.github/workflows/build.yml" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

If verification fails, the image has either not been built by CI or has been tampered
with after push. Operators must not deploy an image that fails this check.

The signing step runs unconditionally on every push to `main` and on every release tag.
Development branch builds are not signed — only `main` and tags.

---

## 5. SLSA Build Provenance

Generate SLSA level 2 build provenance for the Go binary. SLSA level 2 means: the build
runs on a hosted, non-modifiable CI environment (GitHub Actions), and a signed
provenance attestation is generated and uploaded alongside the artifact. The provenance
records: the source commit, the build command, the environment, and the output digest.

```yaml
# In release.yml — triggered on version tags
jobs:
  build-provenance:
    uses: slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@v1.9.0
    permissions:
      id-token: write
      contents: write
      actions: read
    with:
      go-version: "1.22"
      config-file: .slsa-goreleaser.yml
```

The `.slsa-goreleaser.yml` configuration specifies the binary name, target platform
(`linux/amd64`, `linux/arm64`), and output path.

The provenance attestation (`.intoto.jsonl`) is attached to the GitHub release alongside
the binary. Consumers verify with:

```bash
slsa-verifier verify-artifact ja4proxy-linux-amd64.tar.gz \
  --provenance-path ja4proxy-linux-amd64.tar.gz.intoto.jsonl \
  --source-uri github.com/org/ja4proxy \
  --source-tag v1.0.0
```

SLSA provenance is generated for the Go binary only. The Python proxy runs directly from
source and does not have a compiled artifact to attest. Container image provenance is
covered by Cosign signing (Section 4).

---

## 6. Makefile Targets

Add to the bottom of `Makefile` (never edit existing targets):

```makefile
## Phase 61 targets
sbom:
	pip install cyclonedx-bom
	cyclonedx-py requirements requirements.txt --output sbom-python.json --format json --schema-version 1.4
	go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
	cyclonedx-gomod app -main cmd/proxy/ -output sbom-go.json -json
	@echo "SBOMs written: sbom-python.json, sbom-go.json"

licence-check:
	pip install pip-licenses
	pip-licenses --format=json --output-file=licence-inventory-python.json
	@echo "Python licence inventory: licence-inventory-python.json"
	go install github.com/google/go-licenses@latest
	go-licenses report ./cmd/proxy/ --template=csv > licence-inventory-go.csv
	@echo "Go licence inventory: licence-inventory-go.csv"
	@echo "Review both files for GPL/AGPL/SSPL before distribution."

dependency-audit:
	pip install pip-audit
	pip-audit -r requirements.txt --severity high
	go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...
```

---

## 7. Acceptance Criteria

- [ ] `.github/workflows/ci.yml` exists and runs Python tests and Go tests on every PR; both jobs are required status checks before merge
- [ ] `.github/workflows/security.yml` exists and runs TruffleHog, Semgrep, pip-audit, and govulncheck on every PR
- [ ] Weekly scheduled scan is configured in `security.yml` (`cron: "0 6 * * 1"`)
- [ ] `pip-audit` and `govulncheck` fail CI on HIGH/CRITICAL CVEs; no current HIGH/CRITICAL findings are unfixed at phase completion
- [ ] CVE triage policy and exception format are documented in `docs/security/CVE_EXCEPTIONS.md`
- [ ] Python SBOM (`sbom-python.json`, CycloneDX 1.4) is generated in `build.yml` and attached to GitHub releases
- [ ] Go SBOM (`sbom-go.json`, CycloneDX 1.4) is generated in `build.yml` and attached to GitHub releases
- [ ] Container SBOM is generated via Syft (`anchore/sbom-action`) and attached as an OCI image attestation for each built image
- [ ] Licence inventory is generated for Python and Go; any GPL/AGPL/SSPL dependency is documented in `docs/security/LICENCE_EXCEPTIONS.md` with justification
- [ ] All proxy Docker images built from `main` and release tags are signed with Cosign keyless signing
- [ ] Cosign verification command is documented in `docs/operator/TROUBLESHOOTING.md` and the Phase 76 RHEL deployment guide
- [ ] SLSA level 2 provenance attestation (`.intoto.jsonl`) is generated for Go binary releases and attached to GitHub releases
- [ ] `make sbom`, `make licence-check`, and `make dependency-audit` targets are added to the bottom of `Makefile`
- [ ] `README.md` updated to note that images are Cosign-signed and how to verify them
