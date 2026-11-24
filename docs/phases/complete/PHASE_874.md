<!--
title: "Local Preflight & CI Gate Parity Hardening"
audience: developers
last_reviewed: 2026-11-22
phase: 874
-->

# Local Preflight & CI Gate Parity Hardening

## Goal
Eliminate the three local-vs-CI gate parity gaps exposed by PR #736 so that any check capable of failing a PR in GitHub Actions (`Scan Regression`, `Go dependency audit / govulncheck`, and `CodeQL` URL-substring sanitization) fails fast locally inside `make preflight` before push.

## Scope
1. **Scan Regression in `make preflight`:** Wire `make scan-regression` into `make preflight` so `MEDIUM`+ unwaived findings on touched surfaces (against `security/baseline.json`) block locally before push.
2. **Go Toolchain Alignment & Local `govulncheck` Parity:**
   - Extend `scripts/check_toolchain_alignment.py` to verify that all Go builder Dockerfiles (`deploy/docker/Dockerfile*`), `deploy/docker/security-scan/Dockerfile`, and `.github/workflows/ci.yml` (`go-version`) pin the exact same Go minor/patch version (preventing silent `go1.27.3` vs `go1.27.4` drift).
   - Align `deploy/docker/security-scan/Dockerfile` (and any lagging workflow `go-version` pins in `fuzzing.yml`, `nightly-benchmark.yml`, `journeys.yml`) to `1.27.4` and ensure `make lint-go-vuln` / `make preflight` executes `govulncheck ./...` with that aligned Go version.
3. **Local Opengrep Parity for CodeQL URL-Substring Sanitization:**
   - Add a custom Opengrep rule in `security/sast/custom-rules/python-url-substring-sanitization.yaml` flagging `.startswith("<host>/")` / `"<host>/" in ...` checks (matching CodeQL's `py/incomplete-url-substring-sanitization`) so `make lint-opengrep` catches them locally.

## Implementation Plan
1. **Custom Opengrep Rule (`security/sast/custom-rules/python-url-substring-sanitization.yaml`):**
   - Author a targeted Python rule matching `.startswith("<domain.tld>/")` and `"<domain.tld>/" in <var>` expressions with clear remediation guidance (`urllib.parse.urlparse` or explicit host splitting).
   - Verify zero false positives on the current codebase via `make lint-opengrep`.
2. **Toolchain Alignment Check (`scripts/check_toolchain_alignment.py`):**
   - Add checks comparing Go versions across:
     - `.github/workflows/ci.yml` (`go-version: "X.Y.Z"`)
     - `deploy/docker/security-scan/Dockerfile` (`FROM golang:X.Y.Z-alpine`)
     - `deploy/docker/Dockerfile*` (`FROM golang:X.Y.Z-alpine`)
   - Bump `deploy/docker/security-scan/Dockerfile` (and `fuzzing.yml`, `nightly-benchmark.yml`, `journeys.yml`) from `1.26.10` / `1.27.3` to `1.27.4` (digest resolved via `make update-docker`).
3. **Preflight Gate Parity (`Makefile`):**
   - Add `make scan-regression` to `preflight` (updating step count `[1/5]`..`[5/5]`).
   - Add `lint-go-vuln` (running `govulncheck ./...` inside `ja4proxy-security-scan` built from the aligned `golang:1.27.4-alpine` Dockerfile) and wire it into `lint-go` / `preflight`.
   - Run `make sync` to regenerate `docs/reference/MAKEFILE_TARGETS.md` and `docs/reference/DOCKER_IMAGES.md`.
4. **Manifest Registration (`docs/phases/manifest.yaml`):**
   - Register Phase `874` (`size: SMALL`, `dependencies: [873]`).

## Test Strategy (TDD)
- **Unit tests (`tests/unit/test_check_toolchain_alignment.py`):**
  - Assert aligned versions across `ci.yml`, `security-scan/Dockerfile`, and builder Dockerfiles pass.
  - Assert any single-file version drift (`ci.yml` vs builder Dockerfile, or `security-scan/Dockerfile` vs `ci.yml`) fails with a clear diagnostic message.
- **SAST rule test (`tests/unit/test_opengrep_url_sanitization_rule.py` or Opengrep test fixture):**
  - Positive case: `image.startswith("gcr.io/")` triggers the new Opengrep rule.
  - Negative case: `registry == "gcr.io"` after `partition("/")` passes cleanly.
- **End-to-end verification:**
  - `make lint-opengrep` exits 0.
  - `make lint-go-vuln` (`govulncheck ./...`) exits 0.
  - `make scan-regression` exits 0.
  - `make preflight` exits 0 end-to-end.

## Acceptance Criteria
- `make preflight` executes `scan-regression` and `govulncheck` (at the exact Go version pinned in `ci.yml`).
- `scripts/check_toolchain_alignment.py` fails immediately if `ci.yml`, `deploy/docker/security-scan/Dockerfile`, and Go builder Dockerfiles drift out of sync.
- `make lint-opengrep` flags `x.startswith("gcr.io/")` locally and passes cleanly on the repo.
- All unit tests, `make lint-phases`, and `make preflight` exit 0.

## Out of Scope
- Running GitHub's proprietary CodeQL engine locally (Opengrep covers the high-signal rule parity without requiring CodeQL CLI/licensing).
- Remediating third-party monitoring image CVEs (`#727`–`#729`, `#733`–`#735`).
