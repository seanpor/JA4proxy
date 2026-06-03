# Phase 133: CI Stabilization & Go Toolchain Update

> **Status:** IN_PROGRESS
> **Size:** SMALL
> **Depends on:** Phase 132
> **Owner:** Gemini CLI

## Goal

Resolve the remaining CI failures in the GitHub Actions pipeline. This includes fixing a lingering Python test, correcting Go formatting issues caused by previous automated edits, and updating the Go toolchain to address newly discovered CVEs in the standard library.

## Scope

### Components in Scope
- **Python Tests**: `tests/adversarial/`
- **Go Source Code**: Formatting (`go fmt`).
- **Build Toolchain**: Updating Go version across Dockerfiles and GitHub Actions.

---

## Implementation Plan

### Wave 1: Fix Lint & Test Failures
| ID | Task | Description | Size |
|---|---|---|---|
| **133.1** | **Archive Python Test** | Move `tests/adversarial/test_abuseipdb_fp.py` to the archive. | XS |
| **133.2** | **Go Formatting** | Run `go fmt ./...` on the entire Go codebase. | XS |

### Wave 2: Go Toolchain Update (CVE Remediation)
| ID | Task | Description | Size |
|---|---|---|---|
| **133.3** | **Resolve Go 1.26.4** | Pull `golang:1.26.4-alpine` and resolve its immutable SHA256 digest. | XS |
| **133.4** | **Update Dockerfiles** | Update `Dockerfile.cli` and `Dockerfile.go-proxy` with the new digest. | XS |
| **133.5** | **Update GitHub Actions** | Update Go version in `.github/workflows/` to 1.26.4. | S |

### Wave 3: Final Verification
| ID | Task | Description | Size |
|---|---|---|---|
| **133.6** | **Local Verification** | Run `make lint` and `make test-go` locally. | S |

---

## Acceptance Criteria

- [ ] All Python tests (including adversarial) pass without `ModuleNotFoundError`.
- [ ] `go fmt` reports no unformatted files.
- [ ] `govulncheck` reports no standard library vulnerabilities (upgraded to Go 1.26.4).
- [ ] GitHub Actions CI pipeline is 100% GREEN.
