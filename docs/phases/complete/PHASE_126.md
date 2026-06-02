# Phase 126: Toolchain Modernization & Update Automation

> **Status:** IN_PROGRESS
> **Size:** MEDIUM
> **Depends on:** Phase 123 (Containerized Scans)
> **Owner:** Gemini CLI

## Goal

Modernize the security scanning toolchain and establish a proactive update-checking framework. This phase addresses the outdated Trivy versions identified in Phase 123 and implements `make check-updates` to monitor for available updates across Docker images, Go modules, and Python packages.

## Scope

### Components in Scope
- **Makefile**: Security scan targets and new update-checking orchestration.
- **Scanning Tools**: Trivy (upgrade from 0.69.3 to 0.70.0).
- **Automation Scripts**: `scripts/check_updates.py` and supporting utilities.
- **Dependency Tracking**: `go.mod`, `requirements.txt`, and Dockerfiles.

### Out of Scope
- Fixing underlying vulnerabilities found by the scans (covered by subsequent remediation phases).
- Implementing automated "auto-patching" (this phase focuses on *detection*).

---

## Implementation Plan

### Wave 1: Toolchain Modernization
*Focus: Upgrading existing security tools.*

| ID | Task | Size |
|---|---|---|
| 126.1 | **Upgrade Trivy** | Update all Makefile references from `aquasec/trivy:0.69.3` to `0.70.0`. | XS |
| 126.2 | **Scanner Health Check** | Verify `make scan-all` executes successfully with the new Trivy version. | S |

### Wave 2: Update Infrastructure
*Focus: Building the 'make check-updates' framework.*

| ID | Task | Size |
|---|---|---|
| 126.3 | **Update Script Refactor** | Review and enhance `scripts/check_updates.py` to support modern Go/Docker/Python ecosystems. | M |
| 126.4 | **Go Update Check** | Add `go list -m -u all` integration to detect available module updates. | S |
| 126.5 | **Python Update Check** | Add `pip list --outdated` integration for Python dependencies. | S |
| 126.6 | **Docker Update Check** | Implement Docker Hub API check for newer base image tags. | M |

### Wave 3: Integration & Reporting
*Focus: Finalizing the developer experience.*

| ID | Task | Size |
|---|---|---|
| 126.7 | **Makefile Integration** | Connect all components to the `make check-updates` target. | S |
| 126.8 | **Status Dashboard** | Create a summary report format for `check-updates` results. | S |

---

## Test Strategy

### Validation
- **Scanner Verification**: Run `make scan-images` and ensure it pulls/uses Trivy 0.70.0.
- **Update Detection**: Manually "downgrade" a minor Go dependency and verify `make check-updates` flags it.
- **Container Isolation**: Ensure the update script doesn't require local tool installation where possible (use containers).

---

## Acceptance Criteria

- [ ] All Makefile references use Trivy v0.70.0.
- [ ] `make check-updates` provides a comprehensive list of available updates for:
    - [ ] Go modules
    - [ ] Python packages
    - [ ] Docker base images
- [ ] `make check-updates` handles network failures gracefully (e.g., timeout instead of hang).
- [ ] Documentation updated to reflect the new update-checking workflow.

---

## Reference Material
- [Trivy Release Notes (v0.70.0)](https://github.com/aquasecurity/trivy/releases/tag/v0.70.0)
- [Go Module Update Guide](https://go.dev/ref/mod#glos-module-update)
