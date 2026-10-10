# Retrospective Closure Sweep & Toolchain Alignment Gate

## Goal
1. **Retrospective Closure Sweep**: Re-verify historical security findings in `docs/security/findings.yaml` using proof-on-revert testing (`scripts/verify_revert.sh`) to ensure regression tests fail when fixes are removed, promoting valid findings from `FIXED` to `VERIFIED`.
2. **Automated Toolchain Alignment Gate**: Eliminate manual toolchain version drift (e.g. `go.mod` vs. `golangci-lint` vs. Docker base images) by adding automated alignment checks and fixing `scripts/check_updates.py`.

---

## Scope & Workstreams

### Workstream A: Historical Finding Retrospective Sweep
* **Revert Proof Testing**: Execute `scripts/verify_revert.sh` over all **14 CRITICAL**, all **20 HIGH**, and a representative sample of MEDIUM/LOW findings in `docs/security/findings.yaml`.
* **State Verification**: For each finding, verify that the recorded regression test **fails on the pre-fix parent commit** and **passes on `main`**.
* **Status Promotion**: Promote validated findings from `FIXED` to `VERIFIED` via `python3 scripts/findings_register.py promote-verified`.
* **Decoration Remediation**: If a test passes on both pre-fix and `main` (a "decoration"), log a new finding against the test suite to fix it.

### Workstream B: Toolchain Alignment Gate & Update Checker Fixes
* **Toolchain Alignment Gate (`scripts/check_toolchain_alignment.py`)**:
  * Automatically cross-checks `go.mod` (`go 1.26.6`), Docker base images (`golang:1.27.2-alpine`), Makefile variables, and `golangci-lint` capabilities.
  * Wires `make check-toolchain` into `make lint-meta` so any out-of-sync edit to `go.mod` or Dockerfiles immediately fails `make lint` with clear diagnostic instructions.
* **Update Checker Repair (`scripts/check_updates.py`)**:
  * Fix the `GO_MODULES` path list in `scripts/check_updates.py` to target `REPO_ROOT` (root `go.mod`).
  * Add automated checking for compiler directives (`go.mod` version, `golangci-lint` release tags, Python runtime base images) against upstream releases.

---

## Implementation Plan

### Step 1: Claim Lease & Update Manifest
- Set Phase 814c status to `IN_PROGRESS` in `docs/phases/manifest.yaml`.

### Step 2: Implement Toolchain Alignment Script & Repair `check_updates.py`
- Create `scripts/check_toolchain_alignment.py` to check `go.mod` vs `golangci-lint` version compatibility.
- Wire `make check-toolchain` target into `Makefile` under `lint-meta`.
- Update `scripts/check_updates.py` `GO_MODULES` list to include `REPO_ROOT` (root `go.mod`) and add compiler directive checks.
- Add unit tests in `tests/unit/test_check_toolchain.py`.

### Step 3: Execute Retrospective Closure Sweep
- Run `scripts/verify_revert.sh` against the 14 CRITICAL and 20 HIGH findings.
- Run `python3 scripts/findings_register.py promote-verified` for verified findings.
- Document two-state proof logs for all swept findings.

### Step 4: Verification & Close-Out
- Run `make preflight` to confirm zero lint, scan, or test regressions.
- Update `docs/phases/manifest.yaml` status to `COMPLETE`.
- Move `docs/phases/PHASE_814c.md` to `docs/phases/complete/PHASE_814c.md`.
- Create news fragment `docs/fragments/phase-814c-retrospective-closure.md`.

---

## Acceptance Criteria
- [ ] All 14 CRITICAL and 20 HIGH findings evaluated with `verify_revert.sh` and validated findings promoted to `VERIFIED`.
- [ ] `scripts/check_toolchain_alignment.py` created and integrated into `make lint-meta` (`make lint`).
- [ ] `scripts/check_updates.py` updated to include root `go.mod` and toolchain compiler directives.
- [ ] Unit tests added in `tests/unit/test_check_toolchain.py` (100% passing).
- [ ] `docs/phases/PHASE_814c.md` moved to `docs/phases/complete/PHASE_814c.md` and `manifest.yaml` updated to `COMPLETE`.
- [ ] `make preflight` and `make lint-phases` pass cleanly with 0 errors.

---

## Out of Scope
- Stage 1 new vulnerability hunting (Phase 814d+).
- Modifying historical finding CVSS vector scores.
