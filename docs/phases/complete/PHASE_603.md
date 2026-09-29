# Hermetic Tooling & make doctor Accuracy

## Goal
Ensure 100% of lint, scan, and validation tools run in pinned Docker containers, eliminate permission errors and tooling turmoil, make `make doctor` provide an accurate assessment of environment health, and remove redundant host dependency installation in CI.

## Scope
1. **Makefile SHELL_SCRIPTS Optimization**:
   Prune `.git`, `.local`, `node_modules`, and `.claude` directories in `SHELL_SCRIPTS` find command to avoid scanning container-generated root caches (`.local/trivy-cache/fanal`) which caused `Permission denied` noise on every `make` invocation.
2. **Containerize Dependency CVE Auditing**:
   Update `lint-deps` to execute `pip-audit` inside `$(TOOLS_RUN)` (`ja4proxy-tools`), eliminating host Python package requirements for running `make lint-deps` or `make lint-supply-chain`.
3. **Accurate Environment Health (`make doctor`)**:
   - Check host prerequisites: `docker` executable, Docker daemon connectivity (`docker info`), Go 1.26+, and Python 3.
   - Accurately report containerized toolchain status (pinned containers: `ja4proxy-tools`, `ja4proxy-bandit`, official pinned images like `aquasec/trivy`, `hadolint/hadolint`, `koalaman/shellcheck`, `semgrep/semgrep`, `zricethezav/gitleaks`, `prom/prometheus`, `prom/alertmanager`, `golangci/golangci-lint`, etc.).
   - Stop checking obsolete host binaries (`hadolint`, `trivy`, `semgrep`, `promtool`, `amtool`, `gitleaks`) that are fully containerized.
   - Check presence of `.env` configuration file.
4. **CI Workflow Alignment**:
   Remove unnecessary host `pip install ruff mypy bandit pytest-cov pip-audit` from `.github/workflows/ci.yml` `lint` job since all lint and security targets execute hermetically in pinned Docker containers.

## Implementation Plan
1. **Makefile updates**:
   - Update `SHELL_SCRIPTS` definition using `-prune`.
   - Update `lint-deps` to run `pip-audit` via `$(TOOLS_RUN)`.
   - Ensure `GOROOT` and `GO` detection are robust across snap and host environments.
   - Refactor `doctor` target to verify Docker daemon responsiveness and accurately reflect containerized architecture.
2. **CI updates**:
   - Update `.github/workflows/ci.yml` to remove redundant host `pip install` step in the `lint` job.
3. **Verification**:
   - Run `make doctor` and verify zero permission errors and accurate output.
   - Run `make lint` and `make lint-deps` to verify all linters pass in container.
   - Run `make lint-meta` and `make lint-phases`.

## Acceptance Criteria
1. `make doctor` passes cleanly without permission errors and accurately describes host prerequisites and containerized tooling.
2. `SHELL_SCRIPTS` does not emit `Permission denied` on `.local/trivy-cache/fanal`.
3. `make lint-deps` runs containerized via `$(TOOLS_RUN)` and succeeds with 0 vulnerabilities.
4. Redundant host `pip install` removed from CI `lint` job.
5. All meta-lint and phase-lint checks pass.

## Dependencies
* Phase 225 (Hermetic Tooling) - COMPLETE
* Phase 313 (CI Lint Loop) - COMPLETE
