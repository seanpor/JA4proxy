# Hermetic Tooling & make doctor Accuracy

## Goal
Ensure 100% of lint, scan, and validation tools run in pinned Docker containers, eliminating "works on my machine" issues and host-tool version skew.

## Background
Phase 225 began the containerization of host tools but left 5 linters (hadolint, gitleaks, codespell, markdownlint, amtool) relying on host installations. This creates inconsistency between developer machines and CI.

## Scope
1.  **Containerize Remaining Tools**: Add `hadolint`, `gitleaks`, `codespell`, `markdownlint`, and `amtool` to the `Dockerfile.tools` (or create dedicated lightweight images if the tools image becomes too large).
2.  **Makefile Integration**: Update `make lint-all` and `make doctor` to use the containerized versions.
3.  **CI Alignment**: Ensure the CI workflow (`.github/workflows/ci.yml`) uses the same containerized tools.
4.  **Python Linter Pinning**: Pin `ruff`, `mypy`, and `bandit` to specific versions in the tools image to prevent unexpected behavior.

## Implementation Plan
1.  **Step 1: Dockerfile.tools Update**
    *   Add installation of the 5 remaining tools.
    *   Pin Python linter versions in `pyproject.toml` and `Dockerfile.tools`.
2.  **Step 2: Makefile Refactor**
    *   Update `lint-docker`, `lint-docs-all`, and `lint-supply-chain` targets to use `$(TOOLS_RUN)`.
3.  **Step 3: make doctor**
    *   Update `make doctor` to check for the presence of the `ja4proxy-tools` image instead of individual host tools.
4.  **Step 4: CI Cleanup**
    *   Remove any `pip install` steps from the CI workflow that are now handled by the tools container.

## Acceptance Criteria
1.  `make lint-all` passes using only containerized tools (no host tool dependencies).
2.  `make doctor` reports all tools as "present" (via container).
3.  No `pip install` or `go install` for lint tools in the CI workflow.
4.  All tool versions are pinned and documented in `Dockerfile.tools`.

## Dependencies
*   Phase 225 (Hermetic Tooling) - **PARTIAL**
*   Phase 313 (CI Lint Loop) - **COMPLETE**
