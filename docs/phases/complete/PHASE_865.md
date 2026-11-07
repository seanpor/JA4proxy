# Phase 865: Migrate SAST from Semgrep to Opengrep

## Goal
Migrate the project Static Application Security Testing (SAST) pipeline from Semgrep to Opengrep (the open-source, LGPL/community fork of Semgrep CE). This resolves long-standing dependency conflicts on Python packaging toolchains, eliminates telemetry/metrics exfiltration concerns, provides standalone reproducible scans, and aligns with JA4proxy's container-strict, zero-external-network security architecture.

## Scope

1. **WP-865a: Opengrep Container Toolchain Packaging (`deploy/docker/Dockerfile.opengrep`)**
   - Create a dedicated, lightweight, non-root container image for Opengrep pinned to stable release binary `v1.33.1` (SHA-256 verified).
   - Ensure the image runs as non-root user `scanner` (UID 1001), consistent with `deploy/docker/security-scan/Dockerfile` and `Dockerfile.bandit`.
   - Configure container entrypoint and scanning flags with `--disable-version-check` and no external metrics reporting.

2. **WP-865b: Rule Vendoring & Rule Compatibility (`security/sast/`)**
   - Vendor baseline CI and security audit rule configurations locally under `security/sast/opengrep/` (or retain local `.semgrep-phase122.yml` and project-specific rule definitions), removing runtime network dependencies on external registry fetches (`p/ci`, `p/security-audit`, `p/secrets`).
   - Verify pattern compatibility across Go 1.26 (`cmd/ja4pd`, `internal/`) and Python 3.15 (`src/`, `management/`, `scripts/`).
   - Validate comment inline suppression compatibility (`# nosemgrep` and `# nosec`).

3. **WP-865c: Makefile & Developer Workflow Alignment**
   - Introduce `OPENGREP_IMG := ja4proxy-opengrep:1.33.1` with build-on-demand target `docker-build-opengrep`.
   - Update `lint-sast` to depend on `lint-opengrep` and `lint-checkov`.
   - Update `lint-semgrep` target to alias/redirect to `lint-opengrep` (or deprecate cleanly while maintaining backward compatibility in `meta_lint.py`).
   - Update `scripts/close-phase.sh` step `[7/10]` to execute `make lint-opengrep`.
   - Update `scripts/meta_lint.py` if target references need alignment.

4. **WP-865d: CI/CD Pipeline & Dependency Cleanup**
   - Update `.github/workflows/ci.yml`:
     - Replace the `sast` job's `pip install semgrep==1.76.0` step with containerized or native Opengrep binary scan (`v1.33.1`).
     - Remove obsolete Python 3.15 pip constraints on Semgrep.
   - Clean up `.github/dependabot.yml` and `scripts/fix_forward.py`:
     - Remove Semgrep resolution workarounds (e.g., `mcp` and `jsonschema` pinning logic that existed solely because Semgrep pinned legacy versions).

5. **WP-865e: Documentation & Manifest Synchronization**
   - Document the SAST migration in `docs/security/SAST.md` or `docs/reference/SECURITY_SCANNING.md`.
   - Update `docs/phases/manifest.yaml` marking Phase 865 `IN_PROGRESS` -> `COMPLETE`.
   - Generate news fragment `docs/fragments/phase-865-migrate-sast-to-opengrep.md`.

## Implementation Plan

### Step 1: Container Specification
Create `deploy/docker/Dockerfile.opengrep`:
- Base: `alpine:3.24` (or `python:3.15.2-alpine3.24` / `debian:bookworm-slim`).
- Download and verify Opengrep `v1.33.1` standalone binary:
  `https://github.com/opengrep/opengrep/releases/download/v1.33.1/opengrep_manylinux_x86` (or `opengrep_musllinux_x86` for alpine).
- Add user `scanner:1001`.
- Set workdir to `/src`.

### Step 2: Local Rule Vendoring
- Bundle the rules currently fetched via `p/ci`, `p/security-audit`, `p/secrets` into `security/sast/rules/` so CI and local runs require zero network access.
- Validate `.semgrep-phase122.yml` runs identically under Opengrep with zero errors.

### Step 3: Makefile & Gate Integration
- Add target:
  ```makefile
  lint-opengrep: ## Run Opengrep SAST using local rulesets (containerised)
  	@echo "=== opengrep: SAST (pinned binary v1.33.1 in container) ==="
  	@docker run --rm -v $(PWD):/src -w /src $(OPENGREP_IMG) \
  		opengrep scan --quiet --error --disable-version-check --config .semgrep-phase122.yml --config security/sast/rules/ .
  ```
- Keep `lint-semgrep: lint-opengrep` as backward-compatible alias.
- Update `scripts/close-phase.sh` to call `make lint-opengrep`.

### Step 4: Verification & Preflight
- Run `make lint-opengrep`.
- Run `make preflight` (`make lint`, `make scan`, `make test`).
- Ensure all CI gates and security scans remain 100% green.

## Test Strategy
1. **Rule Parity Test:** Verify that Opengrep catches existing test patterns (e.g., eager f-string logging, untrusted XFF, and known test vulnerabilities) identically to Semgrep.
2. **False Positive & Suppression Test:** Verify that existing `# nosemgrep` inline suppressions in `scripts/` continue to function without false alarms.
3. **Hermeticity / Offline Test:** Disconnect network simulation or scan with network disabled to confirm zero outbound network requests.
4. **AST Parser Verification:** Ensure zero AST parse crashes across Go 1.26 and Python 3.15 trees.

## Acceptance Criteria
- [ ] `deploy/docker/Dockerfile.opengrep` builds reproducibly with pinned binary `v1.33.1`.
- [ ] `make lint-opengrep` passes cleanly across the entire repository.
- [ ] Semgrep is completely removed from `.github/workflows/ci.yml` and dependencies.
- [ ] `make preflight` and `bash scripts/close-phase.sh` exit 0.
- [ ] No outbound network calls made during SAST scan (`--disable-version-check` and vendored rules).
- [ ] PR created, passes all CI checks, and merges cleanly to `main`.

## Out of Scope
- Rewriting or modifying custom SAST detection logic outside of syntax compatibility adjustments.
- Modifying Bandit or Checkov configurations (they remain separate SAST linters).
