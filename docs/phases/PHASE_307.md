---
phase: 307
title: Documentation Coherence, Setup Standardization, and Link Remediation
status: COMPLETE
size: SMALL
created: 2026-06-09
completed: 2026-06-10
audience: [developer]
---

# Documentation Coherence, Setup Standardization, and Link Remediation

## Goal

The goal of this phase is to structure the project's documentation into a credible, coherent, and easily maintainable system. It resolves three major issues: (1) internal inconsistencies and gaps, such as the setup wizard (`make init`) not being recommended as the primary onboarding entry point in the READMEs; (2) outdated references to the now-removed Python proxy prototype (`proxy.py`); and (3) broken internal links caused by past file consolidations (like the deleted `MONITORING_SETUP.md` and renamed `OPERATIONS.md`). 

To make this plan easy to execute for a junior engineer who just joined the team, the exact steps, file changes, and validation checks are spelled out in detail below.

---

## The Coherent Documentation Architecture

To ensure the documentation system remains up-to-date and avoids future drift, we establish a strict **no-duplication** architecture with clear single sources of truth (SSoT):

1. **Root [README.md](file:///home/sean/LLM/JA4proxy3/README.md)**: The entry point for the repository. It introduces the project, security posture, and routes users to role-specific files. It provides a simple "Quick Verification" block and points to `make init` for interactive setup.
2. **[docs/GETTING_STARTED.md](file:///home/sean/LLM/JA4proxy3/docs/GETTING_STARTED.md)**: The developer onboarding guide. Explains the local build/test workflow, introduces the two binaries (`ja4pd`) and (`ja4p`), and directs developers to run `make init` to bootstrap their environment.
3. **[docs/OPERATIONS_GUIDE.md](file:///home/sean/LLM/JA4proxy3/docs/OPERATIONS_GUIDE.md)**: The single source of truth for running, configuring, scaling, and debugging the proxy. All operational commands live here (and only here).
4. **[docs/MAKEFILE_TARGETS.md](file:///home/sean/LLM/JA4proxy3/docs/MAKEFILE_TARGETS.md)**: An auto-validated directory of all Makefile commands. Other files must link here instead of describing Makefile targets in detail.

---

## Scope

The following files are in scope for modification to align them with the architecture, fix Python proxy references, and remediate broken links:

| File | Change |
|------|--------|
| `README.md` | **Modify** — Align onboarding instructions to recommend `make init` as the primary Day 1 setup entry point. Link to `docs/OPERATIONS_GUIDE.md` for operations. |
| `docs/README.md` | **Modify** — Align role routing links: point to `OPERATIONS_GUIDE.md` instead of `OPERATIONS.md` and `QUICK_REFERENCE.md`. Point monitoring links to the operations guide's assets section. |
| `docs/GETTING_STARTED.md` | **Modify** — Update onboarding commands to use `make init` (guided wizard) instead of manual file copying/environment setup. Replace Go proxy paths `cmd/proxy` with `cmd/ja4pd` and `cmd/ja4p`. Remove `proxy.py` prototyping instructions. |
| `docs/DEPLOYMENT_OPTIONS.md` | **Modify** — Update Go proxy binary paths (`cmd/ja4pd`/`bin/ja4pd`) and remove Python prototype text. |
| `docs/OPERATIONS_GUIDE.md` | **Modify** — Repair corrupted markdown syntax (literal `\n` characters), fix malformed tables, and ensure all references point to the new Go binaries. |
| `docs/PHASE_LIFECYCLE.md` | **Modify** — Remove obsolete references to implementing signals in Python. |
| `docs/QUALITY_PLAN.md` | **Modify** — Replace/clean up links to complete or cancelled phase plans (e.g. `PHASE_14.md`). |
| `docs/REDIS_SCHEMA.md` | **Modify** — Clean up references to Python proxy paths and transient phase files. |
| `docs/SCALING_GUIDE.md` | **Modify** — Remove references to Python proxy throughput caps. Replace broken links to `MONITORING_SETUP.md` with links to `docs/OPERATIONS_GUIDE.md`. |
| `docs/STYLE_GUIDE.md` | **Modify** — Update coding style examples to avoid referencing the Python proxy. |
| `docs/UPGRADE_PATH.md` | **Modify** — Update Go proxy paths and remove legacy Python rollback instructions. |
| `docs/developer/GO_PORT_GUIDE.md` | **Modify** — Clean up obsolete references to `cmd/proxy`. |
| `docs/developer/go_proxy_guide.md` | **Modify** — Clean up outdated Python-to-Go parity details. |
| `docs/architecture/analytics-node-architecture.md` | **Modify** — Clean up historical references to `PHASE_12.md`. |
| `docs/compliance/SECURITY_CONTROLS_MAPPING.md` | **Modify** — Clean up links to complete phase documents. |
| `docs/compliance/SSDF_MAPPING.md` | **Modify** — Clean up links to complete phase documents. |
| `docs/runbooks/REMOTE_TESTING.md` | **Modify** — Add the missing frontmatter header block to pass `make doc-health`. |
| `docs/for-architects/EVALUATION_GUIDE.md` | **Modify** — Add the missing frontmatter header block to pass `make doc-health`. |
| `scripts/start-monitoring.sh` | **Modify** — Update console log output to refer to `docs/OPERATIONS_GUIDE.md#📊-viewing-logs-&-assets` instead of `docs/MONITORING_SETUP.md`. |
| `docs/phases/manifest.yaml` | **Modify** — Register Phase 307 under the User Interface & Experience epic. |

---

## Implementation Plan

### Step 1: Fix Frontmatter and Baseline Linters
- Open `docs/runbooks/REMOTE_TESTING.md` and add the standard frontmatter header:
  ```yaml
  ---
  title: REMOTE_TESTING
  audience: operator
  last_reviewed: 2026-06-04
  phase: v2.0
  ---
  ```
- Open `docs/for-architects/EVALUATION_GUIDE.md` and add the standard frontmatter header:
  ```yaml
  ---
  title: EVALUATION_GUIDE
  audience: architect
  last_reviewed: 2026-06-04
  phase: v2.0
  ---
  ```
- Run `make doc-health` to verify that all frontmatter errors are resolved.

### Step 2: Align Onboarding to `make init`
- Update the root `README.md` Quick Start section:
  - Recommend `make init` (setup wizard) as the primary way to copy env files, generate passwords, and provision assets (Tranco/GeoIP).
  - Explicitly explain that `make init` builds the `ja4p` CLI and launches the interactive config tool.
- Update `docs/GETTING_STARTED.md` to:
  - Guide the developer to run `make init` first to initialize their environment.
  - Detail the role of the two binaries: `bin/ja4pd` (the Go proxy daemon) and `bin/ja4p` (the Go operational CLI).
  - Update build/run paths to use `cmd/ja4pd` (daemon) and `cmd/ja4p` (CLI) instead of `cmd/proxy`.

### Step 3: Remove Obsolete Python Proxy References
- Audit the scoped files for any mentions of `proxy.py`, `src/security/`, and warnings about the Python proxy being a "prototyping surface."
- Update these descriptions to state that the Go proxy daemon (`ja4pd`) is the sole production runtime.
- Update legacy benchmark commands (e.g. `bench-python`) to benchmark targets for the Go daemon (e.g. `make bench-all`).

### Step 4: Replace Phase Doc References with Stable Links
- Audit the scoped files for links to complete phase documents (e.g. `docs/phases/complete/PHASE_XX.md`).
- Replace these references with links to stable reference guides (such as `docs/decisions/INDEX.md`, `docs/OPERATIONS_GUIDE.md`, or `docs/REDIS_SCHEMA.md`).
- If a phase must be referenced for historical context, clearly mark it as such (e.g. "documented in historical phase plan PHASE_XX.md").

### Step 5: Clean Up Broken Internal Links
- Open `docs/README.md` and update all broken routing links:
  - Point to `OPERATIONS_GUIDE.md` instead of the deleted `OPERATIONS.md`.
  - Point monitoring links to the consolidated section in `docs/OPERATIONS_GUIDE.md#📊-viewing-logs-&-assets`.
  - Remove links to the deleted `QUICK_REFERENCE.md`.
- Open `docs/SCALING_GUIDE.md` and `docs/TLS_TRAFFIC_GENERATOR.md` and resolve references to `MONITORING_SETUP.md` by pointing them to `docs/OPERATIONS_GUIDE.md`.
- Open `scripts/start-monitoring.sh` and change the console print statement from `docs/MONITORING_SETUP.md` to `docs/OPERATIONS_GUIDE.md#📊-viewing-logs-&-assets`.
- Verify all links using the Docker-based Lychee run.

### Step 6: Validate and Sync
- Run `make doc-health` and verify it exits 0.
- Run `make lint-docs-all` to run the doc-health, internal link check, and ATT&CK mapping checkers.
- Run `make sync` to update `docs/phases/TODO.md` and `docs/PROJECT_STATUS.md`.
- Run `make test` to verify no CLI tests or scripts were broken.

---

## Test Strategy

- **Doc Health Validation**: `make doc-health` validates all frontmatter blocks.
- **Link Integrity Audit**: A complete Lychee link scan (running via Docker) will verify that all internal markdown links are fully resolved and correct.
- **Makefile Meta-Linting**: Run `make lint-meta` to verify Makefile targets and automation scripts are clean.
- **Zero Regression Verification**: A full run of `make test` will confirm that no test paths, CLI configs, or runner scripts are affected by the documentation edits.

---

## Acceptance Criteria

- [ ] `make doc-health` passes with zero errors (all 97+ files validated).
- [ ] Onboarding instructions in `README.md` and `docs/GETTING_STARTED.md` recommend `make init` as the primary setup entry point.
- [ ] No references to the removed `proxy.py` or legacy Python proxy remain as active guides.
- [ ] All references to `cmd/proxy/` are updated to `./cmd/ja4pd/` or `./cmd/ja4p/`.
- [ ] All broken links in `docs/README.md` are resolved.
- [ ] Zero broken internal links exist across the entire `docs/` folder (excluding `docs/phases/complete/` and `docs/reports/` which are out of scope).
- [ ] `scripts/start-monitoring.sh` correctly points to `docs/OPERATIONS_GUIDE.md`.
- [ ] `make lint-docs-all` exits with 0.
- [ ] `make test` runs and passes with zero failures.

---

## Out of Scope

- Modifying historical phase plans under `docs/phases/` (other than updating the manifest and this file).
- Editing auto-generated security, performance, or pentest audit reports in `docs/reports/`.
- Changing any codebase logic in `src/`, `internal/`, or `cmd/`.
- Removing historical ADRs under `docs/decisions/`, as they record design choices made at specific times, though their links may be cleaned up.
