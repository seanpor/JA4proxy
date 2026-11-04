# Phase 862: Local Pre-PR Gates & Upstream Drift Prevention

## Goal
Enforce complete shift-left verification so that no documentation drift, conflicting version pins, or bot-induced CI failures can reach GitHub, while providing an on-demand containerized local hygiene command for early CVE detection.

## Scope
1. **Shift-Left Local Reference Doc Gates:**
   - Wire `scripts/sync_reference_docs.py --check` into `make lint-meta` (and thus `make lint`), ensuring any drift between Dockerfiles and `docs/reference/DOCKER_IMAGES.md` fails locally before push.
   - Enforce `sync_reference_docs.py --check` inside `scripts/close-phase.sh`.

2. **Isolated Environment Requirements Validation:**
   - Add a lightweight check (`make lint-deps` / step in `lint-meta`) verifying independent resolution per isolated environment using `$(TOOLS_RUN)` (containerized Python 3.14 per `AGENTS.md`):
     - `management/requirements.txt` (isolated management container).
     - `requirements-analytics.txt` (isolated analytics container).
     - Root `requirements.txt` + `requirements-test.txt` (developer toolchain).
   - Check for unwanted version discrepancies across test fixtures vs runtime environments without artificially forcing unrelated containers into a single synthetic dependency graph.

3. **Dependabot Configuration & Group Hardening:**
   - Refactor `.github/dependabot.yml` Python package grouping to partition core runtime dependencies from development/testing toolchains, avoiding un-mergeable monolithic bundles.
   - Configure Dependabot Docker base image updates with explicit guidance and safe automated sync where applicable.

4. **On-Demand Local Hygiene Gate (`make hygiene`):**
   - Provide a fast, on-demand local pre-check target `make hygiene`:
     - Runs `pip-audit` inside `$(TOOLS_RUN)`.
     - Runs `govulncheck` in the Go toolchain container.
     - Runs `sync_reference_docs.py --check` and `lint-phases.py`.
   - Keep scheduled recurring scans centralized in GitHub Actions cron (alerting via GitHub Issues), avoiding invasive local workstation cron/daemon antipatterns.

## Implementation Plan
1. **Makefile Updates:**
   - Add `sync_reference_docs.py --check` to `lint-meta`.
   - Add `lint-deps` target running containerized resolution checks across separated requirement files.
   - Add `hygiene` target running fast on-demand CVE and doc drift audit.
2. **Phase Close-out Script:**
   - Update `scripts/close-phase.sh` to assert `python3 scripts/sync_reference_docs.py --check` passes before creating branches or PRs.
3. **Dependabot Configuration:**
   - Refactor `.github/dependabot.yml` to partition update groups cleanly.
4. **Documentation:**
   - Document `make hygiene` usage in `docs/development/` for developer shift-left checks.

## Test Strategy
- Unit tests asserting `sync_reference_docs.py --check` detects artificial drift in Dockerfiles and exits non-zero.
- Verification that `make lint-meta` catches reference doc drift locally.
- Full `make preflight` gate validation.

## Acceptance Criteria
- `make lint` fails locally if any Dockerfile base image differs from `docs/reference/DOCKER_IMAGES.md`.
- `scripts/close-phase.sh` refuses to close out a phase if reference docs are out of sync.
- Dependabot Python groups are cleanly partitioned to avoid resolution-impossible bundles.
- `make hygiene` runs on-demand via containerized tools and reports early warnings on CVEs and drift.

## Out of Scope
- Workstation background daemons / cron / systemd user timers (scheduled checks remain centralized in CI).
- Full Python 3.15 runtime migration (Phase 861).
- Python package reconciliation for pending PR updates (Phase 860).
