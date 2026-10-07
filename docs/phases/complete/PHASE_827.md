# Upstream Sidecar CVE Verification & Tag Auditing

## Goal
Eliminate security-theater date bumping for third-party sidecar container image CVE waivers (`.trivyignore.third-party`). Replace blind date extension scripts with an automated upstream tag auditor (`scripts/check_upstream_image_updates.py`) that queries upstream container registries (Docker Hub / Quay) for newly published tags of pinned sidecars (Grafana, HAProxy, Loki, Alertmanager, cAdvisor). If an upstream update exists that resolves open CVEs, the gate fails and forces an image upgrade PR rather than a passive waiver renewal.

## Scope
- **Upstream Tag Verification Engine**: Create `scripts/check_upstream_image_updates.py` to query upstream container registries (Docker Hub API v2, Quay API) for newer image tags of all third-party sidecars.
- **Integration into `make scan-exceptions`**: Update `make scan-exceptions` and `scripts/scan_exceptions.py` to invoke upstream tag verification.
- **Strict Waiver Validation**: Block waiver renewal or extension when a newer upstream tag is available.
- **Documentation**: Update `docs/runbooks/security_scan_exceptions.md` and `.trivyignore.third-party` policy header to mandate upstream tag check before any waiver extension.

## Implementation Plan
1. **Upstream Tag Checker (`scripts/check_upstream_image_updates.py`)**:
   - Parse third-party image declarations from `.trivyignore.third-party` and `deploy/docker/docker-compose.*.yml`.
   - Query OCI / Docker Hub registry APIs (`https://registry-1.docker.io/v2/`, `https://quay.io/api/v1/`) for published tags newer than the pinned tag.
   - For each newer tag found, flag which suppressed CVEs are candidate fixes.
   - Output structured JSON summary and exit non-zero if a newer tag is available for an image with active CVE waivers.
2. **Integration into `make scan-exceptions`**:
   - Wrap `check_upstream_image_updates.py` in `scripts/scan_exceptions.py` or Makefile targets.
   - Ensure local dev and CI pre-push gates fail when a sidecar image tag bump is available to remediate ignored CVEs.
3. **Unit Tests**:
   - Add unit test suite `tests/unit/test_check_upstream_image_updates.py` with mock registry HTTP responses to verify tag parsing, semantic version comparison, and error handling.
4. **Runbook & Policy Alignment**:
   - Update `docs/runbooks/security_scan_exceptions.md` with operator procedures for upstream tag checks before granting or renewing third-party waivers.

## Test Strategy
- Unit test `tests/unit/test_check_upstream_image_updates.py` testing OCI registry JSON parsing, semver ordering, and waiver invalidation.
- Integration test with `make scan-exceptions` running containerized via `ja4proxy-tools`.
- Negative test: mock an available upstream tag (e.g. `grafana/grafana:13.2.0`) and verify `make scan-exceptions` exits non-zero with `UPSTREAM_TAG_AVAILABLE` error.

## Acceptance Criteria
- `scripts/check_upstream_image_updates.py` successfully queries registry APIs and identifies newer image tags.
- `make scan-exceptions` runs containerized and fails if an un-upgraded sidecar has available upstream tag updates.
- All new Python code passes `ruff`, `mypy`, `pytest`, and `make preflight`.
- Manifest entry for Phase 827 created and validated with `make lint-phases`.

## Out of Scope
- Automatic image tag bumping in production compose files without human PR review.
- Modifying first-party image Dockerfiles (`ja4proxy`, `ja4proxy-analytics`, `ja4proxy-tarpit`).
