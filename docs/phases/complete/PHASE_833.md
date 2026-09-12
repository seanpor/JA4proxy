# Eliminate First-Party CVE Scan Exceptions

## Goal
Permanently eliminate all 3 first-party security scan exceptions (`CVE-2026-0994`, `GHSA-6v7p-g79w-8964`, `CVE-2025-47273`) from `.trivyignore.first-party`, achieving **0 exceptions** on all images built and shipped by this repository.

## Scope
1. **Tooling Container (`ja4proxy-test`)**:
   - Upgrade `protobuf` to `>=5.29.6` in `requirements.txt` to clear `CVE-2026-0994` (and `PYSEC-2026-1805`).
   - Remove `PYSEC-2026-1805` from the `Makefile` `pip-audit` ignore list.
   - Verify `semgrep 1.177.0` and `mcp 1.29.0` resolve cleanly with `protobuf>=5.29.6`.
2. **Production Python Containers (`ja4proxy-analytics`, `ja4proxy-management`)**:
   - In `deploy/docker/Dockerfile.analytics` and `deploy/docker/Dockerfile.management`, eliminate pip from the final runtime stage.
   - Using a multi-stage build or removing `/usr/local/lib/python3.14/site-packages/pip` strips pip's vendored `msgpack` (`GHSA-6v7p-g79w-8964`) and `pkg_resources` (`CVE-2025-47273`).
3. **Security Gate & Configuration**:
   - Clean `.trivyignore.first-party` so it contains 0 exceptions.
   - Update `scripts/scan_exceptions.py` tests to verify 0 first-party exceptions.

## Implementation Plan
1. **Step 1: Bump `protobuf`**:
   - Update `requirements.txt` with `protobuf>=5.29.6`.
   - Update `Makefile` `pip-audit` invocation to remove `--ignore-vuln PYSEC-2026-1805`.
   - Test `pip install --dry-run` and `make lint-static` in container.
2. **Step 2: Hardened Python Dockerfiles**:
   - Inspect `deploy/docker/Dockerfile.analytics` and `deploy/docker/Dockerfile.management`.
   - Ensure the final runtime image does not contain `pip` / `setuptools` build trees.
   - Run `trivy image --severity HIGH,CRITICAL ja4proxy-analytics:1.0.0` and `ja4proxy-management:1.0.0` without any first-party ignore file.
3. **Step 3: Clear `.trivyignore.first-party`**:
   - Remove the entries for `CVE-2026-0994`, `GHSA-6v7p-g79w-8964`, and `CVE-2025-47273`.
   - Run `make scan-first-party` and `python3 scripts/scan_exceptions.py`.
4. **Step 4: News Fragment & Closeout**:
   - Add news fragment `docs/fragments/phase-833-eliminate-first-party-cve-exceptions.md`.
   - Run `make preflight`.

## Test Strategy
- `make lint` & `make scan-first-party` exits 0 with completely empty `.trivyignore.first-party`.
- Full unit tests for analytics and management run containerized to guarantee stripping pip has no adverse runtime effect.

## Acceptance Criteria
- [ ] `.trivyignore.first-party` has 0 active CVE waivers.
- [ ] `make scan-first-party` passes cleanly with 0 vulnerabilities.
- [ ] `make test` and `make preflight` pass 100% green.

## Out of Scope
- Modifying third-party monitoring sidecars (Grafana, Alloy, cAdvisor) — tracked separately for Phase 834.
