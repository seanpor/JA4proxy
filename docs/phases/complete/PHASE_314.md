---
phase: 314
title: Third-Party Image HIGH-CVE Remediation (re-enable HIGH-gating)
created: 2026-06-13
audience: [developer]
---

# Third-Party Image HIGH-CVE Remediation

## Goal
Clear the pre-existing **HIGH**-severity CVE backlog in the pinned container images and first-party dependencies so that `make scan` can be flipped back to **gate on HIGH** (not just CRITICAL) — completing the deferral recorded in Phase 313. The end state is that `scan-images` (and `scan-first-party`) fail the build on HIGH or CRITICAL findings, with only justified, dated `.trivyignore` entries where no upstream fix exists.

## Scope
List of files to be modified:
- [Makefile](file:///home/sean/LLM/JA4proxy3/Makefile) - Update `TRIVY_IMAGES` tag bumps, and modify `scan-images` (and verify `scan-first-party`) to gate on HIGH+CRITICAL.
- [deploy/docker/docker-compose.prod.yml](file:///home/sean/LLM/JA4proxy3/deploy/docker/docker-compose.prod.yml) - Update pinned container tags to match Makefile.
- [deploy/docker/docker-compose.monitoring.yml](file:///home/sean/LLM/JA4proxy3/deploy/docker/docker-compose.monitoring.yml) - Update pinned container tags to match Makefile.
- [go.mod](file:///home/sean/LLM/JA4proxy3/go.mod) - Bump Go toolchain and dependencies to resolve first-party CVEs.
- [go.sum](file:///home/sean/LLM/JA4proxy3/go.sum) - Updated for bumped dependencies.
- [docs/DOCKER_IMAGES.md](file:///home/sean/LLM/JA4proxy3/docs/DOCKER_IMAGES.md) - Update documented pinned container tags to match Makefile and compose files.
- [.trivyignore](file:///home/sean/LLM/JA4proxy3/.trivyignore) - Add dated, justified entries for any remaining unfixed CVEs.
- [tests/integration/test_ci_flow.py](file:///home/sean/LLM/JA4proxy3/tests/integration/test_ci_flow.py) - Update assertions to check that HIGH-severity vulnerabilities trigger failures.
- [docs/phases/complete/PHASE_313.md](file:///home/sean/LLM/JA4proxy3/docs/phases/complete/PHASE_313.md) - Mark the deferred subtask checkbox as completed.
- [CHANGELOG.md](file:///home/sean/LLM/JA4proxy3/CHANGELOG.md) - Document the changes made in this phase.

## Implementation Plan
1. **Initial Vulnerability Scan**: Run `make scan-images` and `make scan-first-party` to obtain the current list of HIGH and CRITICAL vulnerabilities across all containers.
2. **First-Party Dependency Remediation**: Update `go.mod` to bump the Go toolchain (e.g. from `1.26` to `1.26.4` or latest patch) and Go dependencies (`go.opentelemetry.io/otel/sdk`, `github.com/apache/thrift`, `github.com/docker/docker`) to address first-party CVEs. Run `go mod tidy` and verify the compilation.
3. **Third-Party Pinned Image Upgrades**: Bump image versions in the `Makefile` under `TRIVY_IMAGES` and in the corresponding Docker Compose files (`deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.monitoring.yml`). Specifically:
   - Upgrade `redis/redis-stack` to clear base image/library CVEs.
   - Upgrade `grafana/*` (Grafana, Loki, Promtail) to clear Go/stdlib CVEs.
   - Upgrade `prom/*` (Prometheus, Alertmanager, Node Exporter) to clear Go/stdlib CVEs.
   - Upgrade `oliver006/redis_exporter`.
   - Upgrade `haproxy`.
4. **Validation and Linting of Image Configs**: Run `make lint-docker` to ensure all compose files and Dockerfiles are syntactically and semantically correct after image upgrades.
5. **Handle Residual CVEs**: If any HIGH CVE has no upstream fix available, document a dated and justified exception in `.trivyignore`.
6. **Enforce HIGH-severity Gating**: Modify the `scan-images` and `scan-first-party` targets in the `Makefile` to set `--severity HIGH,CRITICAL` and verify that any HIGH or CRITICAL finding returns exit code 1.
7. **Test Adaptation**: Modify `tests/integration/test_ci_flow.py` to assert that the scanning pipeline now gates on HIGH+CRITICAL.
8. **Documentation and Metadata updates**: Update `docs/DOCKER_IMAGES.md`, `docs/phases/complete/PHASE_313.md` (check the deferral box), and `CHANGELOG.md`.

## Test Strategy
- **Unit & Integration Tests**: Run `pytest tests/integration/test_ci_flow.py` to assert that the CI flow scanner correctly enforces the HIGH-severity gate.
- **Docker Compose & Port Gating Tests**: Run `make test` (or the relevant docker-compose smoke tests) to verify that upgraded container versions do not introduce runtime failures or port definition regressions.
- **Vulnerability Scanning Verification**: Run `make scan` to ensure it executes successfully and exits with 0 only when all HIGH and CRITICAL CVEs are resolved or ignored.

## Acceptance Criteria
- [ ] `make scan` exits 0 with `scan-images` and `scan-first-party` gating on **HIGH+CRITICAL** (no advisory status for HIGH).
- [ ] Every pinned image bump is mirrored in the Docker Compose files and `docs/DOCKER_IMAGES.md`.
- [ ] `make lint-docker` passes without errors.
- [ ] First-party HIGH CVEs (e.g. stdlib, otel, thrift) are resolved at the source through dependency bumps in `go.mod`.
- [ ] Any entries in `.trivyignore` are dated, individual, and justified.
- [ ] `test_ci_flow.py` verifies the HIGH-gating logic correctly.
- [ ] The full CI check suite (`make test` and `make lint`) is completely green.

## Out of Scope
- Upgrading container OS/base images beyond upgrading the pinned tags of the services.
- Remediation of MEDIUM/LOW severity CVEs.
- Altering the containerization of the lint toolchain (already completed in Phase 313).
