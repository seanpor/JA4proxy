# Third-Party Monitoring Sidecar CVE Analysis & Upstream Bumps

## Goal
Systematically audit the remaining 24 third-party CVE exceptions in `.trivyignore.third-party` against newly published upstream releases of the monitoring sidecars (`grafana/grafana`, `prom/prometheus`, `prom/alertmanager`, `grafana/loki`, `grafana/alloy`, and `oliver006/redis_exporter`). Upgrade any sidecars that have clean or improved releases to reduce our third-party vulnerability count.

## Scope
1. **Audit Upstream Tags**:
   - `grafana/grafana` (current: `13.1.4-ubuntu`)
   - `prom/prometheus` (current: `v3.14.0`)
   - `prom/alertmanager` (current: `v0.34.0`)
   - `grafana/loki` (current: `3.7.6`)
   - `grafana/alloy` (current: `v1.18.1`)
   - `oliver006/redis_exporter` (current: `v1.87.0`)
2. **Scan & Compare Vulnerabilities**:
   - Run containerized Trivy comparisons (`aquasec/trivy:0.71.0`) against current vs candidate tags.
   - Ensure candidate versions introduce zero net regressions in HIGH/CRITICAL vulnerabilities.
3. **Compose Configurations**:
   - Update `deploy/docker/docker-compose.monitoring.yml` and `deploy/docker/docker-compose.prod.yml` with validated image tags.
4. **Ignorefile & Documentation**:
   - Update `.trivyignore.third-party`, `docs/reference/DOCKER_IMAGES.md`, and add news fragment in `docs/fragments/`.

## Implementation Plan
1. Test pull and scan available patch releases for monitoring sidecars.
2. Evaluate which CVEs in `.trivyignore.third-party` are resolved by newer builds (e.g. Apache Thrift `CVE-2026-43871`, Go stdlib DoS `CVE-2026-56854`, `CVE-2026-84304`, `CVE-2026-84445`).
3. Update compose files for images with confirmed net-positive CVE reductions.
4. Update `.trivyignore.third-party` removing retired carriers/CVEs.
5. Validate configuration with `make scan-exceptions`, `make lint-phases`, and `make preflight`.

## Test Strategy
- Trivy scan of bumped images confirms equal or fewer HIGH/CRITICAL vulnerabilities.
- `make scan-exceptions` passes cleanly.
- `make lint-phases` exits 0.
- Integration/compose validation passes.

## Acceptance Criteria
- [ ] Upstream release availability verified for all monitoring sidecars.
- [ ] Viable candidate images bumped across compose files.
- [ ] Carrier lists and `.trivyignore.third-party` updated.
- [ ] `make lint-phases` and test suite pass 100% green.

## Out of Scope
- Recompiling upstream closed-source binaries or maintaining custom forks of Grafana/Prometheus images.
