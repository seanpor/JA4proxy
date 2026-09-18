# Node Exporter Consolidation into Alloy & Carrier Reduction

## Goal
Consolidate host/node metric collection into Grafana Alloy by activating its native `prometheus.exporter.unix` component and retiring the standalone `prom/node-exporter:v1.12.1` sidecar. This eliminates `prom/node-exporter` from our third-party image footprint, cuts down carrier redundancy for Go stdlib CVEs, updates scrape and compose configurations, and preserves full metrics parity.

## Scope
1. **Alloy Configuration**:
   - Enable `prometheus.exporter.unix "node"` in `deploy/monitoring/alloy/config.alloy`.
   - Configure procfs (`/host/proc`), sysfs (`/host/sys`), rootfs (`/host`), textfile collector (`/textfile`), and excluded mount points to match current `node-exporter` settings.
2. **Docker Compose Configuration**:
   - Retire the `node-exporter` service from `deploy/docker/docker-compose.monitoring.yml`.
   - Add the necessary read-only host mounts (`/proc:/host/proc:ro`, `/sys:/host/sys:ro`, `/:/host:ro`, `/var/lib/node_exporter/textfile_collector:/textfile:ro`) to the `alloy` service in `deploy/docker/docker-compose.monitoring.yml`.
3. **Prometheus Scrape Configuration**:
   - Update the `node` scrape job in `deploy/monitoring/prometheus/prometheus.yml` to target Alloy's unix exporter endpoint on `alloy:12345` (`/api/v0/component/prometheus.exporter.unix.node/metrics`).
   - Retain `job_name: 'node'` and all existing metric relabeling so dashboards and alerts continue resolving untouched.
4. **Third-Party Inventory & Ignorefile**:
   - Remove `prom/node-exporter:v1.12.1` from `docs/reference/DOCKER_IMAGES.md`.
   - Update carrier lists in `.trivyignore.third-party` using `scripts/refresh_trivyignore_justifications.py`.
   - Confirm with `scripts/check_trivyignore_drift.py` and prune any newly dead waivers.
5. **Security & Testing**:
   - Update `tests/unit/test_monitoring_privileges.py` and `tests/unit/test_alloy_migration.py` to assert `node-exporter` is retired, its host mounts are read-only in `alloy`, and no new privileges/sockets are introduced.

## Implementation Plan
1. Update `deploy/monitoring/alloy/config.alloy` to define `prometheus.exporter.unix "node"`.
2. Update `deploy/docker/docker-compose.monitoring.yml` to remove `node-exporter` and grant read-only mounts to `alloy`.
3. Update `deploy/monitoring/prometheus/prometheus.yml` to scrape `alloy:12345` with metrics path `/api/v0/component/prometheus.exporter.unix.node/metrics`.
4. Update unit tests in `tests/unit/test_monitoring_privileges.py` and `tests/unit/test_alloy_migration.py`.
5. Update `docs/reference/DOCKER_IMAGES.md` and refresh `.trivyignore.third-party`.
6. Run `make test-unit`, `make scan-images`, `make scan-exceptions`, and `make preflight`.

## Test Strategy
- Unit tests verify `node-exporter` service is absent, `alloy` has proper read-only mounts, and no Docker socket is mounted.
- `docker compose config` validates compose syntax cleanly across stacks.
- `make scan-images` and `make scan-exceptions` confirm third-party image compliance and waiver health.
- `make preflight` exits 0.

## Acceptance Criteria
- [ ] `prom/node-exporter` service removed from compose.
- [ ] Alloy `prometheus.exporter.unix` configured and scraped under `job="node"`.
- [ ] Host mounts on `alloy` remain read-only; no Docker socket leak.
- [ ] Unit tests updated and passing.
- [ ] `.trivyignore.third-party` updated with refreshed carriers; 0 dead waivers.
- [ ] `make preflight` passes.

## Out of Scope
- Migrating log shipping away from Alloy.
- Upgrading or replacing other third-party sidecars without verified clean upstream tags.
