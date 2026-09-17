# Third-Party CVE Reduction — Dead Waiver Prune & Upstream Image Bumps

## Goal
Reduce the total number of third-party CVE scan exceptions in `.trivyignore.third-party` from 24 down to 21 (or lower) by pruning dead exceptions and upgrading upstream sidecar images (`oliver006/redis_exporter` and `grafana/alloy`) to newer, cleaner releases.

## Scope
1. **Prune Dead Exceptions**:
   - Remove 3 dead CVE waivers that no longer affect any deployed image:
     - `CVE-2026-42504` (Go stdlib MIME header DoS)
     - `CVE-2026-34040` (Moby authorization bypass)
     - `CVE-2026-27145` (Go stdlib crypto/x509 DoS)
2. **Upstream Sidecar Image Bumps**:
   - `oliver006/redis_exporter`: Upgrade from `v1.87.0` to `v1.91.1` across `deploy/docker/docker-compose.monitoring.yml` and `deploy/docker/docker-compose.prod.yml`. (Trivy scan confirms 0 HIGH/CRITICAL CVEs in `v1.91.1`, eliminating redis_exporter as a carrier for 8 CVEs).
   - `grafana/alloy`: Upgrade from `v1.18.1` to `v1.19.2` across `deploy/docker/docker-compose.monitoring.yml` and `deploy/docker/docker-compose.prod.yml`. (Trivy scan confirms reduction from 17 down to 4 HIGH/CRITICAL CVEs).
3. **Ignorefile & Inventory Hygiene**:
   - Regenerate carrier notes using `scripts/refresh_trivyignore_justifications.py`.
   - Update `docs/reference/DOCKER_IMAGES.md`.
   - Add news fragment in `docs/fragments/`.

## Implementation Plan
1. Prune the 3 dead CVE entries from `.trivyignore.third-party`.
2. Update `deploy/docker/docker-compose.monitoring.yml` and `deploy/docker/docker-compose.prod.yml` with `oliver006/redis_exporter:v1.91.1` and `grafana/alloy:v1.19.2`.
3. Update `docs/reference/DOCKER_IMAGES.md` with new pinned versions and notes.
4. Run `make scan-images` to ensure 100% clean image scans with no unwaived findings.
5. Run `scripts/refresh_trivyignore_justifications.py` to update accurate carrier blocks.
6. Validate with `make scan-exceptions`, `make lint-phases`, and `make preflight`.

## Test Strategy
- Trivy scan of deployed third-party images (`make scan-images`) exits 0.
- `make scan-exceptions` confirms exception count is reduced.
- `scripts/check_trivyignore_drift.py` reports 0 dead entries.
- `make lint-phases` exits 0.

## Acceptance Criteria
- [ ] 3 dead CVE exceptions removed from `.trivyignore.third-party`.
- [ ] `redis_exporter` and `alloy` bumped in compose files.
- [ ] `make scan-images` passes with zero violations.
- [ ] `docs/reference/DOCKER_IMAGES.md` and manifest updated.

## Out of Scope
- Recompiling third-party upstream binaries.
