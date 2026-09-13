# Third-Party CVE Reduction — HAProxy 2.8 Update

## Goal
Upgrade the pinned `haproxy:2.8.27-alpine` image to clean `haproxy:2.8.28-alpine` across all compose configurations, eliminating HAProxy as a carrier for `CVE-2026-14456` (`libcrypto3` OpenSSL DoS) and reducing our third-party vulnerability footprint.

## Scope
1. **Docker Compose Configurations**:
   - `deploy/docker/docker-compose.prod.yml`
   - `deploy/docker/docker-compose.poc.yml`
   - `deploy/docker/docker-compose.scale.yml`
   Bump `haproxy:2.8.27-alpine` to `haproxy:2.8.28-alpine`.
2. **Third-Party Ignorefile**:
   - In `.trivyignore.third-party`, update the carrier list for `CVE-2026-14456` (remove `haproxy:2.8.27-alpine`).
3. **Validation**:
   - Run Trivy scan on `haproxy:2.8.28-alpine` without an ignorefile to confirm 0 HIGH/CRITICAL vulnerabilities.
   - Run `docker compose config` across compose files to verify syntax and configuration integrity.

## Implementation Plan
1. Update `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.poc.yml`, and `deploy/docker/docker-compose.scale.yml` with `haproxy:2.8.28-alpine`.
2. Update `.trivyignore.third-party` comments for `CVE-2026-14456` reflecting that only `tecnativa/docker-socket-proxy:v0.5.0` remains a carrier.
3. Validate compose configs and run `make scan-exceptions`.
4. Run `make lint-phases`.

## Test Strategy
- Trivy scan of `haproxy:2.8.28-alpine` reports 0 vulnerabilities.
- `docker compose config` exits 0 on all touched files.
- `make scan-exceptions` exits 0.

## Acceptance Criteria
- [x] HAProxy image pinned to `haproxy:2.8.28-alpine` in production, POC, and scale compose files.
- [x] Zero CVE regressions introduced.
- [x] `make lint-phases` exits 0.

## Out of Scope
- Rebuilding or replacing `tecnativa/docker-socket-proxy`.
