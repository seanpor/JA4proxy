# Security Remediation — CI Supply Chain + Default Credential Removal

## Goal

Eliminate six infrastructure-level critical findings: (1) GitHub Actions workflow
uses unpinned `@v4`/`@v5` action tags instead of SHA-pinned references, creating
a supply chain attack vector; (2–4) default credentials in Grafana (`admin`),
Management API (`admin/admin`), and HAProxy stats (`admin/admin123`) exposed via
compose file fallback values; (5) no SBOM generation or image signing for the main
Go proxy image; (6) no CI workflow for the Go proxy image build/sign/push.

## Scope

Files to modify:
- `.github/workflows/ja4proxy-policy.yml` — SHA-pin all actions
- `docker/docker-compose.monitoring.yml` — remove Grafana/HAPROXY default credential fallbacks
- `docker/docker-compose.poc.yml` — remove Management default credential fallbacks
- `docker/docker-compose.test.yml` — add test Redis password, bind to 127.0.0.1
- `.github/workflows/go-proxy-image.yml` — **new** Go proxy image build, SBOM, sign, push
- `docker/Dockerfile.go-proxy` — add non-root USER directive if missing

## Implementation Plan

### A — SHA-pin GitHub Actions (policy workflow)

1. Replace `actions/checkout@v4` with `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683` (v4.1.1)
2. Replace `actions/setup-python@v5` with `actions/setup-python@65d7f2d534ac1bc67fcd62888c5f4f3d2cb2b236` (v5.0.0)
3. Follow the existing pattern in `.github/workflows/release-cli.yml` which already
   uses SHA-pinned actions.

### B — Remove default credential fallbacks

1. `docker/docker-compose.monitoring.yml`:
   - Change `GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD:-admin}` to
     `${GRAFANA_PASSWORD:?GRAFANA_PASSWORD is required}`
   - Change `--haproxy.scrape-uri=http://${HAPROXY_STATS_USER:-admin}:${HAPROXY_STATS_PASSWORD:-admin123}@...`
     to use `:?` required syntax for both user and password.
2. `docker/docker-compose.poc.yml`:
   - Change `MANAGEMENT_JWT_SECRET=${MANAGEMENT_JWT_SECRET:-change-me-in-production}` to
     `${MANAGEMENT_JWT_SECRET:?MANAGEMENT_JWT_SECRET is required}`
   - Change `MANAGEMENT_ADMIN_USER=${MANAGEMENT_ADMIN_USER:-admin}` to `:?` required
   - Change `MANAGEMENT_ADMIN_PASSWORD=${MANAGEMENT_ADMIN_PASSWORD:-admin}` to `:?` required
3. `docker/docker-compose.test.yml`:
   - Set `REDIS_PASSWORD` to a test password (e.g. `${REDIS_PASSWORD:-test-fixtures-pw}`)
   - Change Redis port binding from `6380:6379` to `127.0.0.1:6380:6379`

### C — Go proxy image CI workflow (new)

1. Create `.github/workflows/go-proxy-image.yml`:
   - Trigger: push to `main` + tag creation
   - Build `Dockerfile.go-proxy` (multi-stage, Go binary)
   - Run `go test ./...` before build
   - Run `make scan-first-party` (Trivy CVE scan)
   - Generate SBOM with Syft: `syft dir:. --format cyclonedx-json`
   - Push image to GHCR with `latest` and git SHA tags
   - Sign image with cosign (key from GitHub secrets)
   - Generate SLSA provenance (following `release-cli.yml` pattern)
2. Add required secrets documentation to `docs/enterprise/`:
   - `COSIGN_PRIVATE_KEY`, `COSIGN_PASSWORD` for image signing
   - `GHCR_TOKEN` for GHCR push

### D — Dockerfile.go-proxy hardening

1. Ensure `USER` directive exists (non-root user for the proxy process).
2. Ensure base image version is pinned (not `:latest`).

## Acceptance Criteria

- [ ] All GitHub Actions are SHA-pinned (no `@v4`, `@v5`, etc. remain)
- [ ] `grep -r ':-admin' docker/` returns no matches (no default admin passwords)
- [ ] `grep -r ':-change-me' docker/` returns no matches
- [ ] Grafana refuses to start without `GRAFANA_PASSWORD` env var
- [ ] Management API refuses to start without `MANAGEMENT_JWT_SECRET`
- [ ] Test Redis port bound to `127.0.0.1:6380:6379`
- [ ] `.github/workflows/go-proxy-image.yml` builds, tests, SBOM-generates, signs, and pushes
- [ ] `Dockerfile.go-proxy` has `USER` directive (non-root)
- [ ] CHANGELOG.md entry written
- [ ] `make lint-yaml` passes (compose files valid)

## Out of Scope

- Changing Helm chart secrets management (that's a Kubernetes-specific concern).
- Implementing image verification policies in Kubernetes (admission webhook).
- Adding Redis TLS configuration to management API or analytics services.
- Migrating POC compose to Docker secrets (documented, accepted risk for dev).
