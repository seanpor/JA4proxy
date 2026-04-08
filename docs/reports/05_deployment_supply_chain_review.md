# Deployment Infrastructure & Supply Chain Review

**Date:** 2026-04-08  
**Scope:** Dockerfiles, docker-compose files, Helm chart, CI/CD pipelines, security configs, secrets management, TLS certificates  
**Findings:** 30 total

---

## Findings Summary

| # | Severity | Category | Finding |
|---|----------|----------|---------|
| 1 | **CRITICAL** | Prod Config | Prod compose uses legacy Python proxy, not Go binary |
| 2 | **CRITICAL** | Test Security | Test Redis has hardcoded empty password, port exposed to host |
| 3 | **CRITICAL** | Default Creds | Grafana defaults to password "admin" if env unset |
| 4 | **CRITICAL** | Default Creds | Management service defaults to admin/admin + placeholder JWT |
| 5 | HIGH | Default Creds | HAProxy stats exporter defaults to admin/admin123 |
| 6 | HIGH | Supply Chain | No SBOM generation, no image signing for main proxy |
| 7 | HIGH | CI Security | Policy workflow uses unpinned GitHub Action tags (@v4, @v5) |
| 8 | HIGH | CI Security | GitLab CI uses unpinned `python:3.11-slim` (no digest) |
| 9 | HIGH | Container Security | Test-runner Dockerfile runs as root |
| 10 | HIGH | Container Security | Recorder Dockerfile runs as root |
| 11 | HIGH | TLS Security | Test TLS key embedded in image layers, 10-year validity |
| 12 | HIGH | Kubernetes | Helm chart has no NetworkPolicy resources |
| 13 | HIGH | Kubernetes | Helm chart missing container-level securityContext |
| 14 | HIGH | Kubernetes | Helm chart defaults to image tag "latest" |
| 15 | MEDIUM | Kubernetes | Helm secret has `resource-policy: keep` (stale secrets) |
| 16 | MEDIUM | Kubernetes | Helm secrets exposed via `--set` in CLI/history |
| 17 | MEDIUM | Container Security | Promtail mounts Docker socket |
| 18 | MEDIUM | Container Security | cAdvisor runs with `privileged: true` |
| 19 | MEDIUM | SAST | Bandit skips 17 security checks (B103, B104, B324, etc.) |
| 20 | MEDIUM | Supply Chain | Trivy scanner uses `:latest` tag |
| 21 | MEDIUM | Web Security | Grafana cookies insecure, HSTS disabled |
| 22 | MEDIUM | Supply Chain | No CI workflow for Go proxy image build/sign/push |
| 23 | MEDIUM | Config Drift | Scale compose declares unused/conflicting network names |
| 24 | MEDIUM | Container Security | POC proxy runs without seccomp profile |
| 25 | MEDIUM | Access Control | Redis unix socket permissions 777 |
| 26 | LOW | Base Image | `python:3.14.0-slim` may not be a stable release |
| 27 | LOW | Helm Chart | Missing NOTES.txt and _helpers.tpl |
| 28 | LOW | Helm Chart | ServiceMonitor port "metrics" not exposed by Service |
| 29 | LOW | Helm Chart | Redis StatefulSet with empty volumeClaimTemplates |
| 30 | INFO | Dev Experience | No `.env.example` template |

---

## Critical Findings

### Finding 1 — CRITICAL: Prod Compose Uses Legacy Python Proxy

**File:** `docker/docker-compose.prod.yml`, line 53

```yaml
  proxy:
    build:
      context: ..
      dockerfile: docker/Dockerfile   # <-- LEGACY Python, NOT Go
```

The POC compose correctly uses `Dockerfile.go-proxy`. The production compose deploys the slower, larger-attack-surface Python proxy instead of the hardened Go binary.

**Remediation:** Change to `dockerfile: docker/Dockerfile.go-proxy`.

### Finding 2 — CRITICAL: Test Redis Has No Password, Port Exposed to Host

**File:** `docker/docker-compose.test.yml`, lines 43, 66-67, 88-89

```yaml
ports:
  - 6380:6379        # Exposed to host
environment:
  REDIS_PASSWORD: ""  # Hardcoded empty
```

Unauthenticated Redis reachable on the host.

**Remediation:** Bind to `127.0.0.1:6380:6379` and set a test password.

### Finding 3 — CRITICAL: Grafana Defaults to Password "admin"

**File:** `docker/docker-compose.monitoring.yml`, line 61

```yaml
- GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD:-admin}
```

Exposed on port 3001.

**Remediation:** Use `${GRAFANA_PASSWORD:?GRAFANA_PASSWORD is required}`.

### Finding 4 — CRITICAL: Management Service Defaults to admin/admin

**File:** `docker/docker-compose.poc.yml`, lines 256-258

```yaml
- MANAGEMENT_JWT_SECRET=${MANAGEMENT_JWT_SECRET:-change-me-in-production}
- MANAGEMENT_ADMIN_USER=${MANAGEMENT_ADMIN_USER:-admin}
- MANAGEMENT_ADMIN_PASSWORD=${MANAGEMENT_ADMIN_PASSWORD:-admin}
```

---

## High Findings

### Finding 5 — HAProxy Stats Defaults to admin/admin123

**File:** `docker/docker-compose.monitoring.yml`, line 228

### Finding 6 — No SBOM Generation or Image Signing

`release-cli.yml` has SLSA provenance but no SBOM. No CI workflow for the main proxy image at all.

### Finding 7 — GitHub Actions Not SHA-Pinned in Policy Workflow

**File:** `.github/workflows/ja4proxy-policy.yml`

Uses `actions/checkout@v4` and `actions/setup-python@v5` (mutable tags). The `release-cli.yml` correctly uses full SHA pins.

### Finding 8 — GitLab CI Uses Unpinned Base Image

**File:** `.gitlab-ci/ja4proxy-policy.yml`, line 19

```yaml
image: python:3.11-slim  # No digest pin
```

### Finding 9, 10 — Dockerfiles Run as Root

`tests/docker/Dockerfile.test-runner` and `Dockerfile.recorder` have no `USER` directive.

### Finding 11 — Test TLS Key Embedded in Image

**File:** `tests/docker/Dockerfile.tls-backend`

Key generated inside Dockerfile, embedded in layers, 10-year validity.

### Finding 12 — Helm Chart Has No NetworkPolicy

Zero NetworkPolicy resources. Any pod in the same namespace can communicate with proxy and Redis.

### Finding 13 — Helm Chart Missing Container-Level securityContext

Pod-level `securityContext` set, but no container-level:
- `allowPrivilegeEscalation: false`
- `readOnlyRootFilesystem: true`
- `capabilities.drop: ["ALL"]`

### Finding 14 — Helm Chart Defaults to "latest" Image Tag

**File:** `deploy/helm/ja4proxy/values.yaml`, lines 8-10

---

## Medium Findings

### Finding 15 — Helm Secret Has `resource-policy: keep`

Stale secrets persist across `helm uninstall`.

### Finding 16 — Helm Secrets Exposed via `--set` CLI

Password visible in shell history, CI logs, `helm get values`.

### Finding 17 — Promtail Mounts Docker Socket

**File:** `docker/docker-compose.monitoring.yml`, lines 153-154

### Finding 18 — cAdvisor Runs with `privileged: true`

**File:** `docker/docker-compose.monitoring.yml`, line 189

### Finding 19 — Bandit Skips 17 Security Checks

Including B103 (world-writable dirs), B104 (bind all interfaces), B324 (weak hash).

### Finding 20 — Trivy Scanner Uses `:latest` Tag

**File:** `Makefile`, lines 398, 420, 439

### Finding 21 — Grafana Cookies Insecure, HSTS Disabled

```yaml
GF_SECURITY_COOKIE_SECURE=false
GF_SECURITY_STRICT_TRANSPORT_SECURITY=false
```

### Finding 22 — No CI Workflow for Go Proxy Image

No workflow builds, signs, or pushes the Go proxy image.

### Finding 23 — Scale Compose Has Conflicting Network Names

### Finding 24 — POC Proxy Runs Without Seccomp Profile

### Finding 25 — Redis Unix Socket Permissions 777

**File:** `docker/docker-compose.poc.yml`, line 104

World-readable/writable socket.

---

## Low Findings

### Finding 26 — `python:3.14.0-slim` May Not Be Stable

Python 3.14.0 is not yet a stable release.

### Finding 27 — Missing Helm NOTES.txt and _helpers.tpl

### Finding 28 — ServiceMonitor Port "metrics" Not Exposed by Service

The Service only maps port 80 → 8080. Port 9090 (metrics) is not exposed.

### Finding 29 — Redis StatefulSet with Empty volumeClaimTemplates

Defeats the purpose of using a StatefulSet.

### Finding 30 — No `.env.example` Template

---

## Priority Remediation Order

**Immediate (block production deployment):**
1. Fix Finding 1 — Point prod compose to `Dockerfile.go-proxy`
2. Fix Findings 3, 4, 5 — Remove all default credential fallback values
3. Fix Finding 2 — Add test Redis password, bind port to 127.0.0.1

**Before next production release:**
4. Fix Finding 7 — SHA-pin all GitHub Actions
5. Fix Finding 12 — Add NetworkPolicy to Helm chart
6. Fix Finding 13 — Add container-level securityContext to Helm
7. Fix Finding 6 — Add SBOM and image signing to CI
8. Fix Findings 17, 18 — Remove Docker socket mount, remove privileged mode

**Near-term hardening:**
9. Fix Finding 22 — Create Go proxy CI build/sign-push workflow
10. Fix Finding 14 — Pin Helm chart image by digest
11. Fix Finding 25 — Restrict Redis socket permissions
12. Fix Finding 19 — Review and minimize Bandit skips
