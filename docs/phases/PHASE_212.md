---
phase: 212
title: "Resolve Third-Party Image CVEs (CRITICAL)"
status: COMPLETE
size: MEDIUM
created: 2026-06-01
audience: [developer, ops]
dependencies: []
---

# Resolve Third-Party Image CVEs (CRITICAL)

## Goal

Bump every third-party Docker image referenced in `Makefile:TRIVY_IMAGES` to a version that passes `make scan-images` with zero CRITICAL findings. Currently 7 images have CRITICAL CVEs in their Go transitive dependencies (x/crypto, grpc, stdlib). The fix is mechanical: determine the minimum patch version where each image's embedded Go toolchain/dependencies are patched, update the version in every compose file and the Makefile, and verify with a fresh Trivy scan.

## Scope

### Images to fix

| Image | Current tag | CRITICAL | Root cause |
|-------|------------|----------|------------|
| `oliver006/redis_exporter` | `v1.55.0` | 2 | Go stdlib CVE-2024-24790 |
| `prom/prometheus` | `v2.48.0` | 5 | docker/docker, x/crypto, grpc |
| `prom/alertmanager` | `v0.26.0` | 3 | x/crypto, Go stdlib |
| `prom/node-exporter` | `v1.7.0` | 3 | x/crypto, Go stdlib |
| `grafana/grafana` | `10.2.2` | 2+ | go-git, plugin-sdk, x/crypto, grpc (7 CRITICAL in total) |
| `grafana/loki` | `3.3.2` | 2 | grpc |
| `grafana/promtail` | `3.3.2` | 2 | grpc |

Also fix HIGH-only advisories where a trivial bump eliminates them:
| Image | Current tag | HIGH | Root cause |
|-------|------------|------|------------|
| `haproxy` | `2.8.5-alpine` | 6 | openssl CVE (3.1.4 → 3.1.7) |
| `redis/redis-stack` | `7.4.0-v3` | 1 | gpgv CVE |

### Files to modify
- `Makefile` — update `TRIVY_IMAGES` values
- `deploy/docker/docker-compose.prod.yml` — update image tags
- `deploy/docker/docker-compose.monitoring.yml` — update image tags
- `deploy/docker/docker-compose.poc.yml` — update image tags (haproxy, redis-stack)
- `deploy/docker/docker-compose.scale.yml` — update image tag (haproxy)
- `deploy/docker/docker-compose.manual-test.yml` — if redis:7.2.4-alpine scan reveals HIGH/CRITICAL
- `deploy/docker/docker-compose.test.yml` — if redis:7.2.4-alpine scan reveals HIGH/CRITICAL
- `docs/phases/manifest.yaml` — register Phase 212
- `CHANGELOG.md` — Phase 212 entry

### Files checked (no change expected)
- `deploy/docker/docker-compose.redis-tls.yml` — redis:7-alpine (test-only, not scanned by TRIVY_IMAGES)
- `deploy/docker/docker-compose.python-legacy.yml` — no `image:` references
- `scripts/check_image_versions.py` — verify it tolerates the new versions

### Not in scope
- First-party images (`ja4proxy:*`, `ja4proxy-analytics:*`, etc.) — separate scan target
- Running `make scan` on non-TRIVY_IMAGES compose files (redis:7.2.4-alpine, playwright, etc.)
- Addressing the underlying Go dependency patching strategy for images we build
- Changing Trivy scanner image version (currently `aquasec/trivy:0.69.3`)

## Implementation Plan

1. **Determine target versions** — for each image in scope, try `docker pull <image>:<candidate>` + `make scan-images` (by temporarily editing `TRIVY_IMAGES`) to find the minimum version with zero CRITICAL. Document the result for each.
2. **Update Makefile** — replace current tags with fix versions in `TRIVY_IMAGES`
3. **Update compose files** — bump tags in `prod.yml`, `monitoring.yml`, `poc.yml`, `scale.yml`, and optionally `manual-test.yml`/`test.yml`
4. **Verify** — run `make scan-images` and confirm zero CRITICAL (and ideally zero HIGH). If any image still shows CRITICAL, bump further.
5. **Update `scripts/check_image_versions.py`** — if the version-schema check needs adjustment for new tags
6. **Document** — CHANGELOG, manifest, sync-roadmap, verify `make lint-phases`

## Test Strategy

- `make scan-images` must exit 0 with **zero CRITICAL** findings (pass gate)
- Check the version-reference map in `scripts/check_image_versions.py` matches actual compose-file versions
- Quick smoke test: `docker compose -f deploy/docker/docker-compose.monitoring.yml pull --ignore-pull-failures` to verify all new tags resolve

## Acceptance Criteria

1. `make scan-images` reports zero CRITICAL findings across all 9 images
2. Every compose file that references a bumped image uses the new tag consistently
3. `scripts/check_image_versions.py` passes (version consistency across compose files)
4. `make lint-phases` exits 0
5. `make scan` (which includes `scan-images`) exits 0

## Out of scope

- Patching CVEs in first-party images (separate build-chain concern)
- Patching CVEs in `redis:7.2.4-alpine` or `playwright` test images (not in `TRIVY_IMAGES`)
- Adding `redis:7.2.4-alpine` to `TRIVY_IMAGES`
- Functional regression testing of the monitoring stack after version bumps
