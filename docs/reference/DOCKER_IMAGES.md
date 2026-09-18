<!--
title: Docker Image Inventory
audience: reference
last_reviewed: 2026-06-14
phase: 317
-->

# Docker Image Inventory

This document serves as the canonical registry of every Docker image used in the JA4Proxy project.

## Third-Party Images

| Image | Pinned Version | Used in | Last Reviewed | Notes |
|-------|----------------|---------|---------------|-------|
| `python:3.14.6-alpine3.24` | `3.14.6-alpine3.24@sha256:26730869004e2b9c4b9ad09cab8625e81d256d1ce97e72df5520e806b1709f92` | `src/analytics/Dockerfile`, `src/tarpit/Dockerfile`, `deploy/docker/Dockerfile.test`, `deploy/docker/Dockerfile.trafficgen`, `deploy/docker/Dockerfile.management` | 2026-07-22 | **Phase 317** hardened, digest-pinned, perl-free alpine base; **Phase 801** added `management` (was Debian `python:3.14-slim`, 41 HIGH/CRITICAL findings, 36 no-fix OS packages). All five scan **0 HIGH/CRITICAL** (`management` carries one dated `.trivyignore` residual, `CVE-2024-23342`/ecdsa, upstream won't-fix) |
| `redis:7.4.11-alpine` | `7.4.11-alpine@sha256:520775a41a63e77e06c73e35d2fd9cc15921a609516818796b4ecbb813078bc7` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.poc.yml` | 2026-09-18 | Lightweight official Redis (Phase 837: bumped from 7.4.9-alpine; scans 0 HIGH/CRITICAL) |

| `haproxy:2.8-alpine` | `2.8.28-alpine` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.poc.yml`, `deploy/docker/docker-compose.scale.yml` | 2026-09-13 | Edge proxy/Load balancer (Phase 834: bumped from 2.8.27-alpine; scans 0 HIGH/CRITICAL) |

| `redis:7-alpine` | `7.2.4-alpine` | `deploy/docker/docker-compose.test.yml` | 2026-06-13 | Lightweight Redis for tests |
| `mcr.microsoft.com/playwright:v1.40.0-jammy` | `v1.40.0-jammy` | `deploy/docker/docker-compose.test.yml` | 2026-06-13 | E2E testing environment |
| `prom/prometheus` | `v3.14.0` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.monitoring.yml` | 2026-09-15 | Time-series metrics |
| `prom/alertmanager` | `v0.34.0` | `deploy/docker/docker-compose.monitoring.yml` | 2026-09-15 | Alerting gateway |
| `grafana/grafana` | `13.1.6-ubuntu` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.monitoring.yml` | 2026-09-15 | Visualisation dashboard. Phase 835: bumped to 13.1.6-ubuntu, eliminating multiple HIGH findings |
| `oliver006/redis_exporter` | `v1.91.1` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.monitoring.yml` | 2026-09-17 | Redis metrics collector. Phase 836: bumped to v1.91.1 (scans 0 HIGH/CRITICAL) |
| `grafana/alloy` | `v1.19.2` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.monitoring.yml` | 2026-09-18 | Telemetry & host/container metrics collector (Phase 825 replaced promtail; Phase 829c replaced cadvisor; Phase 837 replaced node-exporter via unix exporter) |
| `grafana/loki` | `3.7.7` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.monitoring.yml` | 2026-09-15 | Log aggregation system. Phase 835: bumped to 3.7.7 |


## First-Party Images

| Image | Tag | Dockerfile | Notes |
|-------|-----|------------|-------|
| `ja4proxy` | `latest` | `deploy/docker/Dockerfile` | Main proxy service |
| `ja4proxy-analytics` | `latest` | `src/analytics/Dockerfile` | Signal analysis service |
| `ja4proxy-tarpit` | `latest` | `src/tarpit/Dockerfile` | Connection slowing service |
| `ja4proxy-mockbackend` | `latest` | `deploy/docker/Dockerfile.mockbackend` | Mock upstream for testing |
| `ja4proxy-management` | `1.0.0` | `deploy/docker/Dockerfile.management` | FastAPI Management API |
| `ja4proxy-test` | `latest` | `deploy/docker/Dockerfile.test` | Test runner environment |
| `ja4proxy-trafficgen` | `latest` | `deploy/docker/Dockerfile.trafficgen` | Traffic generator for benchmarks |

## Version Pinning Rules

| Tag style | Acceptable? | Notes |
|-----------|-------------|-------|
| `image:latest` | **No** | Unpredictable; breaks reproducibility |
| `image:7` (major only) | **No** | Too coarse; gets silent minor upgrades |
| `image:7.4` (major.minor) | Acceptable for low-risk monitoring images | Still gets patch upgrades |
| `image:7.4.0` (major.minor.patch) | **Preferred** | Fully deterministic |
| `image:7.4.0@sha256:abc` (digest-pinned) | Best | Recommended for production |
