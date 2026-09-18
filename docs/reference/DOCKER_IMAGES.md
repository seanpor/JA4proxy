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

<!-- BEGIN GENERATED: first-party-images -->

_13 first-party images. Generated from the Dockerfiles and compose files by `make sync` — do not edit this table by hand._

| Image | Dockerfile | Base |
|-------|------------|------|
| — | `Dockerfile.bandit` | `python:3.14-slim` |
| — | `Dockerfile.tools` | `python:3.14-slim` |
| `ja4proxy-attacker:1.0.0` | `deploy/docker/Dockerfile.attacker` | `alpine:3.22.2@sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412` |
| — | `deploy/docker/Dockerfile.cli` | `gcr.io/distroless/static-debian12@sha256:a9fcaedd4c9b59e12dd65d954f0b5044f19b0647a8a3712e77205df9e7b102cd` |
| `ja4proxy:2.0.0` | `deploy/docker/Dockerfile.go-proxy` | `alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b` |
| — | `deploy/docker/Dockerfile.go-proxy.foss` | `alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b` |
| `ja4proxy-tap:1.0.0` | `deploy/docker/Dockerfile.ja4-tap` | `alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b` |
| `ghcr.io/seanpor/ja4proxy-management:main` | `deploy/docker/Dockerfile.management` | `python:3.14.6-alpine3.24@sha256:26730869004e2b9c4b9ad09cab8625e81d256d1ce97e72df5520e806b1709f92` |
| `ja4proxy-mockbackend:1.0.0` | `deploy/docker/Dockerfile.mockbackend` | `alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b` |
| `ja4proxy-test:1.0.0` | `deploy/docker/Dockerfile.test` | `python:3.14.6-alpine3.24@sha256:26730869004e2b9c4b9ad09cab8625e81d256d1ce97e72df5520e806b1709f92` |
| `ja4proxy-trafficgen:1.0.0` | `deploy/docker/Dockerfile.trafficgen` | `python:3.14.6-alpine3.24@sha256:26730869004e2b9c4b9ad09cab8625e81d256d1ce97e72df5520e806b1709f92` |
| `ja4proxy-analytics:1.0.0` | `src/analytics/Dockerfile` | `python:3.14.6-alpine3.24@sha256:26730869004e2b9c4b9ad09cab8625e81d256d1ce97e72df5520e806b1709f92` |
| — | `src/tarpit/Dockerfile` | `python:3.14.6-alpine3.24@sha256:26730869004e2b9c4b9ad09cab8625e81d256d1ce97e72df5520e806b1709f92` |

<!-- END GENERATED: first-party-images -->

## Version Pinning Rules

| Tag style | Acceptable? | Notes |
|-----------|-------------|-------|
| `image:latest` | **No** | Unpredictable; breaks reproducibility |
| `image:7` (major only) | **No** | Too coarse; gets silent minor upgrades |
| `image:7.4` (major.minor) | Acceptable for low-risk monitoring images | Still gets patch upgrades |
| `image:7.4.0` (major.minor.patch) | **Preferred** | Fully deterministic |
| `image:7.4.0@sha256:abc` (digest-pinned) | Best | Recommended for production |
