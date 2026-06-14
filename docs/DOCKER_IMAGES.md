<!--
title: Docker Image Inventory
audience: Operators, DevOps
last_reviewed: 2026-06-14
phase: 317
-->

# Docker Image Inventory

This document serves as the canonical registry of every Docker image used in the JA4Proxy project.

## Third-Party Images

| Image | Pinned Version | Used in | Last Reviewed | Notes |
|-------|----------------|---------|---------------|-------|
| `python:3.14-slim` | `3.14.0-slim` | `deploy/docker/Dockerfile.management` | 2026-06-14 | Debian base for the FastAPI management service (no-fix distro CVEs are .trivyignore-waived; these are out of the first-party HIGH gate) |
| `python:3.14.6-alpine3.24` | `3.14.6-alpine3.24@sha256:003970a2` | `src/analytics/Dockerfile`, `src/tarpit/Dockerfile`, `deploy/docker/Dockerfile.test`, `deploy/docker/Dockerfile.trafficgen` | 2026-06-14 | **Phase 317** hardened, digest-pinned, perl-free alpine base. `test`/`trafficgen` were re-based off Debian `python:3.14-slim`; all four scan **0 HIGH/CRITICAL** |
| `redis/redis-stack` | `7.4.0-v8` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.poc.yml` | 2026-06-13 | Database with RediSearch/RedisJSON |
| `haproxy:2.8-alpine` | `2.8.24-alpine` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.poc.yml` | 2026-06-13 | Edge proxy/Load balancer |
| `haproxy:2.6` | `2.6.15` | `deploy/docker/docker-compose.scale.yml` | 2026-06-13 | Legacy scaling tests |
| `redis:7-alpine` | `7.2.4-alpine` | `deploy/docker/docker-compose.test.yml` | 2026-06-13 | Lightweight Redis for tests |
| `mcr.microsoft.com/playwright:v1.40.0-jammy` | `v1.40.0-jammy` | `deploy/docker/docker-compose.test.yml` | 2026-06-13 | E2E testing environment |
| `prom/prometheus` | `v3.12.0` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.monitoring.yml` | 2026-06-13 | Time-series metrics |
| `prom/alertmanager` | `v0.33.0` | `deploy/docker/docker-compose.monitoring.yml` | 2026-06-13 | Alerting gateway |
| `grafana/grafana` | `13.0.2-ubuntu` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.monitoring.yml` | 2026-06-13 | Visualisation dashboard |
| `prom/node-exporter` | `v1.11.1` | `deploy/docker/docker-compose.monitoring.yml` | 2026-06-13 | Host metrics collector |
| `oliver006/redis_exporter` | `v1.84.0` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.monitoring.yml` | 2026-06-13 | Redis metrics collector |
| `grafana/loki` | `3.7.2` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.monitoring.yml` | 2026-06-13 | Log aggregation system |
| `grafana/promtail` | `3.6.11` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.monitoring.yml` | 2026-06-13 | Log shipment agent |

## First-Party Images

| Image | Tag | Dockerfile | Notes |
|-------|-----|------------|-------|
| `ja4proxy` | `latest` | `deploy/docker/Dockerfile` | Main proxy service |
| `ja4proxy-analytics` | `latest` | `src/analytics/Dockerfile` | Signal analysis service |
| `ja4proxy-tarpit` | `latest` | `src/tarpit/Dockerfile` | Connection slowing service |
| `ja4proxy-mockbackend` | `latest` | `deploy/docker/Dockerfile.mockbackend` | Mock upstream for testing |
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
