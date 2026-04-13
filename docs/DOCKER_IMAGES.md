<!--
title: Docker Image Inventory
audience: Operators, DevOps
last_reviewed: 2026-04-03
phase: 25
-->

# Docker Image Inventory

This document serves as the canonical registry of every Docker image used in the JA4Proxy project.

## Third-Party Images

| Image | Pinned Version | Used in | Last Reviewed | Notes |
|-------|----------------|---------|---------------|-------|
| `python:3.11-slim` | `3.11.11-slim` | `deploy/docker/Dockerfile`, `src/analytics/Dockerfile`, `src/tarpit/Dockerfile`, `deploy/docker/Dockerfile.mockbackend`, `deploy/docker/Dockerfile.test`, `deploy/docker/Dockerfile.trafficgen` | 2026-03-28 | Base for all Python services |
| `redis/redis-stack` | `7.4.0-v3` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.poc.yml` | 2026-03-28 | Database with RediSearch/RedisJSON |
| `haproxy:2.8-alpine` | `2.8.5-alpine` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.poc.yml` | 2026-03-28 | Edge proxy/Load balancer |
| `haproxy:2.6` | `2.6.15` | `deploy/docker/docker-compose.scale.yml` | 2026-03-28 | Legacy scaling tests |
| `redis:7-alpine` | `7.2.4-alpine` | `deploy/docker/docker-compose.test.yml` | 2026-03-28 | Lightweight Redis for tests |
| `mcr.microsoft.com/playwright:v1.40.0-jammy` | `v1.40.0-jammy` | `deploy/docker/docker-compose.test.yml` | 2026-03-28 | E2E testing environment |
| `prom/prometheus` | `v2.48.0` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.monitoring.yml` | 2026-03-28 | Time-series metrics |
| `prom/alertmanager` | `v0.26.0` | `deploy/docker/docker-compose.monitoring.yml` | 2026-03-28 | Alerting gateway |
| `grafana/grafana` | `10.2.2` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.monitoring.yml` | 2026-03-28 | Visualisation dashboard |
| `prom/node-exporter` | `v1.7.0` | `deploy/docker/docker-compose.monitoring.yml` | 2026-03-28 | Host metrics collector |
| `oliver006/redis_exporter` | `v1.55.0` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.monitoring.yml` | 2026-03-28 | Redis metrics collector |
| `grafana/loki` | `3.3.2` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.monitoring.yml` | 2026-03-28 | Log aggregation system |
| `grafana/promtail` | `3.3.2` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.monitoring.yml` | 2026-03-28 | Log shipment agent |

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
