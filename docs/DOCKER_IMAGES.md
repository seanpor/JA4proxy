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
| `python:3.11-slim` | `3.11.11-slim` | `docker/Dockerfile`, `src/analytics/Dockerfile`, `tarpit/Dockerfile`, `docker/Dockerfile.mockbackend`, `docker/Dockerfile.test`, `docker/Dockerfile.trafficgen` | 2026-03-28 | Base for all Python services |
| `redis/redis-stack` | `7.4.0-v3` | `docker/docker-compose.prod.yml`, `docker/docker-compose.poc.yml` | 2026-03-28 | Database with RediSearch/RedisJSON |
| `haproxy:2.8-alpine` | `2.8.5-alpine` | `docker/docker-compose.prod.yml`, `docker/docker-compose.poc.yml` | 2026-03-28 | Edge proxy/Load balancer |
| `haproxy:2.6` | `2.6.15` | `docker/docker-compose.scale.yml` | 2026-03-28 | Legacy scaling tests |
| `redis:7-alpine` | `7.2.4-alpine` | `docker/docker-compose.test.yml` | 2026-03-28 | Lightweight Redis for tests |
| `mcr.microsoft.com/playwright:v1.40.0-jammy` | `v1.40.0-jammy` | `docker/docker-compose.test.yml` | 2026-03-28 | E2E testing environment |
| `prom/prometheus` | `v2.48.0` | `docker/docker-compose.prod.yml`, `docker/docker-compose.monitoring.yml` | 2026-03-28 | Time-series metrics |
| `prom/alertmanager` | `v0.26.0` | `docker/docker-compose.monitoring.yml` | 2026-03-28 | Alerting gateway |
| `grafana/grafana` | `10.2.2` | `docker/docker-compose.prod.yml`, `docker/docker-compose.monitoring.yml` | 2026-03-28 | Visualisation dashboard |
| `prom/node-exporter` | `v1.7.0` | `docker/docker-compose.monitoring.yml` | 2026-03-28 | Host metrics collector |
| `oliver006/redis_exporter` | `v1.55.0` | `docker/docker-compose.prod.yml`, `docker/docker-compose.monitoring.yml` | 2026-03-28 | Redis metrics collector |
| `grafana/loki` | `3.3.2` | `docker/docker-compose.prod.yml`, `docker/docker-compose.monitoring.yml` | 2026-03-28 | Log aggregation system |
| `grafana/promtail` | `3.3.2` | `docker/docker-compose.prod.yml`, `docker/docker-compose.monitoring.yml` | 2026-03-28 | Log shipment agent |

## First-Party Images

| Image | Tag | Dockerfile | Notes |
|-------|-----|------------|-------|
| `ja4proxy` | `latest` | `docker/Dockerfile` | Main proxy service |
| `ja4proxy-analytics` | `latest` | `src/analytics/Dockerfile` | Signal analysis service |
| `ja4proxy-tarpit` | `latest` | `tarpit/Dockerfile` | Connection slowing service |
| `ja4proxy-mockbackend` | `latest` | `docker/Dockerfile.mockbackend` | Mock upstream for testing |
| `ja4proxy-test` | `latest` | `docker/Dockerfile.test` | Test runner environment |
| `ja4proxy-trafficgen` | `latest` | `docker/Dockerfile.trafficgen` | Traffic generator for benchmarks |

## Version Pinning Rules

| Tag style | Acceptable? | Notes |
|-----------|-------------|-------|
| `image:latest` | **No** | Unpredictable; breaks reproducibility |
| `image:7` (major only) | **No** | Too coarse; gets silent minor upgrades |
| `image:7.4` (major.minor) | Acceptable for low-risk monitoring images | Still gets patch upgrades |
| `image:7.4.0` (major.minor.patch) | **Preferred** | Fully deterministic |
| `image:7.4.0@sha256:abc` (digest-pinned) | Best | Recommended for production |
