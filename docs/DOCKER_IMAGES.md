<!--
title: Docker Image Inventory
audience: Operators, DevOps
last_reviewed: 2026-06-13
phase: 314
-->

# Docker Image Inventory

This document serves as the canonical registry of every Docker image used in the JA4Proxy project.

> **Phase 314 reconciliation (2026-06-13).** The third-party table below was
> refreshed against the actually-pinned tags in `Makefile` (`TRIVY_IMAGES`) and
> `deploy/docker/docker-compose.*.yml` — it had drifted by many releases. The
> `prom/alertmanager` (`v0.32.1`→`v0.33.0`) and `oliver006/redis_exporter`
> (`v1.84.0`→`v1.86.0`) bumps in this phase clear their HIGH CVEs. The remaining
> Go-based images carry upstream HIGH CVEs with **no newer fixed tag yet** —
> tracked in [security/THIRD_PARTY_CVE_WAIVERS.md](security/THIRD_PARTY_CVE_WAIVERS.md).

## Third-Party Images

| Image | Pinned Version | Used in | Last Reviewed | Notes |
|-------|----------------|---------|---------------|-------|
| `python:3.14-slim` | `3.14.0-slim` | `deploy/docker/Dockerfile.management`, `deploy/docker/Dockerfile.test`, `deploy/docker/Dockerfile.trafficgen`, `deploy/docker/Dockerfile.admin` | 2026-06-13 | Base for Debian-based Python services |
| `redis/redis-stack` | `7.4.0-v8` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.poc.yml` | 2026-06-13 | Database with RediSearch/RedisJSON; newest tag (HIGH backlog — see waivers) |
| `haproxy` | `2.8.24-alpine` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.poc.yml`, `deploy/docker/docker-compose.scale.yml` | 2026-06-13 | Edge proxy/Load balancer; HIGH/CRITICAL-clean |
| `prom/prometheus` | `v3.12.0` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.monitoring.yml` | 2026-06-13 | Time-series metrics; newest tag (Go-stdlib HIGH — see waivers) |
| `prom/alertmanager` | `v0.33.0` | `deploy/docker/docker-compose.monitoring.yml` | 2026-06-13 | Alerting gateway; **bumped from v0.32.1 — clears HIGH** |
| `grafana/grafana` | `13.0.2-ubuntu` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.monitoring.yml` | 2026-06-13 | Visualisation dashboard; newest major (HIGH backlog — see waivers) |
| `prom/node-exporter` | `v1.11.1` | `deploy/docker/docker-compose.monitoring.yml` | 2026-06-13 | Host metrics collector; newest tag (Go-stdlib HIGH — see waivers) |
| `oliver006/redis_exporter` | `v1.86.0` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.monitoring.yml` | 2026-06-13 | Redis metrics collector; **bumped from v1.84.0 — clears HIGH** |
| `grafana/loki` | `3.7.2` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.monitoring.yml` | 2026-06-13 | Log aggregation; newest stable (HIGH backlog — see waivers) |
| `grafana/promtail` | `3.6.11` | `deploy/docker/docker-compose.prod.yml`, `deploy/docker/docker-compose.monitoring.yml` | 2026-06-13 | Log shipment agent; newest stable (HIGH backlog — see waivers) |

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
