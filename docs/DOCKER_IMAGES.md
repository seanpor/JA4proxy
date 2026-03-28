| Image | Pinned version | Used in | Last reviewed | Notes |
|-------|---------------|---------|---------------|-------|
| python:3.11-slim | 3.11.11-slim | docker/Dockerfile, src/analytics/Dockerfile, docker/Dockerfile.test | 2026-03-28 | Base for proxy, analytics, test runner |
| haproxy | 2.8-alpine | docker/docker-compose.prod.yml | 2026-03-28 | Load balancer |
| redis/redis-stack | 7.4.0-v3 | docker/docker-compose.prod.yml | 2026-03-28 | Redis + RedisBloom + RedisJSON |
| oliver006/redis_exporter | v1.55.0 | docker/docker-compose.prod.yml, docker/docker-compose.monitoring.yml | 2026-03-28 | Redis Prometheus exporter |
| prom/prometheus | v2.48.0 | docker/docker-compose.prod.yml, docker/docker-compose.monitoring.yml | 2026-03-28 | Metrics collection |
| prom/alertmanager | v0.26.0 | docker/docker-compose.monitoring.yml | 2026-03-28 | Alert routing |
| prom/node-exporter | v1.7.0 | docker/docker-compose.monitoring.yml | 2026-03-28 | Host metrics |
| grafana/grafana | 10.2.0 | docker/docker-compose.prod.yml, docker/docker-compose.monitoring.yml | 2026-03-28 | Dashboards — harmonised across prod and monitoring |
| grafana/loki | 2.9.0 | docker/docker-compose.prod.yml, docker/docker-compose.monitoring.yml | 2026-03-28 | Log aggregation — harmonised across prod and monitoring |
| grafana/promtail | 2.9.0 | docker/docker-compose.prod.yml, docker/docker-compose.monitoring.yml | 2026-03-28 | Log shipper — harmonised across prod and monitoring |
| ja4proxy | latest (first-party) | docker/docker-compose.prod.yml | 2026-03-28 | Built locally via `make build`; no external registry |
| ja4proxy-analytics | latest (first-party) | docker/docker-compose.prod.yml | 2026-03-28 | Built locally via `make build` |
| ja4proxy-tarpit | latest (first-party) | docker/docker-compose.prod.yml | 2026-03-28 | Built locally via `make build` |
