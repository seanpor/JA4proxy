| Image | Pinned version | Used in | Last reviewed | Notes |
|-------|---------------|---------|---------------|-------|
| python:3.11-slim | 3.11.11-slim | docker/Dockerfile | 2026-03-24 | Base for proxy, analytics |
| redis/redis-stack | 7.4.0-v3 | docker-compose.prod.yml | 2026-03-24 | Pin digest in Phase 25c |
| grafana/grafana | 10.2.2 | docker-compose.prod.yml, docker-compose.monitoring.yml | 2026-03-24 | Aligned versions |
| grafana/loki | 3.3.2 | docker-compose.prod.yml, docker-compose.monitoring.yml | 2026-03-24 | Major version update |
| grafana/promtail | 3.3.2 | docker-compose.prod.yml, docker-compose.monitoring.yml | 2026-03-24 | Major version update |
| prom/node-exporter | v1.7.0 | docker-compose.monitoring.yml | 2026-03-24 | Added to scan list |
| ja4proxy | latest | docker/Dockerfile | 2026-03-24 | First-party image |
| ja4proxy-analytics | latest | docker/Dockerfile | 2026-03-24 | First-party image |
| ja4proxy-tarpit | latest | docker/Dockerfile | 2026-03-24 | First-party image |
