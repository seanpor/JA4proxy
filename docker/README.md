# Docker Infrastructure Reference

This document is the single source of truth for all Docker Compose files in JA4proxy.
Read this before running any `docker compose` command.

---

## Compose File Inventory

| File | Type | Environment | Purpose |
|------|------|-------------|---------|
| `docker/docker-compose.poc.yml` | Standalone base | Development / POC | Full stack: HAProxy + Go proxy + Redis + tarpit + analytics + admin-api + management |
| `docker/docker-compose.python-legacy.yml` | Overlay | Development only | Adds Python proxy alongside Go proxy for cross-language parity validation |
| `docker/docker-compose.scale.yml` | Overlay | Load testing | Replaces single proxy with 4 worker instances behind HAProxy |
| `docker/docker-compose.test.yml` | Standalone | CI / integration tests | Isolated test environment: Go proxy + Python proxy + TLS backend + recorder + test-runner |
| `docker/docker-compose.prod.yml` | Standalone | Production | Single-instance production stack; uses Docker secrets for credentials |
| `docker/docker-compose.monitoring.yml` | Overlay (joins POC networks) | Development / POC | Prometheus + Grafana + Loki + Alertmanager; attaches to a running POC stack |

---

## Scenarios and Commands

### Run the development stack (most common)

```bash
export REDIS_PASSWORD=$(openssl rand -base64 32)
export BACKEND_HOST=your-backend.example.com
docker compose -f docker/docker-compose.poc.yml up -d
```

### Run the development stack with monitoring

Requires the POC stack to already be running (monitoring joins its networks externally).

```bash
docker compose -f docker/docker-compose.monitoring.yml up -d
```

### Run the integration test suite (CI)

```bash
docker compose -f docker/docker-compose.test.yml up --build \
  --abort-on-container-exit --exit-code-from test-runner
```

Makefile target: `make test-go-docker`

### Add the Python proxy for parity comparison

```bash
docker compose -f docker/docker-compose.poc.yml \
               -f docker/docker-compose.python-legacy.yml \
               --env-file .env.dev up -d
```

Makefile target: `make go-start`

### Run the multi-worker scaled stack

```bash
docker compose -f docker/docker-compose.poc.yml \
               -f docker/docker-compose.scale.yml up -d
```

Makefile target: `make start-scaled`

### Deploy to production (single instance)

```bash
mkdir -p deploy/secrets
openssl rand -base64 48 > deploy/secrets/redis_password.txt
echo "your-abuseipdb-key" > deploy/secrets/abuseipdb_api_key.txt
chmod 600 deploy/secrets/*.txt
BACKEND_HOST=upstream.example.com ENVIRONMENT=production \
  docker compose -f docker/docker-compose.prod.yml up -d
```

---

## Overlay vs Standalone

**Standalone** files are complete stacks that can be brought up on their own.

**Overlay** files must be combined with a base file using multiple `-f` flags.

| File | Standalone? | Required base |
|------|-------------|---------------|
| `docker/docker-compose.poc.yml` | Yes | — |
| `docker/docker-compose.python-legacy.yml` | No | `docker/docker-compose.poc.yml` |
| `docker/docker-compose.scale.yml` | No | `docker/docker-compose.poc.yml` |
| `docker/docker-compose.test.yml` | Yes | — |
| `docker/docker-compose.prod.yml` | Yes | — |
| `docker/docker-compose.monitoring.yml` | No | Running POC stack (external network join) |

---

## Network Architecture (POC and Production Stacks)

| Network | Internal? | Connected services |
|---------|-----------|-------------------|
| `ja4proxy-dmz` | No | HAProxy, proxy, trafficgen, test |
| `ja4proxy-data` | Yes | proxy, redis, admin-api, management, test |
| `ja4proxy-origin` | Yes | proxy, backend, tarpit, test |
| `ja4proxy-mgmt` | No | proxy, analytics, admin-api, management |

`internal: true` networks have no outbound internet access. Redis and the origin backend
are isolated.

The monitoring overlay joins `ja4proxy-dmz`, `ja4proxy-data`, and `ja4proxy-mgmt` as
external networks to scrape metrics.

---

## Credentials

All compose files use `${REDIS_PASSWORD:?REDIS_PASSWORD is required}` — the stack
will refuse to start if this variable is unset or empty. There are no silent defaults
for security credentials.

The production stack (`docker/docker-compose.prod.yml`) uses Docker secrets (files in
`deploy/secrets/`) instead of environment variables.

---

## Dockerfile Location Policy

| Location | Rule |
|----------|------|
| `docker/` | All production Dockerfiles that do not own their own module directory |
| `tests/docker/` | All test-infrastructure Dockerfiles |
| `<module>/` | Dockerfiles for independently deployable modules with their own build context, labelled `dockerfile.location=module` |

Module Dockerfiles (`src/analytics/Dockerfile`, `src/tarpit/Dockerfile`) carry the label
`dockerfile.location=module` to distinguish them from `docker/` images in inventory
tooling. Both use the root project directory as their build context.
