# JA4proxy — Quick Reference

## Essential Commands

| Action | Command |
|--------|---------|
| **Start all** | `./start-all.sh`  or  `make start` |
| **Stop all** | `./stop-all.sh`   or  `make stop` |
| **Stop + wipe** | `./stop-all.sh --clean`  or  `make stop-clean` |
| **Status** | `./status.sh`     or  `make status` |
| **Generate traffic** | `./generate-tls-traffic.sh 60 10 20` |
| **Reset between runs** | `make flush-redis` |
| **Scale proxies** | `./scale-proxies.sh 4` |
| **Update GeoIP DB** | `make update-geoip` (monthly) |
| **Run tests** | `./run-tests.sh` |
| **View logs** | `make logs` |

## Incident Response (no restart needed)

```bash
./scripts/ja4-admin.sh status                           # Attack snapshot
./scripts/ja4-admin.sh top 10                           # Top fingerprints by volume
./scripts/ja4-admin.sh blocked                          # Active bans/blocks with TTL
./scripts/ja4-admin.sh block-ja4 <fingerprint>          # Blacklist FP → instant TCP RST
./scripts/ja4-admin.sh block-ip  <ip> [secs]            # Hard-block an IP (default 3600s)
./scripts/ja4-admin.sh unblock-ip <ip>                  # Remove IP block
./scripts/ja4-admin.sh list-ja4                         # Current blacklist + whitelist
./scripts/ja4-admin.sh flush                            # Clear all transient state
./scripts/ja4-admin.sh help                             # Full command reference

# Makefile shortcuts (same commands)
make attack-status
make top-attackers
make block-ja4 FP=t13d190900_9dc949149365_97f8aa674fd9
make block-ip   IP=203.0.113.42
make unblock-ip IP=203.0.113.42
```

Look up any fingerprint at **https://ja4db.com/** to identify the tool/malware.

See [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md) for step-by-step attack playbooks.

## Service URLs

| Service | URL |
|---------|-----|
| HAProxy (LB) | `https://localhost:443` |
| HAProxy Stats | `http://localhost:8404/stats` |
| Proxy Metrics | `http://localhost:9090/metrics` |
| Backend (HTTPS) | `https://localhost:8443` |
| Tarpit | `http://localhost:8888` |
| Prometheus | `http://localhost:9091` |
| Grafana | `http://localhost:3001` (admin / see .env) |
| Loki | `http://localhost:3100` (Docker network only) |
| Alertmanager | `http://localhost:9093` |
| Redis | Docker network only, password from .env |

## Testing Commands

```bash
# Run all tests
./run-tests.sh

# Run specific test category
docker compose -f docker-compose.poc.yml run --rm test pytest tests/unit/ -v
docker compose -f docker-compose.poc.yml run --rm test pytest tests/integration/ -v

# Run single test file
docker compose -f docker-compose.poc.yml run --rm test pytest tests/test_proxy.py -v

# Run with coverage report
docker compose -f docker-compose.poc.yml run --rm test pytest tests/ --cov=proxy --cov-report=term
```

## Makefile Shortcuts

```bash
make help              # Show all commands
make start             # Start full stack (POC + monitoring)
make stop              # Stop all services
make stop-clean        # Stop and wipe all volumes
make status            # Health dashboard + security state
make logs              # View proxy logs
make flush-redis       # Clear rate windows/bans/blocks — keep whitelist/blacklist
make update-geoip      # Download latest IP2Location LITE database (run monthly)
make check-geoip       # Check age of current GeoIP database
make fetch-db          # Pull latest malicious fingerprints (ja4db/FoxIO)
make list-pending      # Review fingerprints before approving
make approve-all       # Approve pending fingerprints
make test              # Run all tests
make smoke-test        # Quick smoke test
make clean             # Stop + remove all containers and volumes
```

## Backend Test Endpoints

```bash
# Health check
curl https://localhost:8443/api/health

# Echo request
curl https://localhost:8443/api/echo

# Delayed response (3 seconds)
curl https://localhost:8443/delay/3

# Specific status code
curl https://localhost:8443/status/404

# POST request
curl -X POST -d '{"test":"data"}' https://localhost:8443/api/echo
```

## Docker Operations

```bash
# Start all services
docker compose -f docker-compose.poc.yml up -d

# Stop all services
docker compose -f docker-compose.poc.yml down

# Stop and remove volumes
docker compose -f docker-compose.poc.yml down -v

# View service status
docker compose -f docker-compose.poc.yml ps

# View logs (all services)
docker compose -f docker-compose.poc.yml logs -f

# View logs (specific service)
docker compose -f docker-compose.poc.yml logs -f proxy
docker compose -f docker-compose.poc.yml logs -f backend
docker compose -f docker-compose.poc.yml logs -f redis

# Restart service
docker compose -f docker-compose.poc.yml restart proxy

# Rebuild images
docker compose -f docker-compose.poc.yml build
docker compose -f docker-compose.poc.yml build --no-cache
```

## Redis Operations

```bash
# Access Redis CLI
docker exec -it ja4proxy-redis redis-cli -a "$REDIS_PASSWORD"

# Test Redis
docker exec ja4proxy-redis redis-cli -a "$REDIS_PASSWORD" ping

# View all keys
docker exec ja4proxy-redis redis-cli -a "$REDIS_PASSWORD" KEYS "*"

# Get value
docker exec ja4proxy-redis redis-cli -a "$REDIS_PASSWORD" GET "key"

# Set value
docker exec ja4proxy-redis redis-cli -a "$REDIS_PASSWORD" SET "key" "value"

# Flush all transient security state (rate windows, blocks, bans, audit logs)
# Preserves ja4:whitelist and ja4:blacklist keys
make flush-redis
```

## Debugging

```bash
# Shell access to test container
docker compose -f docker-compose.poc.yml run --rm test bash

# Shell access to proxy container
docker exec -it ja4proxy bash

# View container details
docker inspect ja4proxy
docker inspect ja4proxy-backend
docker inspect ja4proxy-redis

# Check network
docker network inspect ja4proxy_ja4proxy
```

## Cleanup

```bash
# Stop all services (keep Redis data)
make stop

# Stop and wipe all volumes (fresh slate)
make stop-clean

# Full cleanup (containers + volumes + images)
make clean

# Remove unused Docker resources
docker container prune -f
docker image prune -f
docker volume prune -f
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Services won't start | Run `docker compose -f docker-compose.poc.yml down -v` then `./start-poc.sh` |
| Port conflicts | Edit ports in `docker-compose.poc.yml` |
| Tests failing | Run `./start-poc.sh` then `./smoke-test.sh` |
| Permission errors | Run `sudo chown -R $USER:$USER reports/` |
| Redis connection fails | Run `docker compose -f docker-compose.poc.yml restart redis` |
| Good traffic blocked from previous run | Run `make flush-redis` to clear stale bans (auto-expires in 300s anyway) |

## File Locations

| What | Where |
|------|-------|
| Main proxy code | `proxy.py` |
| Configuration | `config/proxy.yml` |
| Tests | `tests/` |
| Test reports | `reports/` |
| Docker compose (POC) | `docker-compose.poc.yml` |
| Docker compose (monitoring) | `docker-compose.monitoring.yml` |
| Documentation | `docs/` |

## First Time Setup

```bash
# 1. Configure your backend (edit BACKEND_HOST / BACKEND_PORT)
cp .env.example .env && nano .env

# 2. Start everything
./start-all.sh

# 3. Verify
./status.sh

# 4. Generate test traffic
./generate-tls-traffic.sh 60 15 20

# 5. Open Grafana
open http://localhost:3001    # password in .env
```

## Daily Development

```bash
make start                   # Start all services
# Make changes...
make logs                    # View proxy output
make flush-redis             # Reset state between test runs
make stop                    # Stop when done
```

---

**Need help?**
- [FAQ](FAQ.md) — Common operational questions
- [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md) — Active attack playbooks
- [SECOPS_OPERATIONS.md](SECOPS_OPERATIONS.md) — Full admin guide
- `make help` — All available commands
