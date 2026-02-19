# JA4proxy — Quick Reference

## Essential Commands

| Action | Command |
|--------|---------|
| **Start all** | `./start-all.sh` |
| **Generate traffic** | `./generate-tls-traffic.sh 60 10 20` |
| **Scale proxies** | `./scale-proxies.sh 4` |
| **Run tests** | `./run-tests.sh` |
| **Stop** | `docker compose -f docker-compose.poc.yml down && docker compose -f docker-compose.monitoring.yml down` |
| **View logs** | `docker compose -f docker-compose.poc.yml logs -f proxy` |

## Service URLs

| Service | URL |
|---------|-----|
| HAProxy (LB) | `https://localhost:443` |
| HAProxy Stats | `https://localhost:8404/stats` (TLS) |
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
make deploy-poc        # Start POC environment
make test              # Run tests
make smoke-test        # Quick smoke test
make logs              # View proxy logs
make health-check      # Check service health
make stop              # Stop services
make clean             # Clean everything
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
# Stop and clean POC
docker compose -f docker-compose.poc.yml down -v
rm -rf reports/

# Full cleanup (including images)
make clean

# Remove all stopped containers
docker container prune -f

# Remove unused images
docker image prune -f

# Remove unused volumes
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
# 1. Clone repo
git clone https://github.com/yourusername/JA4proxy.git
cd JA4proxy

# 2. Start POC
./start-poc.sh

# 3. Verify
./smoke-test.sh

# 4. Run tests
./run-tests.sh

# 5. View reports
open reports/coverage/index.html
```

## Daily Development

```bash
# Start services
./start-poc.sh

# Make code changes...

# Run tests
./run-tests.sh

# View logs if needed
docker compose -f docker-compose.poc.yml logs -f proxy

# Stop when done
docker compose -f docker-compose.poc.yml down
```

---

**Need Help?**
- Read: [POC_GUIDE.md](POC_GUIDE.md)
- Read: [TESTING.md](TESTING.md)
- Run: `make help`
