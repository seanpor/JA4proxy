# JA4 Proxy - Quick Reference

All commands run in Docker - no local Python installation needed!

## Essential Commands

| Action | Command |
|--------|---------|
| **Start POC** | `./start-poc.sh` |
| **Run Tests** | `./run-tests.sh` |
| **Quick Test** | `./smoke-test.sh` |
| **Stop POC** | `docker-compose -f docker-compose.poc.yml down` |
| **View Logs** | `docker-compose -f docker-compose.poc.yml logs -f proxy` |

## Service URLs

| Service | URL | Purpose |
|---------|-----|---------|
| Proxy Metrics | http://localhost:9090/metrics | Prometheus metrics |
| Backend | http://localhost:8081 | Mock backend server |
| Backend Health | http://localhost:8081/api/health | Health check |
| Prometheus | http://localhost:9091 | Metrics dashboard |
| Redis | localhost:6379 | Cache (password: changeme) |

## Testing Commands

```bash
# Run all tests
./run-tests.sh

# Run specific test category
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/unit/ -v
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/integration/ -v

# Run single test file
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/test_proxy.py -v

# Run with coverage report
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/ --cov=proxy --cov-report=term
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
curl http://localhost:8081/api/health

# Echo request
curl http://localhost:8081/api/echo

# Delayed response (3 seconds)
curl http://localhost:8081/delay/3

# Specific status code
curl http://localhost:8081/status/404

# POST request
curl -X POST -d '{"test":"data"}' http://localhost:8081/api/echo
```

## Docker Operations

```bash
# Start all services
docker-compose -f docker-compose.poc.yml up -d

# Stop all services
docker-compose -f docker-compose.poc.yml down

# Stop and remove volumes
docker-compose -f docker-compose.poc.yml down -v

# View service status
docker-compose -f docker-compose.poc.yml ps

# View logs (all services)
docker-compose -f docker-compose.poc.yml logs -f

# View logs (specific service)
docker-compose -f docker-compose.poc.yml logs -f proxy
docker-compose -f docker-compose.poc.yml logs -f backend
docker-compose -f docker-compose.poc.yml logs -f redis

# Restart service
docker-compose -f docker-compose.poc.yml restart proxy

# Rebuild images
docker-compose -f docker-compose.poc.yml build
docker-compose -f docker-compose.poc.yml build --no-cache
```

## Redis Operations

```bash
# Access Redis CLI
docker exec -it ja4proxy-redis redis-cli -a changeme

# Test Redis
docker exec ja4proxy-redis redis-cli -a changeme ping

# View all keys
docker exec ja4proxy-redis redis-cli -a changeme KEYS "*"

# Get value
docker exec ja4proxy-redis redis-cli -a changeme GET "key"

# Set value
docker exec ja4proxy-redis redis-cli -a changeme SET "key" "value"
```

## Debugging

```bash
# Shell access to test container
docker-compose -f docker-compose.poc.yml run --rm test bash

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
docker-compose -f docker-compose.poc.yml down -v
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
| Services won't start | Run `docker-compose -f docker-compose.poc.yml down -v` then `./start-poc.sh` |
| Port conflicts | Edit ports in `docker-compose.poc.yml` |
| Tests failing | Run `./start-poc.sh` then `./smoke-test.sh` |
| Permission errors | Run `sudo chown -R $USER:$USER reports/` |
| Redis connection fails | Run `docker-compose -f docker-compose.poc.yml restart redis` |

## File Locations

| What | Where |
|------|-------|
| Main proxy code | `proxy.py` |
| Tests | `tests/` |
| Configuration | `config/` |
| Test reports | `reports/` |
| Docker compose | `docker-compose.poc.yml` |
| POC guide | `POC_GUIDE.md` |
| Testing guide | `TESTING.md` |

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
docker-compose -f docker-compose.poc.yml logs -f proxy

# Stop when done
docker-compose -f docker-compose.poc.yml down
```

---

**Need Help?**
- Read: [POC_GUIDE.md](POC_GUIDE.md)
- Read: [TESTING.md](TESTING.md)
- Run: `make help`
