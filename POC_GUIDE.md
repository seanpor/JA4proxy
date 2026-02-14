# JA4 Proxy - Proof of Concept (POC) Guide

This guide explains how to run the JA4 Proxy POC environment entirely in Docker containers.

## Overview

The POC environment includes:
- **JA4 Proxy Server**: Main proxy application with JA4 fingerprinting
- **Redis**: Caching and storage backend
- **Mock Backend Server**: Test HTTP server that simulates backend services
- **Prometheus**: Metrics collection and monitoring
- **Test Container**: Runs all tests in isolated environment

All components run in Docker containers - **no local installation of Python or dependencies required**.

## Prerequisites

- Docker 20.10 or later
- Docker Compose 2.0 or later
- 4GB RAM minimum (8GB recommended)
- 2GB free disk space

### Installing Docker

**Ubuntu/Debian:**
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
# Log out and back in
```

**macOS:**
```bash
brew install --cask docker
```

**Windows:**
Download Docker Desktop from https://www.docker.com/products/docker-desktop

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/JA4proxy.git
cd JA4proxy
```

### 2. Start the POC Environment

```bash
./start-poc.sh
```

This script will:
- Build all Docker images
- Start all services
- Wait for services to be healthy
- Display service URLs and commands

**Expected output:**
```
==========================================
JA4 Proxy POC Environment
==========================================

Starting services...
Waiting for services to be ready...
Checking Redis... ✓
Checking Backend... ✓
Checking Proxy... ✓
Checking Prometheus... ✓

==========================================
✓ All services are running!
==========================================

Service URLs:
  Proxy:       http://localhost:8080
  Metrics:     http://localhost:9090/metrics
  Backend:     http://localhost:8081
  Prometheus:  http://localhost:9091
```

### 3. Verify Services

```bash
# Check proxy metrics
curl http://localhost:9090/metrics

# Check backend health
curl http://localhost:8081/api/health

# Check Redis
docker exec ja4proxy-redis redis-cli -a changeme ping
```

### 4. Run Tests

```bash
./run-tests.sh
```

This runs the complete test suite in a Docker container and generates coverage reports.

## Architecture

```
┌─────────────────────┐
│   Test Container    │  (runs on demand)
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐    ┌─────────────────────┐
│   JA4 Proxy         │◄──►│   Mock Backend      │
│   :8080 (proxy)     │    │   :8081 (http)      │
│   :9090 (metrics)   │    └─────────────────────┘
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   Redis Cache       │
│   :6379             │
└─────────────────────┘
           │
           ▼
┌─────────────────────┐
│   Prometheus        │
│   :9091             │
└─────────────────────┘
```

## Mock Backend Server

The mock backend provides various test endpoints:

### Endpoints

- `GET /` - HTML homepage
- `GET /api/health` - Health check endpoint
- `GET /api/echo` - Echo request details (headers, method, etc.)
- `GET /delay/<seconds>` - Delayed response (max 10 seconds)
- `GET /status/<code>` - Return specific HTTP status code
- `POST /api/echo` - Echo POST data

### Testing the Backend

```bash
# Health check
curl http://localhost:8081/api/health

# Echo endpoint
curl http://localhost:8081/api/echo

# Delayed response (3 seconds)
curl http://localhost:8081/delay/3

# Specific status code
curl http://localhost:8081/status/404
```

## Running Tests

### Full Test Suite

```bash
./run-tests.sh
```

This runs all tests and generates reports in `./reports/`.

### Manual Test Execution

```bash
# Run all tests
docker-compose -f docker-compose.poc.yml run --rm test

# Run specific test file
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/test_proxy.py -v

# Run unit tests only
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/unit/ -v

# Run integration tests
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/integration/ -v

# Run with coverage
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/ -v --cov=proxy --cov-report=html:/app/reports/coverage
```

### Test Reports

After running tests, reports are available in:
- `./reports/coverage/index.html` - HTML coverage report
- `./reports/junit.xml` - JUnit XML report

View coverage report:
```bash
# Linux
xdg-open reports/coverage/index.html

# macOS
open reports/coverage/index.html

# Windows
start reports/coverage/index.html
```

## Common Operations

### View Logs

```bash
# All services
docker-compose -f docker-compose.poc.yml logs -f

# Specific service
docker-compose -f docker-compose.poc.yml logs -f proxy
docker-compose -f docker-compose.poc.yml logs -f backend
docker-compose -f docker-compose.poc.yml logs -f redis
```

### Restart Services

```bash
# Restart all
docker-compose -f docker-compose.poc.yml restart

# Restart specific service
docker-compose -f docker-compose.poc.yml restart proxy
```

### Stop Services

```bash
# Stop all services
docker-compose -f docker-compose.poc.yml down

# Stop and remove volumes
docker-compose -f docker-compose.poc.yml down -v
```

### Access Redis CLI

```bash
docker exec -it ja4proxy-redis redis-cli -a changeme

# Example commands:
# KEYS *
# GET ja4:fingerprint:*
# SADD ja4:whitelist "t13d1516h2_8daaf6152771_02713d6af862"
```

### Rebuild Images

```bash
# Rebuild all images
docker-compose -f docker-compose.poc.yml build

# Rebuild specific service
docker-compose -f docker-compose.poc.yml build proxy

# Rebuild without cache
docker-compose -f docker-compose.poc.yml build --no-cache
```

## Makefile Targets

The project includes a Makefile for common operations:

```bash
make help              # Show all available targets
make build             # Build Docker images
make deploy-poc        # Start POC environment (same as ./start-poc.sh)
make test              # Run tests (same as ./run-tests.sh)
make test-unit         # Run unit tests only
make test-integration  # Run integration tests only
make health-check      # Check service health
make logs              # View proxy logs
make stop              # Stop all services
make clean             # Clean up containers, volumes, and reports
```

## Troubleshooting

### Services Won't Start

```bash
# Check Docker is running
docker info

# Check logs
docker-compose -f docker-compose.poc.yml logs

# Clean up and restart
docker-compose -f docker-compose.poc.yml down -v
./start-poc.sh
```

### Port Conflicts

If ports are already in use, you can modify them in `docker-compose.poc.yml`:

```yaml
services:
  proxy:
    ports:
      - "8080:8080"  # Change left side: "8888:8080"
```

### Tests Failing

```bash
# Ensure services are running
./start-poc.sh

# Check service health
make health-check

# View test output
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/ -v -s

# Run single test for debugging
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/test_proxy.py::TestJA4Fingerprint::test_fingerprint_creation -v -s
```

### Redis Connection Issues

```bash
# Check Redis is running
docker ps | grep redis

# Test Redis connection
docker exec ja4proxy-redis redis-cli -a changeme ping

# Check Redis logs
docker-compose -f docker-compose.poc.yml logs redis
```

### Permission Issues

```bash
# Fix reports directory permissions
sudo chown -R $USER:$USER reports/

# Clean up and restart
make clean
./start-poc.sh
```

## Environment Variables

You can customize the environment using a `.env` file:

```bash
# Create .env file
cat > .env << EOF
REDIS_PASSWORD=your-secure-password
ENVIRONMENT=development
EOF
```

## Security Notes

The POC environment uses default passwords and is **not suitable for production**:
- Redis password: `changeme`
- No TLS/SSL encryption
- Services exposed on localhost

For production deployment, see the [Enterprise Deployment Guide](docs/enterprise/deployment.md).

## Next Steps

After verifying the POC works:

1. **Review the code**: Examine `proxy.py` to understand JA4 fingerprinting
2. **Explore tests**: Review `tests/` to see test coverage
3. **Check monitoring**: Open Prometheus at http://localhost:9091
4. **Read documentation**: See `docs/` for detailed documentation
5. **Production deployment**: See `docker-compose.prod.yml` for production setup

## Cleaning Up

To completely remove the POC environment:

```bash
# Stop and remove containers and volumes
docker-compose -f docker-compose.poc.yml down -v

# Remove images
docker rmi ja4proxy:latest ja4proxy-test:latest

# Clean up reports
rm -rf reports/
```

## Getting Help

- Check logs: `docker-compose -f docker-compose.poc.yml logs`
- Run health checks: `make health-check`
- View metrics: `curl http://localhost:9090/metrics`
- Open an issue: https://github.com/yourusername/JA4proxy/issues
