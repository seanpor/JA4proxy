# JA4proxy Quick Start Guide

This guide shows you how to quickly spin up the JA4proxy POC environment and run regression and performance tests.

## Prerequisites

- Docker and Docker Compose installed
- 8GB RAM and 2 CPU cores recommended
- Ports 8080, 9090, 6379, 8081 available

## 🚀 One-Command Quick Start

The easiest way to get started:

```bash
make quick-start
```

This will:
- ✅ Generate secure Redis password
- 🚀 Start all POC services (proxy, Redis, backend, monitoring)
- 🔍 Run health checks
- 🧪 Execute regression tests
- 🏃 Run basic performance tests
- 📊 Show service URLs and credentials

## Manual Steps

If you prefer to run each step manually:

### 1. Start POC Environment
```bash
# Generate secure password
export REDIS_PASSWORD=$(openssl rand -base64 32)

# Start services
docker-compose -f docker-compose.poc.yml up -d

# Wait for startup (30 seconds)
sleep 30
```

### 2. Run Tests
```bash
# All tests
make test

# Individual test suites
make test-unit           # Unit tests
make test-integration    # Integration tests
make test-performance    # Performance tests
make test-security       # Security tests
```

### 3. Check Health
```bash
make health-check
```

## Service Access

Once running, access these services:

| Service | URL | Purpose |
|---------|-----|---------|
| **Proxy** | http://localhost:8080 | Main proxy service |
| **Metrics** | http://localhost:9090/metrics | Prometheus metrics |
| **Backend** | http://localhost:8081 | Test backend (nginx) |
| **Redis** | localhost:6379 | Cache/storage (auth required) |

## Performance Testing

### Basic Performance Test
```bash
# Built-in basic test (no dependencies)
./scripts/basic_perf_test.sh

# Custom parameters
./scripts/basic_perf_test.sh http://localhost:8080 20 15
# (URL, concurrent users, requests per user)
```

### Advanced Performance Test (with Locust)
```bash
# Install Locust first
pip install locust

# Run advanced test
make test-performance

# Custom Locust test
locust -f performance/locust_tests.py --host http://localhost:8080 \
    --users 100 --spawn-rate 10 --run-time 5m --headless
```

## Security Testing

```bash
# Run security vulnerability scan
make security-scan

# Run security-specific tests
make test-security
```

## Logs and Monitoring

```bash
# View live logs
docker-compose -f docker-compose.poc.yml logs -f

# View specific service logs
docker-compose -f docker-compose.poc.yml logs -f proxy

# Check container status
docker-compose -f docker-compose.poc.yml ps
```

## Cleanup

```bash
# Stop and remove all containers
make clean

# Or manually
docker-compose -f docker-compose.poc.yml down -v --remove-orphans
```

## Troubleshooting

### Common Issues

**Port conflicts:**
```bash
# Check what's using the ports
sudo netstat -tlnp | grep ':8080\|:9090\|:6379\|:8081'

# Kill conflicting processes or change ports in docker-compose.poc.yml
```

**Services not starting:**
```bash
# Check container logs
docker-compose -f docker-compose.poc.yml logs

# Rebuild containers
make build
```

**Redis authentication errors:**
```bash
# Check Redis password is set
echo $REDIS_PASSWORD

# Test Redis connection
docker-compose -f docker-compose.poc.yml exec redis redis-cli -a "$REDIS_PASSWORD" ping
```

**Performance test failures:**
```bash
# Check proxy is responding
curl -v http://localhost:8080/

# Check system resources
docker stats
```

## Environment Variables

Key environment variables you can customize:

```bash
# Security
export REDIS_PASSWORD="your_secure_password_here"

# Performance
export MAX_CONNECTIONS=1000
export RATE_LIMIT=1000

# Environment
export ENVIRONMENT="development"  # or "staging", "production"

# Logging
export LOG_LEVEL="INFO"  # or "DEBUG", "WARNING", "ERROR"
```

## Reports

Test results and reports are saved to the `reports/` directory:

- `reports/coverage/` - Code coverage reports
- `reports/performance.html` - Performance test results  
- `reports/basic_performance.html` - Basic performance results
- `reports/security/` - Security scan reports

## Next Steps

1. **Review Security Analysis**: Check `SECURITY_VULNERABILITY_ANALYSIS.md`
2. **Production Deployment**: Use `docker-compose.prod.yml` for production
3. **Configuration**: Customize `config/proxy.yml` for your needs
4. **Monitoring**: Set up Grafana dashboards for the metrics
5. **SSL/TLS**: Configure proper certificates for production

## Support

If you encounter issues:

1. Check the troubleshooting section above
2. Review service logs: `docker-compose -f docker-compose.poc.yml logs`
3. Check the main README.md for detailed documentation
4. Review security considerations in the security analysis report