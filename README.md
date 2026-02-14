*heads up* this repo is ai generated... take with a grain of salt until tested properly.

# JA4 Proxy - TLS Fingerprinting Proxy Server

JA4 Proxy is a high-performance, security-focused proxy server that implements JA4/JA4+ TLS fingerprinting for advanced traffic analysis, filtering, and security enforcement.

## Features

### Core Functionality
- **JA4 TLS Fingerprinting**: Complete implementation of JA4 and JA4+ fingerprinting
- **High-Performance Proxy**: Asynchronous proxy server with connection pooling
- **Security Filtering**: Whitelist/blacklist enforcement with rate limiting
- **TARPIT Integration**: Slow down malicious clients
- **Redis Backend**: Distributed caching and storage
- **Prometheus Metrics**: Comprehensive observability
- **Docker Support**: Container-ready with orchestration

### Security Features
- **TLS Fingerprint Analysis**: Real-time JA4 generation and matching
- **Rate Limiting**: Per-IP and global rate limiting
- **Geo-blocking**: Country-based access control
- **Audit Logging**: Complete security audit trails
- **Threat Intelligence**: Integration with threat feeds
- **Security Hardening**: Non-root execution, read-only filesystem

### Enterprise Features
- **High Availability**: Multi-node deployment with load balancing
- **Monitoring Stack**: Prometheus, Grafana, ELK integration
- **Compliance**: GDPR, PCI-DSS ready configurations
- **Operational Tools**: Health checks, diagnostics, management APIs
- **Performance Tuning**: Optimized for enterprise workloads

## Quick Start

### Prerequisites
- Docker 20.10+
- Docker Compose 2.0+
- 4GB RAM minimum, 8GB recommended
- 2GB free disk space

**No local Python installation required** - everything runs in Docker containers.

### PoC Installation (Docker Only)

1. **Clone the repository:**
```bash
git clone https://github.com/yourusername/JA4proxy.git
cd JA4proxy
```

2. **Start the PoC environment:**
```bash
./start-poc.sh
```

This will start:
- JA4 Proxy server (port 8080, metrics on 9090)
- Redis cache (port 6379)
- Mock backend server (port 8081)
- Prometheus monitoring (port 9091)

3. **Verify installation:**
```bash
# Run quick smoke test
./smoke-test.sh

# Or check individual services
curl http://localhost:9090/metrics        # Proxy metrics
curl http://localhost:8081/api/health     # Backend health
docker exec ja4proxy-redis redis-cli -a changeme ping  # Redis
```

### Running Tests

All tests run in Docker containers:

```bash
# Run full test suite
./run-tests.sh

# Or manually with docker-compose
docker-compose -f docker-compose.poc.yml run --rm test

# View test reports
open reports/coverage/index.html
```

### Development Workflow

```bash
# Start services
./start-poc.sh

# View logs
docker-compose -f docker-compose.poc.yml logs -f proxy

# Run tests after changes
./run-tests.sh

# Run quick smoke test
./smoke-test.sh

# Stop services
docker-compose -f docker-compose.poc.yml down

# Clean up everything (including volumes)
docker-compose -f docker-compose.poc.yml down -v
```

### Using Make

The Makefile provides convenient shortcuts:

```bash
make help              # Show all commands
make deploy-poc        # Start POC environment
make test              # Run tests
make test-unit         # Run unit tests only
make test-integration  # Run integration tests
make smoke-test        # Run quick smoke test
make logs              # View proxy logs
make health-check      # Check service health
make stop              # Stop services
make clean             # Clean up containers and volumes
```

For detailed POC documentation, see [POC_GUIDE.md](POC_GUIDE.md).

### Enterprise Installation

1. **Prepare environment:**
```bash
# Create secrets
mkdir -p secrets ssl
echo "your-redis-password" > secrets/redis_password.txt

# Generate SSL certificates
openssl req -x509 -newkey rsa:4096 -keyout ssl/private/proxy.key \
  -out ssl/certs/proxy.crt -days 365 -nodes
```

2. **Deploy enterprise stack:**
```bash
docker-compose -f docker-compose.prod.yml up -d
```

3. **Configure load balancer:**
```bash
# Access HAProxy stats
curl http://localhost:8404/stats
```

## Configuration

### Basic Configuration (`config/proxy.yml`)

```yaml
proxy:
  bind_host: "0.0.0.0"
  bind_port: 8080
  backend_host: "backend"
  backend_port: 80
  max_connections: 1000

redis:
  host: "redis"
  port: 6379
  password: null

security:
  whitelist_enabled: true
  blacklist_enabled: true
  rate_limiting: true
  max_requests_per_minute: 100
```

### Enterprise Configuration (`config/enterprise.yml`)

```yaml
proxy:
  bind_host: "0.0.0.0"
  bind_port: 8080
  max_connections: 10000
  security_context:
    user: "proxy"
    group: "proxy"

redis:
  mode: "cluster"
  nodes:
    - host: "redis-1"
      port: 6379
  ssl_enabled: true

security:
  audit_logging: true
  threat_intelligence: true
  geo_blocking: true
  allowed_countries: ["US", "CA", "GB"]
```

## Usage

### Managing Security Lists

**Add to whitelist:**
```bash
redis-cli SADD ja4:whitelist "t13d1516h2_8daaf6152771_02713d6af862"
```

**Add to blacklist:**
```bash
redis-cli SADD ja4:blacklist "t12d090909_ba640532068b_b186095e22b6"
```

**View current fingerprints:**
```bash
redis-cli KEYS "ja4:fingerprint:*"
```

### Monitoring

**Check metrics:**
```bash
curl http://localhost:9090/metrics
```

**View logs:**
```bash
docker-compose logs -f proxy
```

**Health check:**
```bash
curl http://localhost:8080/health
```

### Testing

**Run unit tests:**
```bash
./run-tests.sh
```

**Run specific test suite:**
```bash
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/unit/ -v
```

**Performance testing:**
```bash
# Start services first
./start-poc.sh

# Run performance tests (requires locust installed locally or in container)
docker-compose -f docker-compose.poc.yml run --rm test locust -f /app/performance/locust_tests.py --host http://proxy:8080
```

**Integration testing:**
```bash
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/integration/ -v
```

## Documentation

### Getting Started
- **[Quick Reference](docs/QUICK_REFERENCE.md)** - Command cheat sheet
- **[POC Guide](docs/POC_GUIDE.md)** - Detailed POC setup and usage
- **[Testing Guide](docs/TESTING.md)** - Complete testing documentation
- **[Executive Summary](docs/EXEC_SUMMARY.md)** - High-level overview

### Security Documentation
- **[Security Checklist](docs/security/SECURITY_CHECKLIST.md)** - Security audit checklist
- **[Security Analysis](docs/security/SECURITY_ANALYSIS_REPORT.md)** - Detailed security analysis
- **[Security Fixes](docs/security/SECURITY_FIXES.md)** - Implemented security fixes

### Archive
- **[Change History](docs/archive/)** - Historical change logs and migration notes

## Architecture

### System Architecture

```
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│                     │    │                     │    │                     │
│     Client          │◄──►│   JA4 Proxy        │◄──►│   Backend Server    │
│                     │    │                     │    │                     │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
                                       │
                                       ▼
                           ┌─────────────────────┐
                           │                     │
                           │   Redis Cache       │
                           │   Security Lists    │
                           │                     │
                           └─────────────────────┘
                                       │
                                       ▼
                           ┌─────────────────────┐
                           │                     │
                           │   Monitoring        │
                           │   Prometheus        │
                           │                     │
                           └─────────────────────┘
```

For detailed documentation, see [docs/](docs/)
