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
- Python 3.11+
- Docker and Docker Compose
- Redis (or use Docker container)
- 4GB RAM minimum, 8GB recommended

### PoC Installation

1. **Clone and setup:**
```bash
git clone https://github.com/yourusername/JA4proxy.git
cd JA4proxy
pip install -r requirements.txt
```

2. **Start PoC environment:**
```bash
docker-compose -f docker-compose.poc.yml up -d
```

3. **Verify installation:**
```bash
curl http://localhost:8080/health
curl http://localhost:9090/metrics
```

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
pytest tests/ -v --cov=proxy
```

**Performance testing:**
```bash
locust -f performance/locust_tests.py --host http://localhost:8080
```

**Load testing:**
```bash
python performance/locust_tests.py
```

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
