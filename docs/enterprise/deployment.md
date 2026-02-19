# Enterprise Deployment Guide

This guide covers enterprise-grade deployment of JA4 Proxy with high availability, security hardening, and operational procedures.

## Architecture Overview

### Multi-Tier Architecture

```
Internet
    │
    ▼
┌─────────────────────────────────────────────────┐
│                Load Balancer                     │
│              (HAProxy Cluster)                   │
└─────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────┐
│              DMZ Network                         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐│
│  │ JA4 Proxy 1 │ │ JA4 Proxy 2 │ │ JA4 Proxy N ││
│  │             │ │             │ │             ││
│  └─────────────┘ └─────────────┘ └─────────────┘│
└─────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────┐
│              Backend Network                     │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐│
│  │ Backend 1   │ │ Backend 2   │ │ Backend N   ││
│  └─────────────┘ └─────────────┘ └─────────────┘│
└─────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────┐
│              Data Layer                          │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐│
│  │ Redis       │ │ Monitoring  │ │ Logging     ││
│  │ Cluster     │ │ Stack       │ │ Stack       ││
│  └─────────────┘ └─────────────┘ └─────────────┘│
└─────────────────────────────────────────────────┘
```

## Prerequisites

### Hardware Requirements

**Minimum Configuration (Development):**
- CPU: 4 cores
- RAM: 8GB
- Storage: 50GB SSD
- Network: 1Gbps

**Recommended Configuration (Production):**
- CPU: 16+ cores
- RAM: 32GB+
- Storage: 500GB+ NVMe SSD
- Network: 10Gbps+

**High-Load Configuration:**
- CPU: 32+ cores
- RAM: 64GB+
- Storage: 1TB+ NVMe SSD (RAID 10)
- Network: 25Gbps+

### Software Requirements

- **OS**: RHEL 8+, Ubuntu 20.04+, or CentOS Stream 8+
- **Container Runtime**: Docker 20.10+ or Podman 3.0+
- **Orchestration**: Docker Compose 2.0+ or Kubernetes 1.20+
- **Monitoring**: Prometheus, Grafana
- **Logging**: ELK Stack or similar

### Network Requirements

```
Port Mapping:
- 80/443 (HTTP/HTTPS) - Load Balancer
- 8080 (Proxy) - Internal
- 6379/6380 (Redis) - Internal
- 9090 (Metrics) - Internal
- 3000 (Grafana) - Internal/VPN
- 5601 (Kibana) - Internal/VPN
```

## Security Hardening

### System Hardening

**1. User and Group Setup:**
```bash
# Create dedicated user
useradd -r -s /bin/false -d /var/lib/ja4proxy ja4proxy

# Create group
groupadd ja4proxy

# Set up directory permissions
mkdir -p /etc/ja4proxy /var/log/ja4proxy /var/lib/ja4proxy
chown -R ja4proxy:ja4proxy /etc/ja4proxy /var/log/ja4proxy /var/lib/ja4proxy
chmod 750 /etc/ja4proxy /var/log/ja4proxy /var/lib/ja4proxy
```

**2. SELinux Configuration:**
```bash
# Create SELinux policy
cat > ja4proxy.te << 'EOF'
module ja4proxy 1.0;

require {
    type unconfined_t;
    type http_port_t;
    class tcp_socket { bind listen };
}

allow unconfined_t http_port_t:tcp_socket { bind listen };
EOF

# Compile and load policy
checkmodule -M -m -o ja4proxy.mod ja4proxy.te
semodule_package -o ja4proxy.pp -m ja4proxy.mod
semodule -i ja4proxy.pp
```

**3. Firewall Configuration:**
```bash
# Configure firewalld
firewall-cmd --permanent --new-zone=ja4proxy
firewall-cmd --permanent --zone=ja4proxy --add-port=8080/tcp
firewall-cmd --permanent --zone=ja4proxy --add-port=9090/tcp
firewall-cmd --reload
```

### Container Security

**1. Dockerfile Security:**
```dockerfile
# Multi-stage build for security
FROM python:3.11-slim as builder
RUN apt-get update && apt-get install -y gcc libpcap-dev
COPY requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /wheels -r requirements.txt

FROM python:3.11-slim
# Security hardening
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap0.8 && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r proxy && \
    useradd -r -g proxy proxy

COPY --from=builder /wheels /wheels
RUN pip install --no-cache /wheels/*

# Remove package manager
RUN apt-get purge -y --auto-remove apt && \
    rm -rf /var/lib/apt/lists/*

# Set up application
WORKDIR /app
COPY --chown=proxy:proxy proxy.py .
COPY --chown=proxy:proxy config/ config/

# Security settings
USER proxy
EXPOSE 8080 9090
HEALTHCHECK --interval=30s --timeout=10s CMD python -c "import socket; s=socket.socket(); s.connect(('localhost', 8080)); s.close()"
```

**2. Runtime Security:**
```yaml
# docker compose security settings
services:
  proxy:
    security_opt:
      - no-new-privileges:true
      - apparmor:docker-default
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    ulimits:
      nproc: 1024
      nofile: 65536
```

### TLS Configuration

**1. Certificate Management:**
```bash
# Create CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=JA4Proxy-CA"

# Create server certificate
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=ja4proxy.example.com"
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt

# Set proper permissions
chmod 600 *.key
chmod 644 *.crt
```

**2. TLS Configuration:**
```yaml
# Proxy TLS settings
proxy:
  tls:
    enabled: true
    cert_path: /etc/ssl/certs/server.crt
    key_path: /etc/ssl/private/server.key
    protocols:
      - TLSv1.2
      - TLSv1.3
    ciphers:
      - ECDHE-RSA-AES256-GCM-SHA384
      - ECDHE-RSA-AES128-GCM-SHA256
      - ECDHE-RSA-AES256-SHA384
    options:
      - no_sslv2
      - no_sslv3
      - no_tlsv1
      - no_tlsv1_1
```

## High Availability Setup

### Load Balancer Configuration

**HAProxy Configuration (`haproxy.cfg`):**
```
global
    daemon
    maxconn 4096
    log stdout local0
    
    # Security
    chroot /var/lib/haproxy
    user haproxy
    group haproxy
    
    # TLS 1.2+ only — strong ciphers, no RC4/DES/3DES/CBC
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
    ssl-default-bind-ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
    ssl-default-server-options ssl-min-ver TLSv1.2 no-tls-tickets
    ssl-default-server-ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    tune.ssl.default-dh-param 2048

defaults
    mode tcp
    timeout connect 10s
    timeout client 30s
    timeout server 30s
    option tcplog
    option dontlognull
    retries 3

# TLS passthrough — preserves ClientHello for JA4 fingerprinting
frontend tls_in
    bind *:443
    default_backend ja4proxy_backend
    option tcplog

# TLS-terminated management endpoint
frontend tls_managed
    bind *:8443 ssl crt /etc/ssl/certs/haproxy.pem alpn h2,http/1.1
    mode http
    http-response set-header Strict-Transport-Security max-age=31536000
    http-response set-header X-Content-Type-Options nosniff
    http-response set-header X-Frame-Options DENY
    default_backend ja4proxy_backend_http

frontend http_in
    bind *:80
    mode http
    acl is_health path /haproxy-health
    http-request return status 200 content-type text/plain string "OK" if is_health
    default_backend ja4proxy_backend_http

backend ja4proxy_backend
    balance roundrobin
    server proxy1 proxy-1:8080 send-proxy-v2 check inter 5s fall 3 rise 2
    server proxy2 proxy-2:8080 send-proxy-v2 check inter 5s fall 3 rise 2
    server proxy3 proxy-3:8080 send-proxy-v2 check inter 5s fall 3 rise 2

backend ja4proxy_backend_http
    mode http
    balance roundrobin
    server proxy1 proxy-1:8080 check inter 5s fall 3 rise 2
    server proxy2 proxy-2:8080 check inter 5s fall 3 rise 2
    server proxy3 proxy-3:8080 check inter 5s fall 3 rise 2

# mTLS to backend with certificate pinning
backend ja4proxy_backend_mtls
    mode http
    server proxy1 proxy-1:8443 ssl verify required ca-file /etc/ssl/certs/ca.crt crt /etc/ssl/certs/haproxy-client.pem

listen stats
    bind *:8404 ssl crt /etc/ssl/certs/haproxy.pem
    mode http
    stats enable
    stats uri /stats
    stats refresh 10s
    stats admin if TRUE
    # Log TLS handshake failures
    option httplog
    log-format "%ci:%cp [%t] %ft %ST %B %ts sslv:%sslv sslc:%sslc %{+Q}r"
```

### Redis Cluster Setup

**Redis Cluster Configuration:**
```bash
# Initialize Redis cluster
redis-cli --cluster create \
  redis-1:6379 redis-2:6379 redis-3:6379 \
  redis-4:6379 redis-5:6379 redis-6:6379 \
  --cluster-replicas 1 \
  --cluster-yes
```

**Redis Configuration (`redis.conf`):**
```
# Network
bind 0.0.0.0
port 6379
protected-mode yes
tcp-backlog 511
timeout 300
tcp-keepalive 300

# Cluster
cluster-enabled yes
cluster-config-file nodes-6379.conf
cluster-node-timeout 15000
cluster-migration-barrier 1
cluster-require-full-coverage yes

# Memory
maxmemory 2gb
maxmemory-policy allkeys-lru

# Persistence
save 900 1
save 300 10
save 60 10000
rdbcompression yes
rdbchecksum yes

# Security
requirepass ${REDIS_PASSWORD}
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command DEBUG ""

# TLS
tls-port 6380
tls-cert-file /etc/ssl/certs/redis.crt
tls-key-file /etc/ssl/private/redis.key
tls-ca-cert-file /etc/ssl/certs/ca.crt
```

## Monitoring and Observability

### Prometheus Configuration

**Prometheus Config (`prometheus.yml`):**
```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "ja4proxy_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'ja4proxy'
    static_configs:
      - targets:
        - proxy-1:9090
        - proxy-2:9090
        - proxy-3:9090
    metrics_path: /metrics
    scrape_interval: 5s

  - job_name: 'redis'
    static_configs:
      - targets:
        - redis-exporter-1:9121
        - redis-exporter-2:9121
        - redis-exporter-3:9121

  - job_name: 'haproxy'
    static_configs:
      - targets:
        - haproxy-exporter:9101
```

**Alert Rules (`ja4proxy_rules.yml`):**
```yaml
groups:
  - name: ja4proxy.rules
    rules:
    - alert: JA4ProxyHighLatency
      expr: histogram_quantile(0.95, ja4_request_duration_seconds_bucket) > 0.1
      for: 2m
      labels:
        severity: warning
      annotations:
        summary: "JA4 Proxy high latency detected"
        
    - alert: JA4ProxyHighBlockedRequests
      expr: rate(ja4_blocked_requests_total[5m]) > 10
      for: 1m
      labels:
        severity: critical
      annotations:
        summary: "High number of blocked requests"
        
    - alert: JA4ProxyDown
      expr: up{job="ja4proxy"} == 0
      for: 1m
      labels:
        severity: critical
      annotations:
        summary: "JA4 Proxy instance is down"
```

### Grafana Dashboards

**Dashboard Configuration:**
```json
{
  "dashboard": {
    "title": "JA4 Proxy Dashboard",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(ja4_requests_total[5m])",
            "legendFormat": "{{action}} requests/sec"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, ja4_request_duration_seconds_bucket)",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Active Connections",
        "type": "singlestat",
        "targets": [
          {
            "expr": "ja4_active_connections",
            "legendFormat": "Connections"
          }
        ]
      }
    ]
  }
}
```

### Log Management

**Logstash Configuration:**
```yaml
input {
  beats {
    port => 5044
  }
  
  file {
    path => "/var/log/ja4proxy/*.log"
    start_position => "beginning"
    codec => "json"
  }
}

filter {
  if [fields][service] == "ja4proxy" {
    grok {
      match => { 
        "message" => "%{TIMESTAMP_ISO8601:timestamp} - %{WORD:logger} - %{LOGLEVEL:level} - %{GREEDYDATA:message}" 
      }
    }
    
    date {
      match => [ "timestamp", "ISO8601" ]
    }
    
    if [ja4] {
      mutate {
        add_field => { "fingerprint_hash" => "%{ja4}" }
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "ja4proxy-%{+YYYY.MM.dd}"
  }
}
```

## Deployment Procedures

### Initial Deployment

**1. Environment Preparation:**
```bash
#!/bin/bash
# deploy.sh

set -euo pipefail

# Variables
ENVIRONMENT=${1:-production}
VERSION=${2:-latest}

echo "Deploying JA4 Proxy ${VERSION} to ${ENVIRONMENT}"

# Create directories
mkdir -p /opt/ja4proxy/{config,logs,ssl,secrets}
mkdir -p /var/log/ja4proxy

# Set permissions
chown -R ja4proxy:ja4proxy /opt/ja4proxy /var/log/ja4proxy
chmod 750 /opt/ja4proxy /var/log/ja4proxy

# Copy configuration
cp config/${ENVIRONMENT}.yml /opt/ja4proxy/config/proxy.yml
cp ssl/* /opt/ja4proxy/ssl/
cp secrets/* /opt/ja4proxy/secrets/

# Deploy stack
docker compose -f docker-compose.${ENVIRONMENT}.yml pull
docker compose -f docker-compose.${ENVIRONMENT}.yml up -d

# Health checks
sleep 30
./scripts/health-check.sh

echo "Deployment complete"
```

**2. Health Check Script:**
```bash
#!/bin/bash
# health-check.sh

set -euo pipefail

PROXY_URL=${PROXY_URL:-http://localhost:8080}
METRICS_URL=${METRICS_URL:-http://localhost:9090}

echo "Running health checks..."

# Check proxy health
if curl -sf "${PROXY_URL}/health" > /dev/null; then
    echo "✓ Proxy health check passed"
else
    echo "✗ Proxy health check failed"
    exit 1
fi

# Check metrics
if curl -sf "${METRICS_URL}/metrics" | grep -q "ja4_requests_total"; then
    echo "✓ Metrics check passed"
else
    echo "✗ Metrics check failed"
    exit 1
fi

# Check Redis connectivity
if docker exec ja4proxy-redis-1 redis-cli ping | grep -q "PONG"; then
    echo "✓ Redis connectivity check passed"
else
    echo "✗ Redis connectivity check failed"
    exit 1
fi

echo "All health checks passed"
```

### Rolling Updates

**Rolling Update Script:**
```bash
#!/bin/bash
# rolling-update.sh

set -euo pipefail

NEW_VERSION=${1}
INSTANCES=(proxy-1 proxy-2 proxy-3)

echo "Starting rolling update to version ${NEW_VERSION}"

for instance in "${INSTANCES[@]}"; do
    echo "Updating ${instance}..."
    
    # Stop instance
    docker stop "ja4proxy-${instance}"
    
    # Update image
    docker compose pull proxy
    
    # Start instance
    docker compose up -d "proxy-${instance}"
    
    # Wait for health check
    sleep 30
    
    # Verify instance is healthy
    if ! ./scripts/health-check.sh; then
        echo "Health check failed for ${instance}"
        exit 1
    fi
    
    echo "✓ ${instance} updated successfully"
done

echo "Rolling update completed"
```

### Backup Procedures

**Backup Script:**
```bash
#!/bin/bash
# backup.sh

set -euo pipefail

BACKUP_DIR="/backup/ja4proxy"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "${BACKUP_DIR}/${DATE}"

echo "Starting backup at ${DATE}"

# Backup Redis data
docker exec ja4proxy-redis-1 redis-cli BGSAVE
sleep 5
docker cp ja4proxy-redis-1:/data/dump.rdb "${BACKUP_DIR}/${DATE}/"

# Backup configuration
cp -r /opt/ja4proxy/config "${BACKUP_DIR}/${DATE}/"

# Backup SSL certificates
cp -r /opt/ja4proxy/ssl "${BACKUP_DIR}/${DATE}/"

# Backup logs (last 7 days)
find /var/log/ja4proxy -name "*.log" -mtime -7 -exec cp {} "${BACKUP_DIR}/${DATE}/" \;

# Create archive
cd "${BACKUP_DIR}"
tar -czf "ja4proxy_backup_${DATE}.tar.gz" "${DATE}/"
rm -rf "${DATE}"

# Cleanup old backups (keep 30 days)
find "${BACKUP_DIR}" -name "ja4proxy_backup_*.tar.gz" -mtime +30 -delete

echo "Backup completed: ja4proxy_backup_${DATE}.tar.gz"
```

## Maintenance Procedures

### Regular Maintenance Tasks

**Daily Tasks:**
- Monitor system health
- Check log files for errors
- Verify backup completion
- Review security alerts

**Weekly Tasks:**
- Update threat intelligence feeds
- Review performance metrics
- Clean up old log files
- Security patch assessment

**Monthly Tasks:**
- Security vulnerability assessment
- Capacity planning review
- Configuration backup verification
- Disaster recovery testing

### Troubleshooting Procedures

**Performance Issues:**
```bash
# Check system resources
htop
iostat 1 10
netstat -tuln | grep :8080

# Check proxy metrics
curl http://localhost:9090/metrics | grep ja4_

# Check Redis performance
redis-cli --latency-history -h redis-1

# Check container resources
docker stats ja4proxy-*
```

**Connection Issues:**
```bash
# Test proxy connectivity
telnet localhost 8080

# Check backend connectivity
curl -H "Host: backend.example.com" http://localhost:8080/

# Review proxy logs
docker logs ja4proxy-1 | tail -100

# Check network configuration
ip route
iptables -L -n
```

## Security Compliance

### Compliance Frameworks

**SOC 2 Type II:**
- Access controls implemented
- Audit logging enabled
- Data encryption at rest and in transit
- Change management procedures
- Incident response procedures

**PCI DSS:**
- Network segmentation
- Strong access controls
- Regular vulnerability scans
- Secure development practices
- Monitoring and logging

**GDPR:**
- Data minimization
- Encryption of personal data
- Right to erasure implementation
- Data breach notification procedures
- Privacy by design

### Audit Procedures

**Security Audit Checklist:**
- [ ] All services running as non-root
- [ ] TLS encryption properly configured
- [ ] Access controls implemented
- [ ] Audit logging enabled
- [ ] Security patches up to date
- [ ] Firewall rules configured
- [ ] Monitoring and alerting active
- [ ] Backup and recovery tested

**Compliance Reporting:**
```bash
#!/bin/bash
# compliance-report.sh

echo "JA4 Proxy Compliance Report - $(date)"
echo "========================================"

echo "1. Access Controls:"
echo "   - Non-root execution: $(docker exec ja4proxy-1 whoami)"
echo "   - File permissions: $(ls -la /opt/ja4proxy/)"

echo "2. Encryption:"
echo "   - TLS enabled: $(grep -q "tls:" /opt/ja4proxy/config/proxy.yml && echo "Yes" || echo "No")"
echo "   - Redis TLS: $(docker exec ja4proxy-redis-1 redis-cli CONFIG GET tls-port)"

echo "3. Monitoring:"
echo "   - Prometheus: $(curl -s http://localhost:9091/api/v1/query?query=up | grep -q "success" && echo "Active" || echo "Down")"
echo "   - Log retention: $(find /var/log/ja4proxy -name "*.log" | wc -l) files"

echo "4. Backup:"
echo "   - Last backup: $(ls -t /backup/ja4proxy/*.tar.gz | head -1)"
```

This enterprise deployment guide provides comprehensive procedures for deploying, maintaining, and securing JA4 Proxy in enterprise environments with full compliance and operational excellence.