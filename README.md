# JA4proxy — TLS Fingerprinting Security Proxy

A security proxy that extracts [JA4 TLS fingerprints](https://github.com/FoxIO-LLC/ja4) from the plaintext ClientHello and blocks malicious traffic before it reaches your backend — without decrypting TLS.

> **Status:** POC ✅ Ready for demo &nbsp;|&nbsp; Production ⚠️ Requires hardening  
> **Security:** Auto-generated secrets, localhost-only ports, read-only containers. See [Security Checklist](docs/security/SECURITY_CHECKLIST.md).

## How It Works

```
Client ──TLS──▶ HAProxy (LB) ──TCP──▶ JA4proxy ×N ──TLS──▶ Backend (HTTPS)
                   :443                  :8080              :443
                                           │
                                   ┌───────┼───────┐
                                   ▼       ▼       ▼
                                 Redis   Tarpit  Prometheus
                                         :8888   Grafana/Loki
```

1. Client sends a TLS ClientHello (plaintext, before encryption)
2. JA4proxy reads the ClientHello, extracts the JA4 fingerprint
3. **Security pipeline** decides: allow, tarpit, block, or ban
4. Allowed traffic is forwarded unchanged — TLS handshake completes client↔backend
5. The proxy never decrypts, never holds keys

## Quick Start

```bash
# Start everything (proxy + monitoring + Grafana)
./start-all.sh

# Generate test traffic (30s, 10% legitimate, 20 workers)
./generate-tls-traffic.sh 30 10 20

# Open Grafana dashboard
open http://localhost:3001    # admin / password from .env
```

**That's it.** The dashboard shows allowed vs blocked traffic, JA4 fingerprint names, action distribution, and logs.

## Security Pipeline

Connections pass through 5 layers, in order:

| Layer | Check | Action |
|-------|-------|--------|
| 0 | **GeoIP country** | Block/allow by country (IP2Location) |
| 1 | **JA4 blacklist** | Instant TCP RST for known-bad fingerprints |
| 2 | **JA4 whitelist** | Skip rate limiting for known-good fingerprints |
| 2b | **Pattern whitelist** | `h2` ALPN = browser → skip rate limiting |
| 3 | **Rate limiting** | Per-IP, per-JA4, per-IP+JA4 pair thresholds |

Rate limiting escalates: **suspicious → tarpit → block → ban**.

## Services

| Service | URL | Notes |
|---------|-----|-------|
| HAProxy (LB) | `https://localhost:443` | TLS passthrough, PROXY protocol v2 |
| HAProxy stats | `http://localhost:8404/stats` | |
| JA4proxy | `http://localhost:8080` | Proxy + metrics on :9090 |
| Backend | `https://localhost:8443` | Protected HTTPS server |
| Tarpit | `http://localhost:8888` | 1 byte/sec slow drain |
| Prometheus | `http://localhost:9091` | |
| Grafana | `http://localhost:3001` | admin / see .env |
| Loki | `http://localhost:3100` | Centralized container logs (internal only) |
| Alertmanager | `http://localhost:9093` | |

## Configuration

All config is in [`config/proxy.yml`](config/proxy.yml). Key sections:

### Country Filtering (GeoIP)

```yaml
geoip:
  country_whitelist_enabled: true     # Only allow listed countries
  country_whitelist:
    - "IE"  # Ireland
    - "GB"  # United Kingdom
    - "IM"  # Isle of Man
    - "US"  # United States

  country_blacklist_enabled: true     # Block listed countries
  country_blacklist:
    - "KP"  # North Korea
    - "RU"  # Russia
```

### JA4 Fingerprint Lists

```yaml
security:
  whitelist:
    - "t13d1516h2_8daaf6152771_02713d6af862"  # Chrome

  whitelist_patterns:
    - "h2"  # Any browser with HTTP/2 ALPN

  blacklist:
    - "t13d190900_9dc949149365_97f8aa674fd9"  # Sliver C2
```

### Rate Limiting

```yaml
security:
  rate_limit_strategies:
    by_ip_ja4_pair:
      thresholds:
        suspicious: 2    # connections/sec
        block: 5
        ban: 8
      action: "tarpit"
```

## JA4 Fingerprint Names

The proxy decodes JA4 fingerprints into human-readable names automatically:

| JA4 Prefix | Classification | Example |
|------------|---------------|---------|
| `*h2*` | Browser (TLS 1.3) | Chrome, Firefox, Safari |
| `t13d*00*` | Tool/Bot (TLS 1.3) | Sliver C2, Evilginx |
| `t12d*00*` | Tool/Bot (TLS 1.2) | CobaltStrike, Python bot |

Names appear in logs, Prometheus metrics (`fingerprint_name` label), and Grafana panels.

Known fingerprints can be mapped to specific names in `config/proxy.yml` → `fingerprint_labels`.

## Logs

All container logs flow to **Loki** and are visible in Grafana. Proxy log format:

```
ALLOWED:  172.19.0.10 | Country: IE | JA4: t13d1113h2_... | Name: Browser (TLS 1.3) | TLS: TLS 1.3
BLOCKED:  185.220.0.1 | Country: RU | JA4: t13d0912...   | Name: Tool/Bot (TLS 1.3) | Reason: Banned for 604800s
```

View logs:
```bash
docker compose -f docker-compose.poc.yml logs -f proxy    # Proxy decisions
docker compose -f docker-compose.poc.yml logs -f backend   # Backend requests
docker compose -f docker-compose.monitoring.yml logs -f    # Monitoring stack
```

## Traffic Generator

Generates realistic TLS traffic with distinct fingerprints per client profile:

```bash
./generate-tls-traffic.sh <duration_secs> <legit_percent> <workers>

# Examples
./generate-tls-traffic.sh 60 10 20    # 60s, 10% good, 20 workers
./generate-tls-traffic.sh 300 5 50    # 5min stress test
```

Profiles: Chrome, Firefox, Safari (legitimate) + Sliver C2, CobaltStrike, Evilginx, Python bot, Credential stuffer (malicious).

## Documentation

- **[POC Quick Start](docs/POC_QUICKSTART.md)** — 5-minute setup guide
- **[POC Guide](docs/POC_GUIDE.md)** — Detailed usage
- **[Monitoring Setup](docs/MONITORING_SETUP.md)** — Prometheus + Grafana + Loki
- **[TLS Traffic Generator](docs/TLS_TRAFFIC_GENERATOR.md)** — Test traffic profiles
- **[Architecture](docs/architecture/system-architecture.md)** — System design
- **[Security Audit](docs/security/COMPREHENSIVE_SECURITY_AUDIT.md)** — Vulnerability assessment
- **[Threat Model](docs/security/threat-model.md)** — Attack surface analysis
- **[Performance Benchmark](docs/reports/PERFORMANCE_BENCHMARK.md)** — Throughput & scaling
- **[DMZ Deployment Readiness](docs/DMZ_DEPLOYMENT_READINESS.md)** — Security gap analysis for corporate DMZ
- **[Enterprise Deployment](docs/enterprise/deployment.md)** — Production guide
- **[GDPR Compliance](docs/compliance/GDPR_COMPLIANCE.md)** — Data handling
- **[Changelog](CHANGELOG.md)** — Version history

## Scaling

The POC runs a single proxy instance (~210 conn/s). To scale up:

```bash
./scale-proxies.sh 4    # Scale to 4 proxy instances (~840 conn/s)
./scale-proxies.sh 1    # Reset to single instance
```

This automatically scales containers and reconfigures HAProxy for round-robin. All instances share Redis, so bans are enforced cluster-wide. See [Performance Benchmark](docs/reports/PERFORMANCE_BENCHMARK.md) for throughput data.

## Codebase

| Category | Lines | % | What |
|---|---:|---:|---|
| **Core Proxy** | 4,563 | 36% | `proxy.py` + `src/security/` — TLS parsing, JA4 fingerprinting, rate limiting, threat detection |
| **Tests** | 6,027 | 48% | Unit, integration, security, and fuzz tests (1.3× test-to-code ratio) |
| **Traffic Generator** | 851 | 7% | TLS traffic simulator + benchmark tool with browser/bot profiles |
| **Supporting Services** | 282 | 2% | Tarpit server (126 lines) + mock backend (156 lines) |
| **Infrastructure** | 931 | 7% | Dockerfiles + Compose definitions (POC, monitoring, prod) |
| **Total code** | **12,654** | | |

Plus configuration (1,038 lines), Grafana dashboard (1,087 lines), shell scripts (3,009 lines), and documentation (12,383 lines across 30 files).

## Stopping Services

```bash
docker compose -f docker-compose.poc.yml down
docker compose -f docker-compose.monitoring.yml down
```

