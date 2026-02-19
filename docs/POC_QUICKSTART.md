# JA4proxy POC — Quick Start

Get the demo running in under 5 minutes.

## Prerequisites

- Docker 20.10+ and Docker Compose 2.0+
- 4GB RAM, 2GB disk space

## Start Everything

```bash
./start-all.sh
```

This starts 12 containers: HAProxy, JA4proxy, Redis, backend, tarpit, Prometheus, Grafana, Loki, Promtail, Alertmanager, Redis Exporter, and Node Exporter.

## Generate Traffic

```bash
./generate-tls-traffic.sh 60 10 20    # 60s, 10% legitimate, 20 workers
```

## Watch the Dashboard

Open **http://localhost:3001** (admin / password shown by start-monitoring.sh) → JA4proxy Security Overview.

You'll see:
- Allowed vs blocked connections in real time
- JA4 fingerprint names (Chrome, Sliver C2, CobaltStrike, etc.)
- Action distribution (allowed / tarpitted / banned)
- Traffic by country (when GeoIP is enabled)
- Security event logs from Loki

## Services

| Service | URL |
|---------|-----|
| HAProxy (LB) | `https://localhost:443` |
| HAProxy Stats | `http://localhost:8404/stats` |
| JA4proxy | `http://localhost:8080` |
| Proxy Metrics | `http://localhost:9090/metrics` |
| Backend (HTTPS) | `https://localhost:8443` |
| Tarpit | `http://localhost:8888` |
| Prometheus | `http://localhost:9091` |
| Grafana | `http://localhost:3001` |
| Loki (logs) | `http://localhost:3100` (Docker network only) |
| Alertmanager | `http://localhost:9093` |

## Verify Legitimate Traffic Passes

```bash
# Good traffic uses h2 ALPN → whitelisted → forwarded to backend
curl -sk https://localhost:8443/ | head -5
```

## Scale Up (Optional)

```bash
./scale-proxies.sh 4    # 4 proxy instances (~840 conn/s)
./scale-proxies.sh 1    # Reset to single instance
```

## Stop

```bash
docker compose -f docker-compose.poc.yml down
docker compose -f docker-compose.monitoring.yml down
```

## Configuration

All config is in `config/proxy.yml` — see the main [README](../README.md) for details on GeoIP, whitelists, blacklists, rate limiting, and fingerprint names.

## Further Reading

- [README](../README.md) — Full feature overview
- [POC Guide](POC_GUIDE.md) — Detailed walkthrough
- [Performance Benchmark](reports/PERFORMANCE_BENCHMARK.md) — Throughput data
- [Enterprise Deployment](enterprise/deployment.md) — Production guide
- [Security Audit](security/COMPREHENSIVE_SECURITY_AUDIT.md) — Vulnerability assessment

⚠️ **This is a POC. Not for production use.**
