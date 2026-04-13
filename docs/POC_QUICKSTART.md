<!--
title: Poc_Quickstart
audience: Developers
last_reviewed: 2026-03-27
phase: 21
-->

# JA4proxy POC — Quick Start

Get the demo running in under 5 minutes. Designed for assessors evaluating the proxy for deployment.

## Prerequisites

- Docker 20.10+ and Docker Compose 2.0+
- 4 GB RAM, 2 GB disk space
- Ports 443, 3001, 8080, 8404, 8443, 8888, 9090, 9091, 9093 available

## First-time setup (new machine only)

`.env` must exist and contain `BACKEND_HOST`. Then:

```bash
make rebuild        # wipe + rebuild all Docker images from scratch + start stack
make update-geoip   # download IP2Location LITE database (required for country blocking)
```

After that, use `make start` / `make stop` for day-to-day use. Only run `make rebuild` again after pulling changes that affect Docker images.

## 1. Start Everything

```bash
./start-all.sh
```

This starts 12 containers: HAProxy (load balancer), JA4proxy (×1), Redis (shared state),
backend (mock HTTPS server), tarpit (slow-drain for blocked connections), Prometheus, Grafana,
Loki, Promtail, Alertmanager, Redis Exporter, Node Exporter.

First run auto-generates `.env` with random secrets (Redis password, Grafana password).

## 2. Generate Traffic

```bash
# Quick demo: 60s, 10% legitimate, 20 workers
./generate-tls-traffic.sh 60 10 20

# Assessment run: 5 min, 15% legitimate, 50 workers
./generate-tls-traffic.sh 300 15 50
```

Traffic profiles:
- **Legitimate**: Chrome, Firefox, Safari (TLS fingerprints with `h2`/`h1` ALPN — whitelisted)
- **Malicious**: Sliver C2, CobaltStrike Beacon, Evilginx, Python bot, Credential stuffer

After the run, a summary is printed automatically:

```
Requests by fingerprint + action:
  Browser (TLS 1.3)              allowed    2728
  Tool/Bot (TLS 1.2)             blocked    40018

Blocked requests by action type:
  ban          90654
  tarpit       14
  ─────────────────────
  Total blocked  90668
```

## 3. Watch the Dashboard

Open **http://localhost:3001** (admin / password printed by `./start-all.sh` or in `.env`).

Navigate to **JA4proxy Security Overview**. Key panels:

| Panel | What to look for |
|-------|-----------------|
| Allowed vs Blocked | All browser traffic in "allowed"; malicious tools in "blocked"/"banned" |
| Fingerprint names | Human-readable: Chrome, Sliver C2, CobaltStrike — not raw hashes |
| Action distribution | Tarpitted (slow drain) + banned (persistent) + blacklisted (instant RST) |
| Security events | Real-time log of decisions |

## 4. What to Expect

| Metric | Expected result |
|--------|----------------|
| Browser false positives | **0%** — whitelisted at Layer 2b, never reach rate limiting |
| Malicious traffic blocked | **94–99%** depending on load |
| Block self-healing | **300 seconds** — blocks auto-expire; no manual intervention needed |
| Known bad fingerprints | Instant TCP RST (Sliver C2, CobaltStrike, IcedID, Evilginx, SoftEther) |

## 5. Reset Between Runs

```bash
# Clear rate windows, bans, blocks (keeps whitelist/blacklist config)
make flush-redis
```

This resets all transient security state so consecutive test runs start clean without restarting containers.

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
| Alertmanager | `http://localhost:9093` |

## Verify Legitimate Traffic Passes

```bash
# Direct backend connection (bypasses proxy)
curl -sk https://localhost:8443/api/health

# Check proxy logs for ALLOWED decisions
docker compose -f deploy/docker/docker-compose.poc.yml logs proxy | grep ALLOWED | tail -5
```

## Scale Up (Optional)

```bash
./scale-proxies.sh 4    # 4 proxy instances (~840 conn/s total)
./scale-proxies.sh 1    # Reset to single instance
```

## Stop

```bash
./stop-all.sh          # Stop everything, keep Redis data
./stop-all.sh --clean  # Stop and wipe all volumes
```

## Key Configuration File

`config/proxy.yml` controls everything:

```yaml
security:
  multi_strategy_policy: "majority"   # 2 of 3 strategies must agree before blocking
  whitelist_patterns:
    - "h2"   # HTTP/2 ALPN browsers — whitelisted, bypass rate limiting
    - "h1"   # HTTP/1.1 ALPN browsers — whitelisted, bypass rate limiting
  blacklist:
    - "t13d190900_9dc949149365_97f8aa674fd9"  # Sliver C2 Agent (instant RST)
    - "t12d190800_d83cc789557e_16bbda4055b2"  # CobaltStrike Beacon (instant RST)
    # ... 5 more known-bad fingerprints
```

See the main [README](../README.md) for full configuration reference.

## Further Reading

- [README](../README.md) — Full feature overview and configuration reference
- [Quick Reference](QUICK_REFERENCE.md) — Command cheat sheet
- [Performance Benchmark](reports/PERFORMANCE_BENCHMARK.md) — Throughput data
- [Security Audit](security/COMPREHENSIVE_SECURITY_AUDIT.md) — Vulnerability assessment
- [Threat Model](security/threat-model.md) — Attack surface analysis
- [Enterprise Deployment](enterprise/deployment.md) — Production hardening guide
- [GDPR Compliance](compliance/GDPR_COMPLIANCE.md) — Data handling

> ⚠️ **This is a POC environment.** See [DMZ Deployment Readiness](DMZ_DEPLOYMENT_READINESS.md) for outstanding items before production use.
