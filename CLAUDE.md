# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

JA4proxy is a TLS fingerprinting security proxy that inspects TLS ClientHello packets (plaintext — no decryption required) to generate JA4 fingerprints, then blocks malicious clients (C2 tools, botnets) before they reach backend servers. It runs as a transparent TCP proxy with HAProxy in front for load balancing and TLS passthrough.

## Common Commands

```bash
# Start POC environment (proxy + HAProxy + Redis + backend + tarpit)
./start-all.sh                              # Start proxy + monitoring
./start-poc.sh                              # Start proxy stack only
./start-monitoring.sh                       # Start Prometheus/Grafana/Loki

# Testing
make test                                   # All tests
make test-unit                              # Unit tests only
make test-integration                       # Integration tests (requires Docker)
make smoke-test                             # Quick sanity check
make perf-test                              # Locust load tests

# Linting
make lint                                   # black + flake8 + mypy

# Scale and benchmark
./scale-proxies.sh 4                        # Scale to N proxy instances (~210 conn/s each)
./generate-tls-traffic.sh 30 10 20         # Duration(s), legit%, workers

# View logs and metrics
make logs                                   # Proxy container logs
# Grafana dashboard: http://localhost:3001  (admin/password from .env)
# Prometheus:        http://localhost:9091
# HAProxy stats:     http://localhost:8404/stats

# Cleanup
make stop                                   # Stop all services
make clean                                  # Stop + remove all containers and volumes
```

## Architecture

### Traffic Flow

```
Client ──TLS──▶ HAProxy :443 ──PROXY v2──▶ JA4proxy :8080 ×N ──TLS──▶ Backend :8443
                                                │
                                         Redis (shared bans)
                                         Tarpit :8888 (slow drain)
                                         Prometheus :9090
```

HAProxy does TLS passthrough (no termination), forwarding raw TLS via PROXY protocol v2 so the proxy receives the real client IP. All proxy instances share Redis for synchronized ban state.

### Security Pipeline (layers applied in order)

1. **GeoIP filter** — Block/allow by country (IP2Location LITE DB, disabled by default)
2. **JA4 blacklist** — Instant TCP RST for known-bad fingerprints (Sliver C2, CobaltStrike, etc.)
3. **JA4 whitelist** — Skip rate limiting for known-good fingerprints (Chrome, Firefox, Safari)
4. **Multi-strategy rate limiting** — Three independent strategies tracked via Redis:
   - `BY_IP` — catch single-source DDoS
   - `BY_JA4` — catch botnet campaigns sharing a fingerprint
   - `BY_IP_JA4_PAIR` — catch targeted attacks (most granular)
5. **Action escalation** — `NORMAL → SUSPICIOUS → BLOCK → BANNED`, enforced as `LOG → TARPIT → BAN`

Multi-strategy policy (configurable): `ANY` (most strict), `ALL` (most permissive), `MAJORITY` (balanced).

### Key Source Files

| File | Role |
|------|------|
| `proxy.py` | Main proxy: async TCP server, TLS ClientHello parsing, JA4 fingerprint generation, orchestration |
| `src/security/security_manager.py` | Coordinates all 4 security phases |
| `src/security/rate_tracker.py` | Phase 1: multi-strategy rate tracking (Redis-backed sliding windows) |
| `src/security/threat_evaluator.py` | Phase 2: classify `ThreatTier` (NORMAL/SUSPICIOUS/BLOCK/BANNED) |
| `src/security/action_enforcer.py` | Phase 3: apply actions (LOG/TARPIT/BLOCK/BAN), manage ban durations |
| `src/security/gdpr_storage.py` | Phase 4: GDPR-compliant retention (IPs are PII; JA4 fingerprints are not) |
| `src/security/rate_strategy.py` | `RateStrategy` enum (BY_IP, BY_JA4, BY_IP_JA4_PAIR) |
| `src/security/threat_tier.py` | `ThreatTier` enum (NORMAL=0 → BANNED=3) |
| `src/security/action_types.py` | `ActionType` enum (LOG, TARPIT, BLOCK, BAN) |
| `config/proxy.yml` | All runtime config: thresholds, blacklists/whitelists, GeoIP, strategy policy |
| `tarpit/tarpit-server.py` | Slow response server (1 byte/sec) to waste attacker resources |
| `ha-config/haproxy.cfg` | HAProxy: TLS passthrough, PROXY v2, round-robin, TLS 1.2+, ECDHE ciphers only |
| `security/validation.py` | Input validation/sanitization utilities |
| `scripts/tls-traffic-generator.py` | TLS profile simulator (Chrome, Firefox, Sliver C2, bots, etc.) |

### Configuration

`config/proxy.yml` controls everything at runtime:
- Proxy bind address/port and backend address
- Redis connection (password via `REDIS_PASSWORD` env var)
- JA4 blacklist/whitelist fingerprints and patterns
- Rate limit thresholds per strategy (suspicious/block/ban connections per second)
- Multi-strategy policy (ANY/ALL/MAJORITY)
- GeoIP country allow/block lists
- Ban durations per threat tier
- Human-readable fingerprint labels

Secrets (Redis password, Grafana password) are auto-generated by `start-poc.sh` into `.env` using `openssl rand`. Never hardcode them.

### Docker Compose Files

- `docker-compose.poc.yml` — POC stack (proxy, HAProxy, Redis, mock backend, tarpit, test runner)
- `docker-compose.monitoring.yml` — Observability stack (Prometheus, Grafana, Loki, Alertmanager)
- `docker-compose.prod.yml` — Production hardened deployment

Container security: `read_only: true`, `cap_drop: ALL`, `no-new-privileges: true`, internal services bound to `127.0.0.1`.

### Test Structure

```
tests/
├── unit/security/       # Per-module unit tests (rate_tracker, threat_evaluator, etc.)
├── integration/         # Full-stack Docker tests including end-to-end flow
├── compliance/          # GDPR data retention validation
├── fuzz/                # Hypothesis property-based tests
└── security/            # OWASP Top 10 checks
```

Run a single test file: `pytest tests/unit/security/test_rate_tracker.py -v`
