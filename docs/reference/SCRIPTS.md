<!--
title: Scripts
audience: reference
last_reviewed: 2026-03-27
phase: 21
-->

# Scripts Reference

All scripts live in `scripts/`. Each has a usage header — run with `--help` or
read the top of the file for full options.

---

## Startup / Shutdown

| Script | Called by | What it does |
|--------|-----------|-------------|
| `../scripts/start-all.sh` | `make start` | Start full stack: POC (proxy, HAProxy, Redis, backend, tarpit) + monitoring (Prometheus, Grafana, Loki, Alertmanager) |
| `../scripts/start-poc.sh` | `make deploy-poc` | Start POC environment only (no monitoring) |
| `../scripts/start-monitoring.sh` | `make start-monitoring` | Start monitoring stack only (Prometheus, Grafana, Loki, Alertmanager) |
| `../scripts/stop-all.sh` | `make stop` / `make stop-clean` | Stop all stacks; pass `--clean` to wipe volumes |

---

## Status / Health

| Script | Called by | What it does |
|--------|-----------|-------------|
| `../scripts/status.sh` | `make status` | Unified health check — all services, Redis state, active bans, dial setting |
| `../scripts/check-status.sh` | — | Quick one-shot status check (subset of `../scripts/status.sh`) |
| `../scripts/poc-status-check.sh` | — | POC readiness check for assessors: verifies all services are reachable and responsive |
| `../scripts/view-metrics.sh` | — | Pretty-print raw Prometheus metrics from the proxy (:9090) and Redis exporter |

---

## Operations / Incident Response

| Script | Called by | What it does |
|--------|-----------|-------------|
| `../scripts/ja4-admin.sh` | `make block-ja4` etc. | Incident response CLI: block/unblock IPs and JA4 fingerprints, show top attackers, full security report |
| `ja4proxy-admin.py` | — | Python CLI with the same commands as `../scripts/ja4-admin.sh`, for scripted automation |
| `../scripts/set_dial.py` | `make dial` | Set the blocking dial (0–100) via Redis pub/sub — no restart required |
| `../scripts/geoip-monitor.sh` | `make geoip-monitor` / `make geoip-watch` | Auto-block countries that are actively generating blocked traffic; `--watch` loops every 60 s |
| `../scripts/update-geoip.sh` | `make update-geoip` | Download the latest IP2Location LITE country database; pass `--check` to report database age without downloading |
| `../scripts/fetch-ja4db.sh` | `make fetch-db` | Fetch known-bad JA4 fingerprints from FoxIO's public database and queue for admin review |
| `../scripts/setup-redis-security.sh` | — | Configure Redis TLS and secrets for production hardening |
| `../scripts/scale-proxies.sh` | — | Scale proxy to N instances behind HAProxy (`./scale-proxies.sh 4`); reconfigures HAProxy automatically |
| `../scripts/fix-docker-dns.sh` | — | Fix Docker container DNS when running with `"iptables": false` + UFW (this host's network setup) |
| `../scripts/docker-net-diag.sh` | — | Diagnose Docker container networking (DNS, routing, external connectivity) |

---

## Testing

| Script | Called by | What it does |
|--------|-----------|-------------|
| `../scripts/run-local-tests.sh` | `make test` | Fast parallel local test runner; writes timestamped logs + JUnit XML to `test-results/` |
| `../scripts/run-tests.sh` | `make test-docker` | Run tests inside Docker (CI / clean environment); respects `PYTHONUNBUFFERED` |
| `../scripts/run-all-tests.sh` | — | Comprehensive runner that runs all test categories sequentially with summaries |
| `../scripts/test-wrapper.sh` | — | Wrapper ensuring correct exit codes and debug output; used by some CI configurations |
| `../scripts/smoke-test.sh` | `make smoke-test` | Quick sanity check — verifies proxy accepts connections and returns expected responses |
| `../scripts/test-ja4-blocking.sh` | — | End-to-end test that JA4 blacklist blocking works (sends known-bad fingerprint, expects RST) |
| `../scripts/detect_workers.py` | `make test-calibrate` | Benchmarks this machine with a sample test module, writes optimal `WORKERS` count to `.local/machine.mk` |

---

## Traffic Generation / Benchmarking

| Script | Called by | What it does |
|--------|-----------|-------------|
| `../scripts/generate-tls-traffic.sh` | — | **Main demo tool.** Generates realistic TLS traffic with browser and attack profiles. Usage: `./scripts/generate-tls-traffic.sh <secs> <legit_pct> <workers>` |
| `../scripts/generate-test-traffic.sh` | — | Generate test traffic to populate Grafana dashboard with realistic data |
| `../scripts/populate-grafana-demo-data.sh` | — | Inject pre-canned security events directly into Redis to make Grafana look populated without running traffic |
| `../scripts/demo-poc.sh` | — | Guided POC demo script — starts traffic, pauses, shows metrics, stops cleanly |
| `../scripts/benchmark.py` | — | Low-level TLS connection benchmark; measures raw SSL handshake throughput |
| `../scripts/tls-traffic-generator.py` | `../scripts/generate-tls-traffic.sh` | Core traffic generation logic: browser profiles (Chrome/Firefox/Safari) and attack profiles (Sliver, CobaltStrike, Evilginx, etc.) |
| `../scripts/perf-test.sh` | `make perf-test` | Performance test using Locust against a running stack |
| `../scripts/run-benchmark.sh` | `make run-benchmark` | Run throughput benchmarks and write results to `reports/` |

---

## Development / Fixtures

| Script | Called by | What it does |
|--------|-----------|-------------|
| `../scripts/capture_clienthello.py` | — | One-shot: listens on a port, saves the first TLS ClientHello received to `tests/fixtures/clienthello/<name>.bin` |
| `../scripts/capture_server.py` | — | Persistent multi-port ClientHello capture server; saves each connection's ClientHello as a fixture |
| `../scripts/generate_fixtures.sh` | `make capture-fixtures` | Build `bin/ja4check` then generate synthetic ClientHello fixtures for Go/Python parity tests |
| `../scripts/generate_fixtures_browser.py` | `make capture-fixtures-browser` | Generate ClientHello fixtures from real browsers using Playwright (requires Docker + recorder service) |
| `../scripts/generate_synthetic_fixtures.py` | — | Generate synthetic ClientHello bytes covering different TLS versions, ciphers, and extensions |
| `../scripts/generate_adversarial_corpus.py` | — | Generate malformed/adversarial ClientHello bytes for fuzz testing the Go parser |
| `../scripts/generate_realistic_domains.py` | — | Generate a realistic domain list (draws from Tranco top 10k) for SNI analysis testing |
| `../scripts/generate_residential_ips.py` | — | Generate a residential IP list for FCrDNS/ASN testing |
| `../scripts/fetch_tranco_top10k.py` | — | Download the Tranco top 10k domain list for false-positive corpus testing |
| `../scripts/compute_ja4.py` | — | Compute a JA4 fingerprint from a raw ClientHello `.bin` file; useful for verifying parity |
| `../scripts/create_test_mmdb.py` | — | Create a minimal MaxMind `.mmdb` test database with residential and datacenter entries |
| `../scripts/mock-backend.py` | Docker | Mock HTTPS backend server used inside the test container; provides `/api/health` and other test endpoints |
| `../scripts/docker-entrypoint.sh` | Docker | Container entry point for the proxy container; configures environment then exec's the proxy |

---

## Redis / Lua

| Script | What it does |
|--------|-------------|
| `sliding_window.lua` | Atomic sliding-window rate tracker loaded into Redis via `SCRIPT LOAD` / called with `EVALSHA`. Never call inline — always use the cached SHA. See file header for `KEYS`/`ARGV` contract. |

---

## Subdirectories

| Directory | What it contains |
|-----------|-----------------|
| `scripts/docker-troubleshooting/` | One-off Docker networking repair scripts (`../scripts/docker-troubleshooting/fix-docker.sh`, `../scripts/docker-troubleshooting/nuclear-reset-docker.sh`, etc.) — only needed when Docker networking breaks on this host |

---

## Line Counter

```bash
python3 scripts/count_lines.py          # run from repo root
python3 scripts/count_lines.py --root /path/to/repo
```

Counts non-blank lines by category (Python proxy, Go proxy, tests, scripts, infrastructure, docs).
Excludes `.git`, build artefacts, generated output, and binary files.
