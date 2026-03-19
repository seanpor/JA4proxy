# Scripts Reference

All scripts live in `scripts/`. Each has a usage header — run with `--help` or
read the top of the file for full options.

---

## Startup / Shutdown

| Script | Called by | What it does |
|--------|-----------|-------------|
| `start-all.sh` | `make start` | Start full stack: POC (proxy, HAProxy, Redis, backend, tarpit) + monitoring (Prometheus, Grafana, Loki, Alertmanager) |
| `start-poc.sh` | `make deploy-poc` | Start POC environment only (no monitoring) |
| `start-monitoring.sh` | `make start-monitoring` | Start monitoring stack only (Prometheus, Grafana, Loki, Alertmanager) |
| `stop-all.sh` | `make stop` / `make stop-clean` | Stop all stacks; pass `--clean` to wipe volumes |

---

## Status / Health

| Script | Called by | What it does |
|--------|-----------|-------------|
| `status.sh` | `make status` | Unified health check — all services, Redis state, active bans, dial setting |
| `check-status.sh` | — | Quick one-shot status check (subset of `status.sh`) |
| `poc-status-check.sh` | — | POC readiness check for assessors: verifies all services are reachable and responsive |
| `view-metrics.sh` | — | Pretty-print raw Prometheus metrics from the proxy (:9090) and Redis exporter |

---

## Operations / Incident Response

| Script | Called by | What it does |
|--------|-----------|-------------|
| `ja4-admin.sh` | `make block-ja4` etc. | Incident response CLI: block/unblock IPs and JA4 fingerprints, show top attackers, full security report |
| `ja4proxy-admin.py` | — | Python CLI with the same commands as `ja4-admin.sh`, for scripted automation |
| `set_dial.py` | `make dial` | Set the blocking dial (0–100) via Redis pub/sub — no restart required |
| `geoip-monitor.sh` | `make geoip-monitor` / `make geoip-watch` | Auto-block countries that are actively generating blocked traffic; `--watch` loops every 60 s |
| `update-geoip.sh` | `make update-geoip` | Download the latest IP2Location LITE country database; pass `--check` to report database age without downloading |
| `fetch-ja4db.sh` | `make fetch-db` | Fetch known-bad JA4 fingerprints from FoxIO's public database and queue for admin review |
| `setup-redis-security.sh` | — | Configure Redis TLS and secrets for production hardening |
| `scale-proxies.sh` | — | Scale proxy to N instances behind HAProxy (`./scale-proxies.sh 4`); reconfigures HAProxy automatically |
| `fix-docker-dns.sh` | — | Fix Docker container DNS when running with `"iptables": false` + UFW (this host's network setup) |
| `docker-net-diag.sh` | — | Diagnose Docker container networking (DNS, routing, external connectivity) |

---

## Testing

| Script | Called by | What it does |
|--------|-----------|-------------|
| `run-local-tests.sh` | `make test` | Fast parallel local test runner; writes timestamped logs + JUnit XML to `test-results/` |
| `run-tests.sh` | `make test-docker` | Run tests inside Docker (CI / clean environment); respects `PYTHONUNBUFFERED` |
| `run-all-tests.sh` | — | Comprehensive runner that runs all test categories sequentially with summaries |
| `test-wrapper.sh` | — | Wrapper ensuring correct exit codes and debug output; used by some CI configurations |
| `smoke-test.sh` | `make smoke-test` | Quick sanity check — verifies proxy accepts connections and returns expected responses |
| `test-ja4-blocking.sh` | — | End-to-end test that JA4 blacklist blocking works (sends known-bad fingerprint, expects RST) |
| `detect_workers.py` | `make test-calibrate` | Benchmarks this machine with a sample test module, writes optimal `WORKERS` count to `.local/machine.mk` |

---

## Traffic Generation / Benchmarking

| Script | Called by | What it does |
|--------|-----------|-------------|
| `generate-tls-traffic.sh` | — | **Main demo tool.** Generates realistic TLS traffic with browser and attack profiles. Usage: `./scripts/generate-tls-traffic.sh <secs> <legit_pct> <workers>` |
| `generate-test-traffic.sh` | — | Generate test traffic to populate Grafana dashboard with realistic data |
| `populate-grafana-demo-data.sh` | — | Inject pre-canned security events directly into Redis to make Grafana look populated without running traffic |
| `demo-poc.sh` | — | Guided POC demo script — starts traffic, pauses, shows metrics, stops cleanly |
| `benchmark.py` | — | Low-level TLS connection benchmark; measures raw SSL handshake throughput |
| `tls-traffic-generator.py` | `generate-tls-traffic.sh` | Core traffic generation logic: browser profiles (Chrome/Firefox/Safari) and attack profiles (Sliver, CobaltStrike, Evilginx, etc.) |
| `perf-test.sh` | `make perf-test` | Performance test using Locust against a running stack |
| `run-benchmark.sh` | `make run-benchmark` | Run throughput benchmarks and write results to `reports/` |

---

## Development / Fixtures

| Script | Called by | What it does |
|--------|-----------|-------------|
| `capture_clienthello.py` | — | One-shot: listens on a port, saves the first TLS ClientHello received to `tests/fixtures/clienthello/<name>.bin` |
| `capture_server.py` | — | Persistent multi-port ClientHello capture server; saves each connection's ClientHello as a fixture |
| `generate_fixtures.sh` | `make capture-fixtures` | Build `bin/ja4check` then generate synthetic ClientHello fixtures for Go/Python parity tests |
| `generate_fixtures_browser.py` | `make capture-fixtures-browser` | Generate ClientHello fixtures from real browsers using Playwright (requires Docker + recorder service) |
| `generate_synthetic_fixtures.py` | — | Generate synthetic ClientHello bytes covering different TLS versions, ciphers, and extensions |
| `generate_adversarial_corpus.py` | — | Generate malformed/adversarial ClientHello bytes for fuzz testing the Go parser |
| `generate_realistic_domains.py` | — | Generate a realistic domain list (draws from Tranco top 10k) for SNI analysis testing |
| `generate_residential_ips.py` | — | Generate a residential IP list for FCrDNS/ASN testing |
| `fetch_tranco_top10k.py` | — | Download the Tranco top 10k domain list for false-positive corpus testing |
| `compute_ja4.py` | — | Compute a JA4 fingerprint from a raw ClientHello `.bin` file; useful for verifying parity |
| `create_test_mmdb.py` | — | Create a minimal MaxMind `.mmdb` test database with residential and datacenter entries |
| `mock-backend.py` | Docker | Mock HTTPS backend server used inside the test container; provides `/api/health` and other test endpoints |
| `docker-entrypoint.sh` | Docker | Container entry point for the proxy container; configures environment then exec's the proxy |

---

## Redis / Lua

| Script | What it does |
|--------|-------------|
| `sliding_window.lua` | Atomic sliding-window rate tracker loaded into Redis via `SCRIPT LOAD` / called with `EVALSHA`. Never call inline — always use the cached SHA. See file header for `KEYS`/`ARGV` contract. |

---

## Subdirectories

| Directory | What it contains |
|-----------|-----------------|
| `scripts/docker-troubleshooting/` | One-off Docker networking repair scripts (`fix-docker.sh`, `nuclear-reset-docker.sh`, etc.) — only needed when Docker networking breaks on this host |

---

## Line Counter

```bash
python3 scripts/count_lines.py          # run from repo root
python3 scripts/count_lines.py --root /path/to/repo
```

Counts non-blank lines by category (Python proxy, Go proxy, tests, scripts, infrastructure, docs).
Excludes `.git`, build artefacts, generated output, and binary files.
