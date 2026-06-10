<!--
title: JA4proxy — Makefile Targets
audience: operator
last_reviewed: 2026-06-04
phase: v2.0
-->

# Makefile Targets Reference

> **Audience:** Developer, Operator  
> **Last reviewed:** 2026-05-30

Every target in the JA4proxy Makefile, with description, arguments, and prerequisites.

---

## Quick-Start

```bash
make help               # Show top-level help (lists all sub-helps)
make lint-help          # Linting targets
make scan-help          # Container scanning targets
make legacy-help        # Python legacy proxy targets
make dev-help           # Build, test, proxy, bench, docs, agents
```

---

## Startup / Shutdown

| Target | Description | Env / Args | Prerequisites |
|--------|-------------|------------|---------------|
| `start` | Start full stack (POC + Prometheus/Grafana) | `.env` | Docker |
| `start-monitoring` | Start monitoring stack only | `.env` | Docker |
| `start-scaled` | Start 4-worker scaled config with HAProxy | `.env` | Docker |
| `stop` | Stop all services (keep Redis data) | — | Running stack |
| `stop-clean` | Stop all + wipe volumes (fresh slate) | — | Running stack |
| `status` | Show health of all services + security state | — | Running stack |
| `logs` | Stream proxy container logs | `.current-agent` | Running stack |
| `health-check` | Run health checks against metrics + Redis | `.current-agent` | Running stack |

### Multi-Agent

| Target | Description | Env / Args | Prerequisites |
|--------|-------------|------------|---------------|
| `agent-up NAME=<agent>` | Start isolated agent env (writes `.current-agent`) | `NAME` (required) | Docker |
| `agent-down [NAME=]` | Stop agent env (reads `.current-agent` if no NAME) | `NAME` (optional) | Running agent |
| `agent-status` | List all running agent environments | — | Docker |
| `tunnel NAME=<agent> [HOST=user@server]` | SSH tunnels for agent UIs | `NAME`, `HOST` (optional) | Running agent |

---

## Build

| Target | Description | Env / Args | Prerequisites |
|--------|-------------|------------|---------------|
| `build` | Build Docker images (incremental, BuildKit) | — | Docker |
| `rebuild` | Wipe volumes/images, rebuild from scratch, start fresh | `.current-agent` (optional) | Docker |
| `clean` | Stop + remove all containers and volumes | `.current-agent` (optional) | Docker |
| `deploy-poc` | Deploy PoC environment | — | Docker, `.env` |
| `deploy-enterprise` | Deploy enterprise environment (sudo) | — | Sudo, Docker |

---

## Testing

| Target | Description | Env / Args | Prerequisites |
|--------|-------------|------------|---------------|
| `test` | Run all tests locally (fast, no Docker) | `ARGS=` | Python deps |
| `test-live` | Run full suite including live-service tests | `ARGS=` | Go + Python proxy + Redis |
| `test-unit` | Run unit tests only | `ARGS=` | Python deps |
| `test-chaos` | Run chaos/resilience tests only | `ARGS=` | Python deps |
| `test-adversarial` | Run adversarial/fuzz tests only | `ARGS=` | Python deps |
| `test-calibrate` | Benchmark this machine, store worker count | — | Python deps |
| `test-docker` | Run tests inside Docker (CI env) | — | Docker |
| `smoke-test` | Quick sanity check | — | Python deps |
| `smoke-docker` | Docker Compose lifecycle smoke test | — | Docker |
| `smoke-k8s` | Helm/kind smoke test (skips if kind absent) | — | kind, Helm |
| `test-component-suites` | Run every per-component test suite | — | Go + Python deps |

### Go-Specific Test Targets

| Target | Description | Prerequisites |
|--------|-------------|---------------|
| `test-go` | Build + test all Go (build binaries, generate fixtures, run suite) | GOROOT |
| `test-go-docker` | Go integration tests inside Docker (self-contained) | Docker |
| `test-go-integration` | Go integration tests locally | Go proxy on GO_PROXY_PORT |
| `test-go-chaos` | Go chaos tests locally | Go proxy on GO_PROXY_PORT |
| `test-go-perf` | Go performance benchmarks | Go proxy on GO_PROXY_PORT |
| `test-go-redis-tls` | Go Redis TLS smoke test | Docker |
| `test-go-fuzz-smoke` | Go fuzz tests (10s each) | GOROOT |
| `test-go-property` | Go property-based tests | GOROOT |
| `test-go-chaos-unit` | Go chaos unit tests | GOROOT |

### Component Test Suites

| Target | Description | Prerequisites |
|--------|-------------|---------------|
| `test-mgmt-api` | All Management API tests | Python deps |
| `test-mgmt-api-unit` | Unit tests: auth, dial, lists, bans, health, config, audit | Python deps |
| `test-mgmt-api-events` | Management API events tests | Python deps |
| `test-logging-webhook` | Logging + webhook tests (Go + Python) | GOROOT, Python deps |
| `test-policy-validator` | Policy validator tests | Python deps |
| `test-compliance` | All compliance regression guards | Go + Python deps |
| `test-compliance-go` | Go compliance tests | GOROOT |
| `test-compliance-python` | Python compliance tests | Python deps |
| `test-compliance-parity` | Cross-language compliance parity | Go + Python deps |
| `test-cli` | CLI tests (build + vet + test + parity) | GOROOT, Python deps |
| `test-slo` | SLO validation tests | GOROOT, Python deps |
| `test-infra-monitoring` | Infra monitoring unit tests | Python deps |
| `test-infra-monitoring-integration` | Infra monitoring integration tests | Monitoring stack |
| `test-docker-consistency` | Dockerfile consistency tests | Python deps |
| `test-gdpr-compliance` | GDPR compliance tests | Python deps |
| `test-lint-hierarchy` | Lint hierarchy tests | Python deps |
| `test-provisioning` | Terraform provider + emergency playbook tests | GOROOT, Python deps |
| `test-tap` | All TAP mode unit/chaos/corpus tests | Python deps |
| `test-tap-live INTERFACE=eth1` | TAP integration with live capture interface | Sudo, TAP interface |
| `test-tap-perf` | TAP throughput benchmark | Python deps |
| `test-attack-mapping` | ATT&CK mapping CI gate | Python deps |
| `test-doc-links` | Doc link check (requires lychee) | lychee CLI |
| `test-compliance-language` | Fail if "certified"/"compliant" in self-assessed docs | Python deps |
| `test-evidence-paths` | Fail if conformance docs cite nonexistent paths | Python deps |

---

## Linting

### Python

| Target | Description |
|--------|-------------|
| `lint-static` | mypy + bandit + ruff + pip-audit |
| `lint-security` | bandit SAST (medium/high severity) |
| `lint-pylint` | pylint errors-only — catches semantic bugs |
| `lint-quality` | flake8 code quality |
| `lint-coverage` | pytest-cov coverage reporting (≥80% gate) |
| `lint-python` | Aggregate: `lint-static` + `lint-security` + `lint-pylint` |

### Go

| Target | Description |
|--------|-------------|
| `go-lint` | `go vet` |
| `lint-go-full` | golangci-lint comprehensive |
| `lint-go-mod` | `go mod verify` — module integrity |
| `lint-go` | Aggregate: `go-lint` + `lint-go-full` + `lint-go-mod` |

### Infrastructure / Config

| Target | Description |
|--------|-------------|
| `lint-docker` | hadolint + `docker compose config --quiet` (all overlays) |
| `lint-compose-config` | `docker compose config --quiet` (poc/test/prod) |
| `lint-shell` | shellcheck all `.sh` scripts (error-level) |
| `lint-yaml` | yamllint `config/` and `monitoring/` |
| `lint-json` | JSON syntax validation |
| `lint-lua` | luacheck Redis Lua scripts |
| `lint-haproxy` | haproxy `-c` config validation |
| `lint-helm` | helm lint chart validation |
| `lint-github-actions` | actionlint workflow validation |
| `lint-ansible` | ansible-lint playbook validation |
| `lint-makefiles` | checkmake Makefile validation |
| `lint-toml` | TOML syntax + parse validation |
| `lint-infra` | Aggregate of all infra linters |

### Observability

| Target | Description |
|--------|-------------|
| `lint-prom` | promtool check rules (alerts + recording) |
| `lint-alertmanager` | amtool check-config |
| `lint-observability` | Aggregate: `lint-prom` + `lint-alertmanager` |

### Cross-Cutting / SAST

| Target | Description |
|--------|-------------|
| `lint-semgrep` | semgrep auto-config cross-language pattern matching |
| `lint-checkov` | checkov IaC security misconfiguration scan |
| `lint-sast` | Aggregate: `lint-semgrep` + `lint-checkov` |

### Supply Chain

| Target | Description |
|--------|-------------|
| `lint-secrets` | gitleaks scan of git history |
| `lint-deps` | pip-audit (Python) + govulncheck (Go) CVE scan |
| `lint-supply-chain` | Aggregate: `lint-secrets` + `lint-deps` + advisory image scans |

### Documentation

| Target | Description |
|--------|-------------|
| `lint-docs` | Validate doc frontmatter |
| `lint-phases` | Validate manifest + phase doc integrity |
| `link-check` | Check internal Markdown links (markdown-link-check) |
| `lint-markdown` | markdownlint structural quality |
| `lint-spelling` | codespell typo detection |
| `check-paths` | Check for dangling moved-path references |
| `lint-alert-urls` | Verify Alertmanager runbook URLs are up to date |
| `lint-docs-all` | All doc linters aggregate |
| `doc-health` | Run `lint-phases` + `lint-docs` + `link-check` + `check-paths` |

### Mega-Aggregates

| Target | Description |
|--------|-------------|
| `lint-all` | Every linter — the single entry point for full validation |
| `quality` | `lint-all` + `lint-coverage` + Go coverage check (≥50%) |

---

## Container Scanning

| Target | Description |
|--------|-------------|
| `scan-images` | Trivy scan of third-party images (HIGH/CRITICAL; fails on CRITICAL) |
| `scan-dockerfiles` | Trivy config scan of Dockerfiles + compose files (HIGH/CRITICAL → fail) |
| `scan-first-party` | Trivy CVE scan of built images (CRITICAL → fail) |
| `scan` | All three scans combined |
| `check-image-versions` | Detect `:latest` tags and version drift across compose files |

---

## Operations

| Target | Description | Env / Args |
|--------|-------------|------------|
| `flush-redis` | Reset bans/blocks/rates (keeps whitelist/blacklist) | `.current-agent` (optional) |
| `dial LEVEL=<0-100>` | Set the blocking dial via pubsub | `LEVEL` (required) |
| `ssh-tunnels` | Print SSH tunnel command for default stack | — |
| `perf-test` | Run performance tests with Locust | Docker stack running |
| `perf-test-basic` | Run basic performance test | — |
| `quick-start` | Start proxy with default config | Docker |

### Incident Response

| Target | Description | Env / Args |
|--------|-------------|------------|
| `attack-status` | Quick security snapshot | — |
| `top-attackers` | Top 10 fingerprints by traffic | — |
| `block-ja4 FP=<fp>` | Blacklist a JA4 fingerprint (instant TCP RST) | `FP` (required) |
| `block-ip IP=<ip>` | Hard-block an IP for 1 hour | `IP` (required) |
| `unblock-ip IP=<ip>` | Remove all blocks for an IP | `IP` (required) |

### Threat Intelligence

| Target | Description |
|--------|-------------|
| `fetch-db` | Fetch new malicious fingerprints from ja4db/FoxIO |
| `list-pending` | Show fingerprints awaiting admin approval |
| `approve-all` | Approve all pending fingerprints |
| `update-geoip` | Download latest IP2Location LITE DB (monthly) |
| `check-geoip` | Check age of current GeoIP database |
| `geoip-report` | Full blocking report |
| `geoip-monitor` | Auto-block attacking countries (run once) |
| `geoip-watch` | Auto-block attacking countries (continuous loop) |

### GDPR / Compliance

| Target | Description | Env / Args |
|--------|-------------|------------|
| `gdpr-delete IP=<ip>` | Delete all Redis data for a specific IP | `IP` (required), `DRY_RUN` (optional) |
| `validate-ecs-schema` | Validate ECS event JSON schema | Python jsonschema |

---

## Go Proxy

| Target | Description | Prerequisites |
|--------|-------------|---------------|
| `go-build` | Build Go proxy binary to `bin/ja4proxy` | GOROOT |
| `go-test` | Run all Go unit tests | GOROOT |
| `go-lint` | Run `go vet` on Go code | GOROOT |
| `go-build-ja4check` | Build `bin/ja4check` utility | GOROOT |
| `check-scores` | Audit Python and Go signal scores against registry | Python deps |
| `parity-check` | Live end-to-end decision parity verification | Both proxies running |
| `go-start` | Start Python legacy proxy alongside Go (parity comparison) | Docker |
| `go-stop` | Stop Python legacy proxy container | Docker |
| `go-switch` | Show instructions to confirm Go proxy is HAProxy primary | — |
| `go-rollback` | Emergency: roll HAProxy back to Python proxy | Docker |
| `go-parity` | Run cross-language parity tests | Both proxies running |

### Go Internal Benchmarks

| Target | Description |
|--------|-------------|
| `bench-go-pipeline` | Go pipeline benchmark (no Python) |

---

## Benchmarking

| Target | Description | Env / Args |
|--------|-------------|------------|
| `bench` | Run all benchmarks (micro + macro) | `ARGS=` |
| `bench-micro` | Go native micro-benchmarks (pipeline cost, no I/O) | — |
| `bench-macro` | End-to-end load test through the bridge port (requires `make start`) | `ARGS=` |
| `bench-hostnative` | End-to-end throughput with `ja4pd` host-native (no `docker-proxy`; ~4.5× the bridge port). See `docs/performance/benchmarks.md` | `BENCH_WORKERS=`, `BENCH_DURATION=`, `BENCH_GOOD_RATE=` |
| `bench-all` | Every heavy benchmark (perf, load, go-perf, MTTR) — slow, runs alone | — |

---

## Management UI

| Target | Description | Prerequisites |
|--------|-------------|---------------|
| `management-build` | Build management UI Docker image | Docker |
| `management-up` | Start management UI container (agent-aware) | Docker |
| `management-down` | Stop management UI container (agent-aware) | Running stack |
| `management-logs` | Stream management UI logs (agent-aware) | Running stack |
| `management-test` | Run management UI tests | Python deps |
| `management-shell` | Open shell in management container (agent-aware) | Running stack |

---

## Load Testing

| Target | Description | Env / Args |
|--------|-------------|------------|
| `load-test` | Run JA4proxy load test | `LOAD_TEST_TARGET`, `LOAD_TEST_DURATION`, `LOAD_TEST_RPS`, `LOAD_TEST_SCENARIO` |
| `load-test-baseline` | Baseline load test (localhost:8080, 60s, 1000 rps) | — |
| `load-test-report` | Show latest load test reports | — |

---

## Fixture Capture

| Target | Description |
|--------|-------------|
| `capture-fixtures` | Generate ClientHello `.bin` fixtures (curl + openssl) |
| `capture-fixtures-browser` | Capture browser-specific ClientHello fixtures (Docker + recorder) |

---

## SLO / Validation

| Target | Description |
|--------|-------------|
| `validate-slo-rules` | Validate SLO recording/alert rules (promtool or YAML) |
| `slo-report` | Show SLO report from live Prometheus |
| `test-ratio` | Show current test-to-code ratio |
| `validation-report` | Generate validation report |
| `ci-local` | Run the same checks the CI workflow runs (Go + Python) |

---

## Findings Register

| Target | Description |
|--------|-------------|
| `verify-findings` | Validate `docs/security/findings.yaml` schema and integrity |
| `verify-findings-green` | Run regression tests backing findings entries (fast signal) |
| `findings-render` | Regenerate `FINDINGS_REGISTER.md` from `findings.yaml` |
| `findings-list` | List open findings (`FINDINGS_ARGS=--severity HIGH`) |
| `verify-manifest-closeout` | Manifest close-out gate (register, docs, ADRs, manifest) |

---

## Phase / Manifest Management

| Target | Description |
|--------|-------------|
| `sync` | Sync roadmap/status docs (`python3 scripts/sync-roadmap.py`) |
| `lint-phases` | Validate phase doc + manifest consistency |
| `check-manifest` | Manifest consistency check (TODO.md, PROJECT_STATUS, CHANGELOG, CLAUDE.md) |

---

## Miscellaneous

| Target | Description |
|--------|-------------|
| `openapi-spec` | Export OpenAPI spec from management API |
| `check-updates` | Check Python/Go/Docker dependency versions |
| `test-compose-config-lint` | Deprecated alias for `lint-compose-config` |
| `verify-manifest-closeout` | Manifest close-out gate |
| `test-attack-mapping` | ATT&CK mapping CI gate (Phase 107f) |
| `test-doc-links` | Doc link check (Phase 107w, requires lychee) |

---

## ARGS Variable

Many `test-*` targets accept an `ARGS=` variable that is passed directly to the underlying pytest or benchmark script:

```bash
make test ARGS='-k test_ja4_parity -v'
make bench ARGS='--scenarios peak_throughput --duration-long 60'
```

---

## NAME Variable Convention

The `NAME=` variable is used for multi-agent operations and is normalised from `Name=` or `name=`:
- `make agent-up NAME=claude` — start agent
- `make agent-down NAME=claude` — stop agent
- `make tunnel NAME=claude HOST=user@server` — SSH tunnels

After `agent-up`, many targets read `.current-agent` automatically:
`stop`, `stop-clean`, `status`, `logs`, `health-check`, `flush-redis`, `clean`, `rebuild`, `management-up/down/logs/shell`.
