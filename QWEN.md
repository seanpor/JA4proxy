# QWEN.md — JA4proxy Project Context

## Project Overview

**JA4proxy** is a TLS-aware passthrough security proxy that blocks bots, C2 frameworks, and scanners at the TLS layer — **without decrypting a single byte**. It operates by inspecting the TLS ClientHello metadata (cipher suites, extensions, ALPN, elliptic curves), computing [JA4 fingerprints](https://github.com/FoxIO-LLC/ja4), and running them through a multi-signal scoring pipeline to make allow/block decisions before the TLS handshake completes.

**Key architectural principle:** When in doubt, fail open. False positives are far more costly than false negatives. Real browser traffic (`h2`/`h1` ALPN) bypasses the scorer entirely — blocking a real browser is structurally impossible.

**Current status:** Hardened prototype — security-hardened, extensively tested, enterprise-featured. Not yet field-validated in production.

## Technology Stack

| Layer | Implementation |
|-------|---------------|
| **Python proxy core** (~26k LOC) | `proxy.py` + `src/security/` — TLS parsing, JA4 fingerprinting, signal modules, pipeline, rate limiting |
| **Go proxy core** (~9.5k LOC) | `cmd/proxy/` + `internal/` — **production implementation**, high-throughput replacement (15,000+ conn/s vs 2,184 conn/s Python) |
| **Tests** (~60k LOC) | ~2,948 tests — unit, integration, chaos, adversarial, performance |
| **Management UI** | FastAPI + web frontend (`src/management/`) |
| **Analytics** | Prometheus + Grafana + Loki + Alertmanager |
| **Infrastructure** | Docker Compose, Kubernetes (Helm), systemd/Quadlets (RHEL) |

**Language versions:** Python 3.11+ (target 3.14), Go 1.25.0

## Architecture

```
Internet ──TLS──▶ HAProxy (LB) ──TCP──▶ JA4proxy ×N ──TLS──▶ Backend (HTTPS)
                      :443                  :8080               :443
                                              │  ▲
                           write events       │  │  write findings
                           (Redis Stream)     ▼  │  (Redis keys)
                                         ┌──────────────┐
                                         │  Analytics   │──▶ Prometheus
                                         │    Node      │
                                         └──────────────┘
                                         ┌──────────────┐
                                         │  Management  │  FastAPI + React
                                         │     UI       │  :8090
                                         └──────────────┘
```

**Security Pipeline (connection decision flow):**
```
TCP accept → IP trust & normalisation → GeoIP country block → CIDR block → Spamhaus DROP/EDROP
    → ALPN browser bypass (h2/h1 → ALLOW) → JA4 whitelist/blacklist → mTLS cert check
    → TLS enforcement (1.0/1.1/SSLv3 → BLOCK)
    → Signal collection (8 parallel checks: TLS, SNI, TCP, ASN, FCrDNS, rate limit, AbuseIPDB, RDAP)
    → Attacker attribution → Behavioural analysis
    → Risk scorer (0-100) → Action decider (score × dial) → allow/flag/rate-limit/tarpit/block/ban
```

## Key Directories

| Path | Contents |
|------|----------|
| `proxy.py` | Python proxy entry point (experimental prototype only) |
| `cmd/proxy/` | Go proxy main entry point (**production**) |
| `internal/` | Go proxy internal packages |
| `src/security/` | Python signal modules (prototyping surface) |
| `src/ja4/` | JA4 fingerprint computation |
| `src/cache/` | Caching layer (Redis, local) |
| `src/management/` | Management API (FastAPI) |
| `src/analytics/` | Analytics node |
| `src/config/` | Configuration loading |
| `tests/` | Unit, integration, chaos, adversarial tests |
| `docs/phases/` | Phase-driven development docs (manifest, phase files) |
| `config/proxy.yml` | Main configuration file |
| `docker/` | Dockerfiles and Compose files |
| `deploy/helm/` | Kubernetes Helm chart |
| `scripts/` | Operational and development scripts |

## Building and Running

### Prerequisites
- Docker + Docker Compose
- GNU Make
- Python 3.11+ (for local development/testing)
- Go 1.25+ (for building the Go proxy)

### Quick Start
```bash
cp .env.example .env        # Set BACKEND_HOST to your backend
make rebuild                # Clean rebuild — wipes volumes and images, then starts
make update-geoip           # Download IP2Location country database (needed for GeoIP blocking)
```

### Running
```bash
make start                  # Start full stack (proxy + monitoring: Prometheus/Grafana/Loki)
make stop                   # Stop all services (keep Redis data)
make stop-clean             # Stop + wipe volumes (fresh slate)
make status                 # Show health of all services + security state
```

### Building Go Proxy
```bash
make go-build               # Build Go proxy binary to bin/ja4proxy
make go-start               # Start Go proxy alongside Python proxy (for parity comparison)
make go-test                # Run all Go unit tests
make go-lint                # Run go vet on Go code
```

### Testing
```bash
make test                   # Run all tests locally in parallel (fast, no Docker)
make test-unit              # Run unit tests only
make test-chaos             # Run chaos/resilience tests only
make test-adversarial       # Run adversarial/fuzz tests only
make test-docker            # Run tests inside Docker (CI / clean environment)
make test-live              # Run full suite including live-service tests (requires proxies + Redis)
make lint-static            # Phase 16f gates: mypy + bandit + ruff + pip-audit
make lint-all               # Run every linter in one shot
```

### Benchmarking
```bash
make bench                  # Full Go vs Python benchmark suite
make bench-go               # Go proxy only benchmark
make bench-python           # Python proxy only benchmark
make bench-quick            # Quick benchmark, 10s/scenario
```

### Linting & Quality
```bash
make lint-static            # mypy + bandit + ruff + pip-audit (no Docker)
make lint-docker            # hadolint + docker compose config
make lint-shell             # shellcheck all .sh scripts
make lint-yaml              # yamllint config/ and monitoring/ YAML
make lint-go-full           # golangci-lint full suite
make lint-secrets           # gitleaks scan of git history
make lint-all               # Run every linter in one shot
```

### Incident Response (No Restart Needed)
```bash
make attack-status          # Quick security snapshot (active bans, block rate)
make block-ja4 FP=...       # Blacklist a JA4 fingerprint (instant TCP RST)
make block-ip  IP=...       # Hard-block an IP for 1 hour
make unblock-ip IP=...      # Remove all blocks for an IP
make flush-redis            # Reset bans/blocks/rates (keeps blacklist/whitelist)
make top-attackers          # Top 10 fingerprints by traffic right now
```

## Development Conventions

### Phase-Driven Development

The project uses a **Manifest-Driven Roadmap** via `docs/phases/manifest.yaml`. All work is organized into numbered phases. When starting work:

1. **Read `docs/phases/manifest.yaml`** to understand current phase status
2. **Read the relevant `docs/phases/PHASE_XX.md`** for detailed mandate
3. **Follow the Mandatory Planning Protocol** (see `AGENTS.md`):
   - Write a plan document before any code
   - Wait for explicit user approval
   - Implement only after approval
4. **Phase Close-Out Checklist** (see `AGENTS.md` for full details):
   - Tests pass: `make test` — zero failures, zero warnings
   - Go tests pass: `make go-test` — zero failures
   - Update CHANGELOG.md, REDIS_SCHEMA.md
   - Run `make check-scores` (if signal scores change)
   - Run `make parity-check` (if scoring/pipeline logic changes)
   - Update manifest.yaml status to COMPLETE
   - Run `make sync` (regenerate TODO.md and PROJECT_STATUS.md)
   - Run `make lint-phases` — must exit 0
   - Atomic commit of all artifacts

### Python/Go Parity

The project maintains **two complete proxy implementations** that must produce identical decisions for identical inputs:

- **Python** (`proxy.py`, `src/security/`) — experimental prototyping surface
- **Go** (`cmd/proxy/`, `internal/`) — **production implementation**

**Rules:**
- New signals are prototyped in Python first
- Once stable, port to Go before phase can be marked COMPLETE
- Signal scores must match `config/signal_scores.yml` exactly
- `make check-scores` must exit 0 for any phase touching scores
- `make parity-check` validates live decision parity (both proxies running)

### Go Build Environment Note

The snap Go installation requires `GOROOT=/snap/go/current`. All `go` commands need:
```bash
GOROOT=/snap/go/current go build ./...
GOROOT=/snap/go/current go test ./...
```

### Testing Practices

- **TDD mandatory:** Search for existing tests before modifying code. Reproduce bugs with new tests first.
- **Zero tolerance:** No skipped tests, no warnings, zero failures.
- **Web services require:** (1) HTML page rendering tests, (2) Container configuration parity tests.
- **ProxyServer test stubs:** Four stubs must be updated together when `__init__` attributes change (see `AGENTS.md` for details).
- **New files must pass ruff/mypy immediately:** Run `python3 -m ruff check --select I001 --fix <file>` and `python3 -m mypy <file>` after creation.
- **Go files must pass vet immediately:** Run `GOROOT=/snap/go/current go vet ./...` after creation.

### Security & Coding Standards

- **Logging:** Never use f-strings or `.format()` in logging calls. Use lazy formatting: `logger.info("Connection from %s", ip)`.
- **Exception handling:** Never use broad `except Exception:` blocks. Catch specific exceptions. Fail-open for enrichment failures.
- **Secrets:** Never log, print, or commit API keys, Redis passwords, or TLS private keys.
- **Naming:** Follow `docs/STYLE_GUIDE.md` — `PascalCase` for classes, `snake_case` for metrics with `ja4proxy_` prefix.

### Git & Version Control

- **Never commit directly to `main`** — always work on `phase-XX-description` branches
- **Atomic commits:** One commit per phase or logical sub-task
- **Commit messages:** Follow format `type(scope): brief description` (e.g., `feat(security): add JA4X fingerprinting`)
- **Push only when phase is fully complete** — orchestrator handles merging to `main`

### File Ownership (Multi-Agent)

| File | Rule |
|------|------|
| `Makefile` | Add new named target at bottom. Do NOT edit existing targets |
| `README.md` | Add section under `## Phase XX`. Do not edit other sections |
| `CHANGELOG.md` | Prepend new entry at top only |
| `requirements.txt` | Add new deps at bottom with `# phase-XX` comment |
| `config/proxy.yml` | Only edit keys your phase introduces. Comment `# phase-XX` |
| `docs/phases/manifest.yaml` | Edit ONLY to mark your phase COMPLETE |
| `docker-compose*.yml` | Only edit if your phase requires new service. Add at bottom |

## Key Commands Reference

| Goal | Command |
|------|---------|
| Start development stack | `make start` |
| Clean rebuild | `make rebuild` |
| Run all tests | `make test` |
| Run Go tests | `make go-test` |
| Build Go proxy | `make go-build` |
| Start Go proxy | `make go-start` |
| Check signal score parity | `make check-scores` |
| Live parity check | `make parity-check` |
| Generate test traffic | `./scripts/generate-tls-traffic.sh 60 10 20` |
| Open Grafana | `http://localhost:3001` |
| Update GeoIP database | `make update-geoip` |
| Flush Redis state | `make flush-redis` |
| Sync roadmap docs | `python3 scripts/sync-roadmap.py` |
| Lint phase docs | `make lint-phases` |

## Default Ports

| Service | Port | Notes |
|---------|------|-------|
| HAProxy | `:443` | TLS passthrough, PROXY protocol v2 |
| HAProxy stats | `:8404/stats` | |
| JA4proxy | `:8080` (proxy) · `:9090` (metrics) | |
| Mock backend | `:8443` | Test-only |
| Tarpit | `:8888` | |
| Prometheus | `:9091` | |
| Grafana | `:3001` | Credentials in `.env` |
| Loki | `:3100` | |
| Alertmanager | `:9093` | |
| Management UI | `:8090` | FastAPI + web frontend |

## Documentation

- **[Documentation Index](docs/README.md)** — all docs organised by role
- **[POC Quick Start](docs/POC_QUICKSTART.md)** — step-by-step from zero to traffic
- **[Go Proxy Developer Guide](docs/developer/go_proxy_guide.md)** — building, testing, extending Go proxy
- **[Signal Development Guide](docs/developer/SIGNAL_DEVELOPMENT.md)** — implementing new signal modules
- **[Monitoring Setup](docs/MONITORING_SETUP.md)** — Prometheus/Grafana/Loki/Alertmanager
- **[CHANGELOG](CHANGELOG.md)** — version history

## Enterprise Integration (Phases 79–86)

The enterprise phases deliver integration surface for regulated-industry buyers:

| Phase | Deliverable |
|-------|------------|
| 79 | Management API v2, RBAC, SSO (OIDC/SAML) |
| 80 | ECS 8.x log format + SIEM connectors (Splunk, QRadar, Sentinel, Elastic) |
| 81 | SOAR playbooks + ops platform integrations |
| 82 | Policy-as-Code, shadow mode, four-eyes dial approval |
| 83 | CLI binary, Terraform provider, Kubernetes operator + CRDs |
| 84 | ISO 27001 / SOC 2 evidence pack |
| 85 | TAXII 2.1 / MISP threat intel ingestion |
| 86 | Grafana enterprise dashboards, SLO burn-rate alerting |

Phase 79 is the critical path — every subsequent enterprise phase depends on it.
