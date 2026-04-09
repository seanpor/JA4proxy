# QWEN.md — JA4proxy Project Context

## Project Overview

**JA4proxy** is a TLS-aware passthrough security proxy that blocks bots, C2 frameworks, and scanners at the TLS layer — without decrypting a single byte. It sits between a load balancer (HAProxy) and the backend server, inspects the plaintext TLS ClientHello metadata, computes a [JA4 fingerprint](https://github.com/FoxIO-LLC/ja4), runs it through a multi-signal scoring pipeline, and makes allow/block decisions before the TLS handshake completes.

**Key properties:**
- **0% false positive rate** on browser traffic — `h2`/`h1` ALPN bypasses the scorer entirely (architectural guarantee)
- **94–99% malicious traffic blocked** across test runs
- **Never terminates TLS, never holds keys, never sees decrypted payloads**
- **Dial = 0** by default (monitor-only mode); blocking is opt-in and incremental
- All bans carry a **5-minute TTL** — false positives self-heal automatically

### Two Implementations

| | Python (`proxy.py`, `src/`) | Go (`cmd/proxy/`, `internal/`) |
|---|---|---|
| **Role** | Experimental prototyping surface | **Production runtime** |
| **Throughput** | ~2,184 conn/s | 15,000+ conn/s |
| **Use when** | Iterating new signal modules quickly | Shipping to production |

When making changes, **default to the Go side**. Touch Python only when the task explicitly involves prototyping, signal-module research, or fixing the Python prototype itself.

---

## Building and Running

### Quick Start

```bash
cp .env.example .env        # set BACKEND_HOST to your backend
make start                  # proxy + monitoring stack (Docker Compose)
make update-geoip           # download IP2Location country database
```

### Key Commands

```bash
# Development
make build                  # Build Docker images (incremental)
make rebuild                # Clean rebuild — wipe volumes + images, then start
make stop                   # Stop, keep Redis state
make stop-clean             # Stop + wipe volumes (fresh slate)

# Testing
make test                   # Run all tests (fast, no Docker — parallel)
make test-unit              # Unit tests only
make test-chaos             # Chaos/resilience tests
make test-adversarial       # Adversarial/fuzz tests
make test-docker            # Tests inside Docker (CI)

# Go proxy
make go-build               # Build Go binary to bin/ja4proxy
make go-test                # Go unit tests
make go-lint                # go vet
make go-start               # Start Go proxy alongside Python (parity comparison)
make go-parity              # Cross-language parity tests (both proxies running)

# Linting & Static Analysis
make lint                   # black + flake8 + mypy
make lint-static            # mypy + bandit + ruff + pip-audit
make lint-go-full           # golangci-lint (errcheck, staticcheck, ineffassign, govet, unused)
make lint-phases            # Phase doc validation
make lint-secrets           # gitleaks scan

# Signal Scores & Parity
make check-scores           # Audit Python/Go signal scores against config/signal_scores.yml
make parity-check           # Live end-to-end decision parity (both proxies must be running)

# Operations
make dial LEVEL=50          # Set blocking dial via pubsub
make flush-redis            # Reset bans/blocks/rates
make block-ja4 FP=...       # Blacklist a JA4 fingerprint
make block-ip IP=...        # Hard-block an IP
make unblock-ip IP=...      # Remove all blocks for an IP

# Monitoring
make start-monitoring       # Start Prometheus/Grafana/Loki stack
# Grafana: http://localhost:3001
```

### Python Environment

```bash
pip install -r requirements.txt
pip install -r requirements-test.txt
pip install -r requirements-analytics.txt
```

---

## Architecture

```
Internet ──TLS──▶ HAProxy (:443) ──TCP──▶ JA4proxy (:8080) ──TLS──▶ Backend
                                              │  ▲
                           Redis ("bans, lists, rates")   │
                                              ▼  │
                                      Prometheus · Grafana · Loki
```

### Security Pipeline (per connection)

```
TCP accept
  ├── Layer 0:  IP trust & normalisation (PROXY protocol, IPv4/IPv6)
  ├── Layer 0b: Static IP allowlist    → ALLOW
  ├── Layer 0c: GeoIP country block    → BLOCK
  ├── Layer 0d: CIDR block             → BLOCK
  ├── Layer 0e: Spamhaus DROP/EDROP    → BLOCK
  ├── Layer 1:  ALPN browser bypass (h2/h1) → ALLOW (never scored)
  ├── Layer 1b: JA4 whitelist          → ALLOW
  ├── Layer 1c: mTLS client cert       → ALLOW
  ├── Layer 2:  JA4 blacklist          → BLOCK (TCP RST)
  ├── Layer 3:  TLS enforcement (1.0/1.1/SSLv3 → BLOCK)
  ├── Layers 4–8: Signal collection (TLS, SNI, TCP, ASN, FCrDNS, rate, beaconing)
  ├── Layer 9:  Attacker attribution (JA4+JA4X+JA4T correlation)
  ├── Layer 10: Behavioural analysis (sequential probing, coordinated bursts)
  ├── Layer 11: Risk scorer (confidence-weighted → 0–100)
  └── Layer 12: Action decider (score × dial → allow/flag/rate-limit/tarpit/block/ban)
```

### Core Asymmetry

**False positives are far more costly than false negatives.** When in doubt, fail open. This governs every caching TTL, threshold default, and fallback behaviour.

---

## Project Structure

| Directory | Purpose |
|-----------|---------|
| `proxy.py` | Python proxy entry point (prototyping) |
| `src/` | Python proxy core — security signals, caching, config, JA4, TLS parsing, management API, analytics |
| `cmd/proxy/` | Go proxy entry point (production) |
| `internal/` | Go proxy core — mirrors `src/` structure |
| `tests/` | Test suite — unit, integration, chaos, adversarial, performance, compliance (~2,948 tests) |
| `config/` | `proxy.yml` (proxy config), `signal_scores.yml` (canonical score registry) |
| `docs/` | Documentation — phases, architecture, runbooks, security audits, compliance |
| `docs/phases/` | Phase-driven development — manifest-driven roadmap |
| `docker/` | Docker Compose files |
| `deploy/helm/` | Kubernetes Helm chart |
| `scripts/` | Admin CLI, traffic generators, sync tools |
| `Makefile` | All build/test/ops commands |
| `docker-compose.poc.yml` | Main compose file for dev stack |

---

## Development Workflow

### Phase-Driven Development

This project uses a **manifest-driven roadmap**. Every feature/change lives in a numbered phase.

1. **Check `docs/phases/manifest.yaml`** for the next available phase number and current status.
2. **Create `docs/phases/PHASE_XX.md`** using the standard template before writing any code.
3. **Wait for explicit user approval** before implementing.
4. **Implement** on a named branch: `claude/phase-XX-description`
5. **Close out** following the checklist in AGENTS.md (tests pass, lint clean, changelog updated, manifest updated, sync script run).

**Roadmap sync:** After any manifest change, run `python3 scripts/sync-roadmap.py` to regenerate `docs/phases/TODO.md` and `docs/PROJECT_STATUS.md`.

**Validation:** Run `make lint-phases` — must exit 0 before any phase close-out.

> **Reference:** The Phase Index table in CLAUDE.md is a static reference. For current status, always read `docs/phases/manifest.yaml` or `docs/phases/TODO.md`.

### Git Rules

- **Named branches only** — never commit directly to `main`. The orchestrator handles merging.
- **Atomic commits** — one commit per phase or logical sub-task.
- **Commit format:** `type(scope): brief description` (e.g., `feat(security): add JA4X fingerprinting`).
- **File ownership:** Only edit files within your phase's scope. Follow the rules in AGENTS.md for shared files.

### Testing Standards

- **TDD is mandatory.** A change is incomplete without corresponding tests.
- **Zero tolerance:** No skipped tests, no warnings, no errors, no failures.
- **`make test` runs four static-analysis tools BEFORE pytest:** mypy, bandit, ruff, pip-audit. All must pass.
- **HTML page rendering tests** and **container configuration parity tests** are mandatory for every web service route.
- **Go tests:** `make go-test` — required for any phase touching Go source.

### Linting

All linting must pass with zero warnings:
```bash
make lint-static            # Python: mypy + bandit + ruff + pip-audit
make lint-go-full           # Go: golangci-lint
make lint-phases            # Phase docs validation
```

### Go/Python Parity

The two proxy implementations must produce **identical decisions for identical inputs**:
1. Update `config/signal_scores.yml` first (canonical source).
2. Implement in Python, then Go.
3. `make check-scores` — must exit 0.
4. `make parity-check` — both proxies running, must exit 0.

### GOROOT Note

The snap Go installation requires:
```bash
export GOROOT=/snap/go/current
```
All `go` commands need this set. Add it to `~/.bashrc` for permanence.

---

## Key Configuration Files

| File | Purpose |
|------|---------|
| `config/proxy.yml` | Main proxy configuration — security policies, whitelists, rate limits, GeoIP settings |
| `config/signal_scores.yml` | **Single authoritative source** for all signal score values |
| `.env` / `.env.example` | Environment variables — backend host, Redis password, Grafana password, API keys |
| `pyproject.toml` | Python tool config (pytest, ruff, targets) |
| `go.mod` | Go module definition |
| `mypy.ini` | Python type checking config |

---

## Documentation Standards

See `docs/DOCUMENTATION_STANDARDS.md` for full details. Every phase completion requires:

1. **CHANGELOG.md** — standard entry under correct version
2. **docs/REDIS_SCHEMA.md** — document every new key, type, TTL, owner
3. **README.md** — update Security Pipeline or Services tables if architecture changed
4. **ADRs** — create new Architectural Decision Record in `docs/decisions/` for non-obvious design choices

---

## Ports (Local Dev Stack)

| Service | Port | Notes |
|---------|------|-------|
| HAProxy | `:443` | TLS passthrough, PROXY protocol v2 |
| HAProxy stats | `:8404` | |
| JA4proxy | `:8080` (proxy) · `:9090` (metrics) | |
| Mock backend | `:8443` | Test-only |
| Tarpit | `:8888` | |
| Prometheus | `:9091` | |
| Grafana | `:3001` | |
| Loki | `:3100` | |
| Alertmanager | `:9093` | |

---

## Coding Standards

### Python
- **Logging:** Never use f-strings or `.format()` in logging calls. Use lazy formatting: `logger.info("Connection from %s", ip)`
- **Exceptions:** Never use broad `except Exception:` blocks. Catch specific exceptions.
- **Fail-Open:** If external API/Redis fails, log WARNING, increment counter, allow connection.
- **Naming:** `PascalCase` classes, `snake_case` functions/metrics with `ja4proxy_` prefix.

### Go
- All code must compile with zero warnings (`GOROOT=/snap/go/current go build ./...`)
- Follow `go fmt` conventions
- Mirror Python proxy's security signal structure

### Security
- Never log, print, or commit API keys, Redis passwords, or TLS private keys.
- Check `.env.example` for required variables.
- Secrets management via `secrets/` directory.

---

## AI Agent Instructions

When working on this project with Qwen Code:

1. **Read AGENTS.md first** — it contains the mandatory planning protocol, tool usage rules, file ownership conventions, and the phase close-out checklist.
2. **Read the specific phase file** in `docs/phases/PHASE_XX.md` for the current work.
3. **Follow the planning protocol** — write the plan document first, wait for approval, then implement.
4. **Output language:** Always respond in **English** (per output-language.md).
5. **Default to Go** for implementation work unless the task explicitly requires Python.
