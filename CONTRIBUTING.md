# Contributing to JA4proxy

## Prerequisites

- **Go 1.26+** (Required for the proxy core)
- **Python 3.14** (Required for the Management API and Analytics node)
- **Docker and Docker Compose v2**
- **Redis Stack** (For local development: `docker run -p 6379:6379 redis/redis-stack-server:latest`)

## Day 1: Get Up and Running

```bash
# Clone the repository
git clone https://github.com/seanpor/JA4proxy
cd JA4proxy

# Initialize environment
cp template.env .env

# Build the Go proxy
make build

# Run the test suite
make test-go test-unit
```

## Read First

Before writing any code:

1. **`CLAUDE.md`** — architecture overview, phase index, and cross-cutting requirements.
2. **`docs/phases/`** — Look for the active phase document you are working on.
3. **`docs/developer/STYLE_GUIDE.md`** — coding standards, log formats, and documentation requirements.

## Project Structure

JA4proxy is a Go-centric security stack. All legacy Python proxy components have been archived.

### Production runtime — Go (The Proxy Core - Performance Critical)

The Go implementation handles 100% of production traffic. It is built for sub-millisecond latency and high-concurrency.

```
cmd/ja4pd/main.go               # Production proxy entry point
internal/
  proxy/                        # TCP forwarder, PROXY protocol parsing
  security/                     # Pipeline orchestration and signal modules
  tls/                          # ClientHello parser, JA4 computation
  redis/                        # Redis client (fail-open), Lua scripts
  cache/                        # LRU cache
  config/                       # Hot-reload config loader
  metrics/                      # Prometheus metrics
  logging/                      # Structured (logrus) logging
  compliance/                   # Compliance reporter integration
  webhook/                      # Webhook delivery
  cli/                          # CLI subcommands
bin/ja4p                       # Built artifact (Go static binary)
```

### Python Ecosystem (Management & Analytics - Non-Performance Critical)

Python is used for the control plane and data analysis layers where developer velocity and integration flexibility are prioritized over raw packet-processing speed.

```
management/                     # FastAPI Management API (JWT-gated, port 8090)
src/analytics/                  # Redis Stream consumers and TI feed workers
src/tarpit/                     # Tarpit / slow-loris responder
```

### Testing & Quality

We maintain a strict TDD process. Every feature must include:
- Unit tests in the same package (e.g. `internal/security/sni_analyzer_test.go`).
- Integration tests in `tests/integration/`.
- Fuzz targets in `cmd/ja4pd/fuzz_test.go` for all untrusted input boundaries.

## Governance

See [GOVERNANCE.md](GOVERNANCE.md) for details on how the project is managed.

## Security

See [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy.\n