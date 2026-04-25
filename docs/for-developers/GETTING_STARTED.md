<!--
title: "Getting Started — 30 Minutes to Productive"
audience: developers
last_reviewed: 2026-04-25
phase: 105
-->

# Getting Started

This page is the **30-minute path** from a fresh clone to a green local test
run. For deeper material on project structure, code style, and the
completing-a-phase mechanics, see [`../../CONTRIBUTING.md`](../../CONTRIBUTING.md);
this doc does not duplicate that content.

> **Production runtime is the Go proxy.** The Python proxy (`proxy.py`,
> `src/security/`) is a **prototyping surface** for new signal modules.
> Default to the Go side unless your task is explicit Python prototyping
> or fixing the Python prototype itself.

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Go | 1.25.9 | Production runtime; matches `go-version: "1.25.9"` in `.github/workflows/ci.yml` |
| Python | 3.14 | Matches the CI Python version |
| Docker + Docker Compose v2 | latest | Smoke tests, integration tests, local stack |
| Redis Stack | 7.x | `docker run -p 6379:6379 redis/redis-stack-server:latest` is fine for dev |
| `make` | GNU make | All entry points are Make targets |

Optional but recommended:

- `latexmk` / `tectonic` (only if you touch `docs/pdf/`)
- `gh` CLI for PR work
- `direnv` / a clean shell for `GOROOT` (see Troubleshooting)

## Clone, build, test (the happy path)

```bash
git clone https://github.com/anomalyco/JA4proxy.git
cd JA4proxy

# 1. Python deps (test infrastructure runs in Python)
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 2. Build the Go proxy
GOROOT=/snap/go/current go build ./cmd/proxy

# 3. Run the full test suite
make test
```

A clean run ends with all sections green:

```
✓ mypy: OK
✓ bandit: OK
✓ ruff: OK
✓ pip-audit: OK
... 2700+ passed, N skipped (all approved), 0 failed
```

If `make test` is green, your environment is correctly configured. Move on to
[`HOW_WE_WORK.md`](HOW_WE_WORK.md) before writing any code.

## Run the proxy locally

```bash
# Start Redis and the backend stack
make start

# In a separate shell, run the Go proxy directly against the running stack
GOROOT=/snap/go/current go run ./cmd/proxy

# Smoke test
bash scripts/smoke/test_docker_compose.sh

# Stop the stack
make stop
```

The Python proxy entry point (`proxy.py`) is intentionally not part of the
default workflow — it exists only when you are prototyping a new signal.

## What to read next

1. [`HOW_WE_WORK.md`](HOW_WE_WORK.md) — branch flow, keep-main-green, commit
   conventions. Read this **before** opening a branch.
2. [`TDD_AND_TESTING.md`](TDD_AND_TESTING.md) — the test-first loop and the
   matrix of test categories.
3. [`../../CONTRIBUTING.md`](../../CONTRIBUTING.md) — project structure, code
   style, completing-a-phase mechanics. Use as a reference, not a tutorial.
4. [`PHASE_LIFECYCLE.md`](PHASE_LIFECYCLE.md) — only relevant if your work is
   organised as a phase; see also [`../../AGENTS.md`](../../AGENTS.md).

## Troubleshooting

### Docker not installed or daemon not running

`make start` fails with `Cannot connect to the Docker daemon`. Install Docker
Engine and ensure `docker info` succeeds before trying again. On Linux, your
user must be in the `docker` group.

### Redis port 6379 already occupied

Another Redis (system service, dev container, or stale `docker run`) is bound
to 6379. Either stop it (`sudo systemctl stop redis-server` or `docker rm -f
<container>`) or override the port:

```bash
REDIS_URL=redis://localhost:6380/0 make test
```

If you reuse an existing local Redis, run `redis-cli FLUSHDB` first — stale
keys from earlier runs cause confusing test failures.

### `go: cannot find GOROOT directory: /usr/share/go`

The snap installation of Go sets `GOROOT=/usr/share/go`, which does not exist
on this host. Every `go` invocation must use the real GOROOT:

```bash
GOROOT=/snap/go/current go build ./...
GOROOT=/snap/go/current go test ./...
```

Or set it permanently:

```bash
echo 'export GOROOT=/snap/go/current' >> ~/.bashrc
source ~/.bashrc
```

### `pytest` collection error: `empty test body`

The conftest enforces non-empty tests. A test with only `pass` or a docstring
exits collection with code 3. Add a real assertion or remove the placeholder.

### `make test` is green locally but red in CI

Almost always means a test reaches an external service that exists on your dev
machine but not in CI (commonly Redis on `localhost:6379`). See the "Unit
tests must mock every external service" section of `AGENTS.md` and the
"Dev-vs-CI environment divergence" guidance in [`HOW_WE_WORK.md`](HOW_WE_WORK.md).
