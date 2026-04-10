# Phase 64a Notes — Docker Compose Smoke Test

## What was created

1. **`scripts/smoke/test_docker_compose.sh`** — A bash smoke test that validates
   a Docker Compose deployment end-to-end: stack startup, health check polling,
   container state verification, synthetic TLS probe, and teardown.

2. **`tests/test_phase64a_smoke_docker.py`** — TDD validation of the smoke script's
   structural correctness. Runs under pytest without Docker. Checks: file existence,
   executable bit, shebang, strict mode, docker compose v2 syntax, results directory
   creation, health URL default, result file output, and teardown command.

3. **Makefile target `smoke-docker`** — Appended at the bottom; runs the smoke script.

## Design decisions

- The script uses `docker compose` (v2 space-separated syntax), never the legacy
  `docker-compose` (v1 hyphenated binary). The test enforces this.
- Health polling uses a 60-second timeout with 1-second intervals.
- The synthetic TLS connection treats any TLS-layer response as success; only
  `Connection refused` is treated as failure (the proxy may legitimately reject
  the handshake for policy reasons).
- Teardown always runs `docker compose down -v` to remove volumes.
