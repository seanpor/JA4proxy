---
phase: 220
title: Remote Manual Testing Enablement — Browser, curl, Bot, Logs, Dashboards
status: COMPLETE
size: SMALL
created: 2026-06-04
completed: 2026-06-09
audience: [developer, qa]
---

> **Outcome (COMPLETE — 2026-06-09, salvaged from PR #82 and security-tightened).**
> Delivered: `scripts/test-bot.py` (stdlib TLS test bot), `make remote-bot`, and
> `docs/runbooks/REMOTE_TESTING.md`.
>
> **The plan below described a new `docker-compose.remote.yml` that binds every
> port to `0.0.0.0` — that was dropped as both redundant and unsafe.** Review
> during salvage found the existing `docker-compose.poc.yml` *and*
> `docker-compose.monitoring.yml` already bind every service to
> **`AGENT_BIND_IP` (default `127.0.0.1`)**, and `scripts/start-poc.sh` already
> validates it via `scripts/check_bind_address.py` (refuses a public/`0.0.0.0`
> bind). So remote access needs no special stack: set `AGENT_BIND_IP` to the
> server's private LAN IP in `.env`, run `make start`, then `make remote-bot`.
> Where the body below references `docker-compose.remote.yml` or
> `make remote-start`, read it as this existing, safer mechanism.
---

# Remote Manual Testing Enablement

## Goal

Enable a remote developer (laptop, browser, curl, a test bot) to exercise the
full JA4proxy stack end-to-end and observe every connection through logs,
the Management UI, and Grafana dashboards. Currently everything binds to
`127.0.0.1` — this phase adds the scripts, override config, and documentation
to safely expose ports, run a simple bot, and verify all services are reachable
from a remote host.

## Scope

| File | Change |
|------|--------|
| `deploy/docker/docker-compose.remote.yml` | **Create** — compose override that sets `AGENT_BIND_IP=0.0.0.0` for POC services and overrides monitoring port bindings to `0.0.0.0` |
| `scripts/test-bot.py` | **Create** — lightweight stdlib-only Python bot that connects through the proxy, exercises allowed/blocked paths, and prints per-connection results |
| `docs/runbooks/REMOTE_TESTING.md` | **Create** — complete runbook for the remote tester |
| `Makefile` | **Modify** — add `remote-start`, `remote-stop`, `remote-status`, `remote-bot` targets |
| `docs/phases/manifest.yaml` | **Modify** — register Phase 220 under QA epic |

## Implementation plan

1. **Create `deploy/docker/docker-compose.remote.yml`** — a standalone override:
   - Sets `AGENT_BIND_IP=0.0.0.0` for every POC service that reads it (haproxy, proxy, management, analytics, admin-api)
   - Overrides monitoring port bindings to use `0.0.0.0` instead of `127.0.0.1` (Prometheus `:9091`, Grafana `:3001`, Alertmanager `:9093`)
   - Does NOT expose Redis, backend, or tarpit host ports (no value for remote testing)
   - Adds YAML comments documenting every port and its purpose

2. **Create `scripts/test-bot.py`** — a simple, dependency-free bot:
   - Uses only Python stdlib (`ssl`, `socket`, `http.client`, `argparse`)
   - Connects to the proxy at a given host:port
   - Sends HTTP requests through the CONNECT tunnel
   - Exercises: allowed route, blocked route (malicious JA4), health check
   - Prints per-connection result: `✓ ALLOWED`, `✗ BLOCKED`, latency, JA4 fingerprint
   - Exits non-zero if any unexpected result occurs
   - Run: `python3 scripts/test-bot.py --proxy-host <host> --proxy-port 443`

3. **Create `docs/runbooks/REMOTE_TESTING.md`**:
   - Prerequisites (`.env` with `GRAFANA_PASSWORD`, `REDIS_PASSWORD`, `UI_PASSWORD`, etc.)
   - Quick start: `make remote-start && make remote-status`
   - Port reference table (what each port does, what protocol)
   - Browser: Management UI at `http://<host>:8090/login`, Grafana at `http://<host>:3001/login`
   - Curl examples through HAProxy (`curl -k https://<host>:443`) and direct proxy (`curl -k https://<host>:8081`)
   - Bot: `python3 scripts/test-bot.py --proxy-host <host>`
   - Logs: Grafana → Explore → Loki, or `docker compose logs proxy -f`
   - Dashboards: Grafana "JA4 Proxy Security Dashboard"
   - Security: always run `make remote-stop` when done, never leave exposed in production
   - Troubleshooting: common failures (wrong password, port blocked, Docker not running)

4. **Add Makefile targets**:
   ```makefile
   remote-start:
       @docker compose -f deploy/docker/docker-compose.poc.yml \
           -f deploy/docker/docker-compose.monitoring.yml \
           -f deploy/docker/docker-compose.remote.yml up -d
       @echo "✓ Remote stack started — all ports on 0.0.0.0"

   remote-stop:
       @docker compose -f deploy/docker/docker-compose.poc.yml \
           -f deploy/docker/docker-compose.monitoring.yml \
           -f deploy/docker/docker-compose.remote.yml down

   remote-status:
       @./scripts/status.sh

   remote-bot:
       @python3 scripts/test-bot.py --proxy-host $(HOST) --proxy-port $(PORT)
   ```

5. **Register in manifest.yaml** — add Phase 220 to "Quality Assurance & Test Maturity" epic.

## Test strategy

- **Smoke:** `make remote-start` → `ss -tlnp` confirms ports bound to `0.0.0.0`, not `127.0.0.1`
- **Curl from local:** `curl -sk https://localhost:443` returns backend response
- **Curl from remote:** `curl -sk https://<remote-ip>:443` returns same response
- **Management UI:** `curl -s http://<remote-ip>:8090/login` returns 200 + HTML login page
- **Grafana:** `curl -s http://<remote-ip>:3001/login` returns 200 + Grafana HTML
- **Prometheus:** `curl -s http://<remote-ip>:9091/api/v1/query?query=up` returns valid JSON
- **Bot (local):** `python3 scripts/test-bot.py --proxy-host localhost --proxy-port 8081` passes
- **Bot (remote):** same command against `<remote-ip>:443` passes
- **Logs:** `curl -s "http://<remote-ip>:3001/api/ds/query?ds_type=loki"` returns recent log entries

## Acceptance criteria

- [ ] `make remote-start` binds all POC + monitoring ports to `0.0.0.0`
- [ ] `make start` still binds to `127.0.0.1` (no regression)
- [ ] Management UI reachable at `http://<remote-ip>:8090` — login page renders
- [ ] Grafana reachable at `http://<remote-ip>:3001` — dashboard loads
- [ ] Proxy accepts TLS connections on `:443` (HAProxy) and `:8081` (direct) from remote
- [ ] `scripts/test-bot.py` runs successfully against both localhost and remote proxy
- [ ] Test bot output shows per-connection verdicts (ALLOWED/BLOCKED), latency, and JA4
- [ ] Loki logs show proxy container logs in Grafana Explore
- [ ] `docs/runbooks/REMOTE_TESTING.md` covers all URLs, ports, auth, bot, and log-viewing steps
- [ ] `make lint-phases` exits 0
- [ ] `make test` passes (no code changes)

## Out of scope

- SSH tunnel / VPN setup (direct `0.0.0.0` binding is the intended approach)
- TLS certificate changes (self-signed is fine for testing)
- Authentication hardening beyond existing JWT/Grafana/UI passwords
- CI/CD pipeline changes
- Multi-agent isolation changes
- Production deployment guidance
- Epic assignment for unassigned pre-existing phases (separate cleanup)
