---
phase: 816
title: "Demo environment — end-to-end management console showcase"
status: PROPOSED
size: MEDIUM
created: 2026-08-13
audience: [developer, operator]
---

# Demo environment — end-to-end management console showcase

> **STATUS: PROPOSED — plan for review. No code until approved.**

## Goal (plain language)

Stand up a single-command demo that shows off the whole JA4proxy stack the way
an assessor or stakeholder would want to see it: varied (good + bad) traffic
flowing through the Go proxy, visible live in the **management console**, with
**Prometheus/Grafana** panels moving, and the operator able to **change what
gets blocked in real time** (block/allow fingerprints, IPs, dial the blocking
aggression up/down) — all from the browser UI.

This phase does **not** build the proxy or the console from scratch: they
exist and are mature. Its job is (1) *verify* every piece of the demo loop
actually works end-to-end, (2) fix/glue whatever is missing or broken for a
live demonstration, and (3) deliver the runbook so the demo is repeatable and
safe.

## Context — what already exists (verified on main 2026-08-13)

The stack is 95% there. Almost every capability the demo needs is already
implemented and tested:

| Need | Exists today | Location |
|---|---|---|
| Fake backend | Go null backend (TLS, `:8443`, `/api/health`, `/api/echo`, returns `200 ok`) | `internal/test/nullbackend/main.go`, built by `deploy/docker/Dockerfile.mockbackend` |
| Varied traffic | TLS traffic generator with 8 distinct ClientHello profiles (Chrome/Firefox/Safari legit; Sliver/CobaltStrike/Requests/cred-stuffer/Evilginx/Masscan malicious) + `--fingerprint-mix` buckets | `scripts/tls-traffic-generator.py` (`MIX_BUCKETS` at line 181), `deploy/docker/Dockerfile.trafficgen` |
| Management console | FastAPI service, JWT-cookie auth, RBAC (auditor/analyst/operator/admin), Tailwind+HTMX+Alpine UI, live SSE feed, dial widget, list/ban/audit/threat-intel pages | `management/`, `management/templates/`, `deploy/docker/Dockerfile.management` |
| Live blocking control | `POST/DELETE /api/v1/lists/{ja4,ip}/{whitelist,blacklist,allowlist}/{entry}`, `GET/PUT/PATCH /api/v1/dial`, `POST/DELETE /api/v1/attack-mode`, `POST /api/v1/config/reload` (Redis pub/sub `config:reload`) | `management/api/routes/{lists,dial,attack_mode,config_ops}.py` |
| Prometheus | Full monitoring stack: Prometheus (`:9091`), Grafana (`:3000`, HTTPS, auto-provisioned), Alertmanager, Loki, Promtail, cadvisor, node/redis exporters | `deploy/docker/docker-compose.monitoring.yml`, `deploy/monitoring/` |
| Grafana dashboards | 6 provisioned dashboards incl. **JA4proxy Security Overview** (Connections/sec, Allowed/Blocked, Block Rate, Dial Setting, Action Breakdown, Risk Score Percentiles, TLS distribution, Security Event Log) | `deploy/monitoring/grafana/dashboards/ja4proxy-overview.json` |
| Orchestration | `start-poc.sh` (redis+backend+proxy+tarpit+analytics), `start-monitoring.sh`, `start-all.sh`, lane-aware `.env`/ports | `scripts/`, `deploy/docker/docker-compose.poc.yml` |

### The known gaps (what this phase fixes)

1. **`trafficgen` is not wired into the default demo.** `start-poc.sh:145`
   starts `redis backend proxy tarpit analytics` — `trafficgen` exists in
   compose under `profiles: [traffic]` (`docker-compose.poc.yml:298`) and is
   never started. The demo must run it with a good `--fingerprint-mix`
   (e.g. `browser_alpn=70,automation=20,scanner=5,malicious=5`) and a
   sustained duration so the console/Grafana have something to show.
2. **`management` is also not in the default start list.** `docker-compose.poc.yml:422`
   defines it; `start-poc.sh` doesn't start it. `start-all.sh` starts it — but
   `start-all.sh` also pulls in HAProxy + the full monitoring stack, which is
   heavy and slow for a quick demo. Need a lean `demo` target.
3. **`demo-poc.sh` predates the management console.** It demos with `curl` +
   raw `redis-cli` (whitelist/blacklist via `SADD ja4:...`) and does not
   touch the browser UI at all. The new demo must drive **the management API
   and console**, not Redis directly.
4. **Proxy `dial` defaults to 0 (monitor-only) and `blocking_acknowledged:
   false`** (`config/proxy.yml:437,445`). For a "watch it block" demo we need
   dial raised through the UI during the run — the demo runbook should show
   raising dial from the console, and the demo must tolerate the proxy's
   safety gate (it resets dial to 0 at startup until acknowledged).
5. **Demo data seeding is raw Redis + stale ports.** `populate-grafana-demo-data.sh`
   writes fake lists/blocks/bans straight to Redis with hard-coded container
   names and `:3001` Grafana URL — contradicts the current provisioning
   (lane-prefixed containers, `:3000`). Seeding a clean demo should go through
   the management **API** so it also populates the audit log.
6. **No "data is flowing" verification.** Nothing confirms the SSE live feed,
   Grafana panels, and list changes all actually move when traffic is fired.
   The demo needs a smoke check (and ideally a repeatable regression script)
   that asserts: proxy sees connections, `events:connection` stream grows,
   blacklisted fingerprint gets blocked at dial>0, whitelisted browser passes.

## Scope

**In scope:**

- A `make demo` / `scripts/demo-up.sh` entry point that starts the lean
  demo set (redis, backend, proxy, tarpit, analytics, management, trafficgen)
  and prints the console/Grafana/Prometheus URLs + seeded credentials.
- A demo **orchestration script** (`scripts/demo-mgmt.sh`) that:
  1. starts the stack,
  2. seeds baseline state **via the management API** (a couple of
     whitelisted browser fingerprints + a couple of blacklisted tool
     fingerprints + one long-lived ban),
  3. kicks off sustained varied traffic (`tls-traffic-generator.py` with the
     `--fingerprint-mix` above, running in background),
  4. runs the **end-to-end verification** (below),
  5. prints the live-demo walkthrough (URLs, credentials, what to click in
     order, what to watch in Grafana).
- End-to-end verification script (`scripts/demo-verify.sh`) covering the six
  checks in the gap list (proxy sees traffic, SSE stream grows, blacklist
  blocks at dial>0, whitelist passes, dial change via API takes effect,
  Grafana API returns non-zero series for the demo panels).
- A **demo runbook** `docs/operations/DEMO_MANAGEMENT_CONSOLE.md`: the
  scripted narrative for a live demo (login → watch live feed → block a
  fingerprint from the live feed → watch Grafana blocked/sec move → raise
  dial → activate attack mode → review audit log → clean up).
- **Fixes found while wiring it up**: e.g. if `trafficgen` or the console
  doesn't start cleanly from a fresh checkout, or the SSE feed doesn't
  stream, or list changes don't propagate — fix those. (The current code
  *appears* correct by inspection: trafficgen targets `proxy:8080`, the
  console reads `events:connection` via XREAD, the proxy subscribes to
  `config:reload`. The plan is to prove it, not rebuild it.)
- Tests (see Test strategy) — each fix gets a regression test; the demo
  verify script itself is testable in CI-light mode.

**Out of scope:**

- Rebuilding the management UI or proxy features (they're mature).
- HAProxy / multi-proxy / scale demo (out of demo scope; `start-all.sh` keeps
  serving that).
- The webhook/compliance/enterprise/attacker/Pentest demo ranges.
- Grafana dashboard redesign (existing dashboards are fine; only used as-is).
- Performance benchmarking (that's `benchmark.py`, separate).

## Implementation plan

1. **`scripts/demo-up.sh`** — thin wrapper: `start-poc.sh` (existing) then
   `docker compose ... up -d management trafficgen --profile traffic`, plus
   wait-for-healthy loops for the management API (`/api/v1/health`) and
   Grafana (`/api/health`).
2. **`scripts/demo-mgmt.sh`** — the orchestrated demo:
   - source `.env` (lane-aware),
   - call `demo-up.sh`,
   - login to management API (`POST /api/v1/auth/login`) to get a cookie,
   - seed baseline via API: 2× `ja4/whitelist`, 2× `ja4/blacklist`
     (using the generator's known-fresh fingerprints), 1× IP allowlist
     entry, 1× long-lived ban,
   - launch `tls-traffic-generator.py` in background with the mix and a
     demo-appropriate duration (`DEMO_DURATION`, default e.g. 5 min),
   - wait for traffic to land, then run `demo-verify.sh`,
   - print the walkthrough (URLs, creds, click path) and leave traffic
     running for the live demo.
3. **`scripts/demo-verify.sh`** — the six end-to-end assertions (exit non-zero
   on first failure, human-readable output):
   1. `proxy` metrics show `ja4_requests_total` increasing,
   2. `events:connection` stream length grows (via management API or redis),
   3. blacklisted fingerprint → block action when dial>0,
   4. whitelisted browser fingerprint → allow,
   5. `PUT /api/v1/dial` to e.g. 60 and confirm `GET /api/v1/dial` returns 60,
      and the proxy's `/metrics` dial gauge moves,
   6. Grafana API query (`/api/datasources/proxy/health` or a PromQL query via
      Grafana) returns data for `ja4proxy` job.
4. **`docs/operations/DEMO_MANAGEMENT_CONSOLE.md`** — the runbook: 10-minute
   narrative with expected on-screen results at each step and the cleanup
   path (`make stop` / `scripts/stop-all.sh`).
5. **Fix whatever the wiring-up surfaces** — with regression tests for any
   code change (see AGENTS.md TDD rules). All containerized via `make` /
   the `ja4proxy-tools` image.
6. **Makefile:** add `make demo` (up + seed + traffic + verify) and
   `make demo-stop`. Wire `demo-verify.sh` into CI-light (a fast variant
   using the existing `docker-compose.test.yml` integration stack, or a
   skipped-when-not-Docker guard — see Test strategy).

## Test strategy

- **`make test`** (existing) must stay green — the management-route changes
  (if any) get standard FastAPI route tests (HTML page renders, auth, parity)
  in `management/tests/`.
- **`scripts/demo-verify.sh`** is the phase's core test: a fresh-stack,
  end-to-end check. Run it in the demo lane; a CI-light variant (against
  `docker-compose.test.yml`) runs in CI with a `docker` availability guard.
- **`make preflight`** (lint + scan + test) must pass before PR.
- **`make lint-phases`** must pass (manifest + action_plan consistency).
- If a fix touches proxy Go code, `go test ./...` (host) plus the container
  build; any Python fix runs through the tools image.
- No skipped tests without explicit approval; if any existing test is
  discovered broken by the wiring-up, it's fixed, not skipped.

## Acceptance criteria

- `make demo` from a clean checkout brings up the lean stack (no HAProxy),
  seeds baseline lists through the management API, starts sustained varied
  traffic, and `scripts/demo-verify.sh` passes all six assertions.
- A user can, from the **browser only**, log into the management console,
  watch the live connection feed move, add a blacklist entry and see the
  matching traffic get blocked (with Grafana `Blocked/sec` moving), raise the
  dial from the widget, and see the change reflected in Prometheus/Grafana.
- The demo runbook documents the full click path + expected outcomes + cleanup.
- `make preflight` and `make lint-phases` pass; no skipped tests.

## Risks / notes

- **Traffic generator fingerprints must match blacklist entries.** The
  generator's JA4 hashes are fixed strings in source; the seed script must
  blacklist exactly the profiles the generator emits (or generate traffic
  first, read the live JA4s, then blacklist one — the more convincing demo).
  Prefer: fire traffic → observe a malicious JA4 in the live feed → block it
  from the feed → watch it die. This is also the most honest demo of the
  product.
- **Dial safety gate:** proxy resets dial to 0 at startup until
  `blocking_acknowledged: true`. The demo raises dial via the UI/API during
  the run (that's part of the narrative), not by editing config.
- **Lane/ports:** demo must respect `lane-env.sh` port remapping; runbook
  should print actual URLs from `.env`.
- **Time budget:** trafficgen at high worker counts can saturate a dev
  machine; default demo rates should be modest (≤50 workers) so the console
  stays responsive for a live audience.
