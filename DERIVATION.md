# Derivation Log

## Change — CVE-2026-46600 scan exception + tools-image download resilience (branch `fix-test-entrypoint-shebang`)

Add a justified, dated `.trivyignore` exception for a newly-surfaced HIGH
CVE and curl retry for the tools-image pinned-binary downloads, so PR 420's
required CI gates stop failing on infra flakiness and a Trivy-DB update.

| # | Problem | Fix |
|---|---|---|
| 1 | PR 420's Meta-Validation / Full Lint / Full Test jobs failed twice at the tools-image build step: `curl -fsSL` from the GitHub release CDN exited 22 (HTTP error) then 56 (recv failure). URLs verified live (all HTTP 200), so the pins are valid — only connectivity flakes | Added `--retry 5 --retry-delay 2 --retry-all-errors` to all five pinned downloads (helm, promtool, docker CLI, docker-compose plugin, buildx plugin) |
| 2 | Security Scan gate began failing on CVE-2026-46600 (golang.org/x/net/dns/dnsmessage, fixed in x/net 0.56.0) across four third-party monitoring images (cadvisor:v0.52.1, promtail:3.6.11, alertmanager:v0.33.1, haproxy-exporter:v0.15.0) — surfaced by a Trivy DB update, not by any PR diff | Added a justified, dated `.trivyignore` entry (`exp:2026-08-19`), sibling of the existing -46595/-46597 x/net batch for the same images |

## Assumptions

- The pinned versions + SHA256 checksums are unchanged; retry only re-attempts
  the identical download, and the sha256 check still fails closed on a
  corrupted/truncated fetch.
- Transient GitHub-Actions connectivity flakiness is the failure mode (curl
  exit 22 then 56 on different binaries across two runs); deterministic pin
  failures would reproduce identically everywhere and would exit 22 every time
  (here URL checks returned 200).
- `curl --retry-all-errors` is supported on the Debian-slim curl in the base
  image (curl 7.x+); local `docker build` of the modified image passed.
- CVE-2026-46600 has no available fix: no tag newer than the pinned ones
  exists for any of the four images (verified v0.52.2 / v3.6.12 / v0.33.2 /
  v0.15.1 all 404). Rationale matches the documented sibling -46595/-46597
  exception batch; exception expires 2026-08-19 for re-review.
- The vulnerable path (`dns/dnsmessage`) is not reachable in our deployment
  (these services consume metrics/logs or serve authenticated admin UIs).

## Checks run

- Verified all 3 github.com release URLs return HTTP 200 from the local host.
- `docker build -t ja4proxy-tools -f Dockerfile.tools .` → success, image
  `e9668465...` produced (all 5 downloads executed with the new retry flags).
- `make lint-meta` and `make lint` pass locally; the image builds on demand.
- `make scan-exceptions` → 73 exceptions, all within window, CVE-2026-46600
  registered with 7 days remaining.
- Trivy re-scan of all four affected images with the exception in place → all
  clean (HIGH/CRITICAL, `--exit-code 1`).

## Model

- Author: `opencode/deepseek-v4-flash-free` (family `deepseek`), version `deepseek-v4-flash-free-2026-08`.
- Reviewer (quality gate): `ollama/deepseek-r1:14b` (family `deepseek-r1`).

---

## Change — CI tools-image download resilience (branch `fix-test-entrypoint-shebang`)

Add curl retry to the pinned-binary downloads in `Dockerfile.tools` so the
CI gates (`make lint`, `make test`, `make lint-meta` — all tools-image
prereqs) stop failing on transient GitHub-Actions-runner download flakiness.

| # | Problem | Fix |
|---|---|---|
| 1 | PR 420's Meta-Validation / Full Lint / Full Test jobs failed twice at the tools-image build step: `curl -fsSL` from the GitHub release CDN exited 22 (HTTP error) then 56 (recv failure). URLs verified live (all HTTP 200), so the pins are valid — only connectivity flakes | Added `--retry 5 --retry-delay 2 --retry-all-errors` to all five pinned downloads (helm, promtool, docker CLI, docker-compose plugin, buildx plugin) |

## Assumptions

- The pinned versions + SHA256 checksums are unchanged; retry only re-attempts
  the identical download, and the sha256 check still fails closed on a
  corrupted/truncated fetch.
- Transient GitHub-Actions connectivity flakiness is the failure mode (curl
  exit 22 then 56 on different binaries across two runs); deterministic pin
  failures would reproduce identically everywhere and would exit 22 every time
  (here URL checks returned 200).
- `curl --retry-all-errors` is supported on the Debian-slim curl in the base
  image (curl 7.x+); local `docker build` of the modified image passed.

## Checks run

- Verified all 3 github.com release URLs return HTTP 200 from the local host.
- `docker build -t ja4proxy-tools -f Dockerfile.tools .` → success, image
  `e9668465...` produced (all 5 downloads executed with the new retry flags).
- `make lint-meta` and `make lint` pass locally; the image builds on demand.

## Model

- Author: `opencode/deepseek-v4-flash-free` (family `deepseek`), version `deepseek-v4-flash-free-2026-08`.
- Reviewer (quality gate): `ollama/deepseek-r1:14b` (family `deepseek-r1`).

---

## Change — demo-stack fixes (branch `fix-bench-all-poc-secrets`)

Fix the JA4proxy demo stack (POC + Prometheus/Grafana monitoring) so the
full pipeline runs end-to-end in a live lane:

| # | Problem | Fix |
|---|---|---|
| 1 | `start-all.sh` skip-check used the monitoring compose `ps` output, but both compose files share `COMPOSE_PROJECT_NAME` from `.env`, so the check saw the POC containers (Up) and skipped the monitoring stack | Gate on the actual running Grafana container name, lane-derived (`ja4proxy-lane${JA4_LANE}-grafana-1`), not project-scoped compose ps |
| 2 | Proxy `/metrics` unreachable from Prometheus — proxy binds loopback by default (JA4PROXY-2026-0008) and requires a Bearer token on non-loopback binds | `METRICS_BIND_HOST=0.0.0.0` + `METRICS_AUTH_TOKEN` in `.env`, wired into `docker-compose.poc.yml` proxy env; `prometheus.yml` ja4proxy job targets `proxy:9090` with `authorization: credentials_file`; token mounted into Prometheus |
| 3 | Scripts hardcoded stale ports/URLs and the old `ja4_*` metric names | `generate-tls-traffic.sh`, `start-all.sh`, `start-monitoring.sh` source `.env`, use `HOST_PORT_*` lane ports, use `ja4proxy_*` metric names, Bearer auth |
| 4 | Grafana crash-looped: compose sets HTTPS cert paths but the cert volume mount was removed by an earlier commit | Restored `./certs/grafana:/etc/grafana/certs:ro`; `grafana.key` chmod 644 (container uid 472) |
| 5 | Redis ACL users `exporter`/`ja4tap` had empty passwords (0-byte secret files), so redis-exporter and ja4tap auth failed | Filled `.env` + `deploy/secrets/*.txt`; redis restarted to re-render ACL |
| 6 | `blocking` at `config:dial=100` never took effect: `config/integrity.key` was 0664, tripping the JA4PROXY-2026-0070 permission gate (client.go:328 → fail open, dial=0) | `chmod 600 config/integrity.key`; proxy then read dial=100 and enforced it |
| 7 | Stale in-process decision cache (ADR-003, 30-min allow TTL) served dial=0-era "allow" decisions, bypassing the dial fetch | Restarted proxy to clear the cache (cache has no dial-change flush by design) |
| 8 | `loki` permanently `(unhealthy)`: distroless image ships only `/usr/bin/loki` (no wget/curl/sh), so the `wget` healthcheck could never run | Removed the healthcheck from `docker-compose.monitoring.yml`; `start-monitoring.sh` probes loki via the Grafana container's curl instead |

## Assumptions

- All changes are operational/demo-stack only; no production Go code modified.
- The `container_name:` fields in the monitoring compose were intentionally
  removed (commit 8de0753d, multi-lane isolation), so lane-derived container
  names are the correct gate target.
- `config/integrity.key` must remain 0600 for JA4PROXY-2026-0070 to pass.
- Metrics endpoint is plain HTTP (not TLS) — the Go proxy serves /metrics
  over HTTP with Bearer auth; enterprise TLS config does not apply to it.

## Checks run

- Live verification: dial=100 read by proxy (`action=rate_limit` at score 35,
  correct — block threshold is 70); Prometheus scrapes 214 `ja4proxy_*`
  metrics; all 16 lane containers Up (healthy); `start-monitoring.sh` reports
  Prometheus/Alertmanager/Grafana/Loki all healthy; `getent hosts backend`
  resolves in proxy; traffic generator runs end-to-end through proxy → backend.

## Model

- Author: `opencode/deepseek-v4-flash-free` (family `deepseek`), version `deepseek-v4-flash-free-2026-08`.
- Reviewer (quality gate): `ollama/deepseek-r1:14b` (family `deepseek-r1`).

---

## Change — Phase 814k

Fix four data-layer defects on branch `phase-814k-redis-acl-data-layer`:

| # | Finding | Fix |
|---|---|---|
| A (0098) | Analytics Redis ACL user cannot read the connection event stream it must consume | `config/redis_acl.conf.template` + `scripts/redis-acl-setup.sh`: analytics user gets `resetkeys ~analytics:* ~events:connection ~ti_feed:* +@read +@write +xadd +xgroup +xack +xreadgroup +xread +xrevrange +ping -@admin` |
| B (0099) | Proxy Redis ACL user under-scoped — rate limiting, audit trail, event stream silently dead | Same two files: proxy user now grants the full command/key/channel surface verified against Go proxy usage (incl. `+script|load`, `+exists`, `+incr`, `+scan`, `~proxy:*`, `~audit:*`, `~events:connection`, `~ban_cidr:*`, `+subscribe &config:* &ja4:* &geoip:*`) |
| C (0100) | Stream-key drift: analytics consumes retired `ja4proxy:events`; Go proxy writes `events:connection` | `config/analytics.yaml`, `src/analytics/config.py`, `src/analytics/stream_consumer.py`, plus stale refs in `management/api/routes/metrics.py`, `scripts/ja4proxy_admin.py`, `deploy/prometheus/alerts/compliance.yml` → all `events:connection` |
| D (0101) | GDPR purge targets the wrong stream | `management/compliance/purge.py`, `management/compliance/pack_builder.py`: `_STREAM_KEY = "events:connection"` |

## Assumptions

- Canonical ACL surface derived from Go proxy source (`internal/redis/client.go`, `cmd/ja4pd/main.go`, `internal/redis/pubsub.go`, sync agent), not from docs.
- Analytics does NOT use category grants (`+@read`/`+@write`): those transitively allow `FLUSHALL`/`FLUSHDB`/`KEYS` (verified live). The analytics user holds an explicit command whitelist instead, covering every call the node makes (incl. `MULTI`/`EXEC`/`DISCARD` for the `pipeline()` usage in `ti_feeds/state.py`).
- Analytics node uses NO Lua/EVAL and NO PUBLISH; therefore no `+script|load` or `&` channel grants needed for the analytics user.
- `events:connection` is the single canonical connection stream name (proxy writes it, per `cmd/ja4pd/main.go:1292`).
- The 94 findings without GitHub issue numbers predate this phase and are out of scope.

## Checks run

- **Two-state regression proof:** `tests/unit/test_redis_acl_coverage.py` — 7/9 tests FAIL on pre-fix code (`git show HEAD` copies), 9/9 PASS on post-fix.
- `pytest tests/unit/test_redis_acl_coverage.py` → 9 passed.
- `pytest tests/unit/test_analytics_config.py tests/unit/test_stream_consumer.py tests/unit/analytics/` → all passed.
- `pytest management/tests/test_compliance_purge.py test_compliance_pack.py` → 27 passed, 1 skipped (pre-existing).
- `pytest tests/integration/test_stream_processing.py` → 12 passed.
- `make test` → full suite green (Go native + 751 Python + integration + guardrails).
- `make lint` → CI LINT PASS (2 advisory codespell hits, pre-existing).
- `make lint-phases` → OK, 341 phases, 0 violations.
- `python3 scripts/findings_register.py validate` → OK, 99 findings.
- `ruff check` + `mypy` on all changed `.py` → clean.
- **Live-deploy validation (the state that surface the bug):** on recreate,
  Redis 7.4.9 rejected the rendered ACL with `+zrangewithscores: Unknown
  command or category name in ACL` — that token does not exist in Redis 7.4
  (go-redis's `ZRangeWithScores` issues `ZRANGE ... WITHSCORES`). Removed it
  from the template, setup script, test constants, proxy.yml comment and this
  log. Full rendered ACL re-validated against `redis:7.4.9-alpine` (server
  starts, no ACL errors); analytics user proven end-to-end: XGROUP CREATE
  MKSTREAM / XADD / XREADGROUP / XACK on `events:connection` all succeed from
  a fresh aclfile, and denied key access is NOPERM'd.
- Added `test_no_unknown_acl_command_tokens` to pin the bug class (parity
  tests could not catch a bad token present in both files). Two-state proof:
  fails when `+zrangewithscores` is injected, passes clean. Suite → 10 passed.
- Independent crit of the staged diff surfaced the broad-category over-grant:
  `+@read +@write` on the analytics user returned `OK` for `FLUSHALL` against
  live Redis. Replaced with an explicit command whitelist (template, setup
  script, test constants, proxy.yml comment); added
  `test_analytics_acl_has_no_broad_categories_or_dangerous_commands` and
  `test_analytics_acl_grants_every_command_the_node_issues` (two-state:
  `+flushall` injected → fail; clean → pass). Suite → 13 passed.
- Healthcheck fix: analytics `wget http://localhost:8080/health` resolved
  `localhost`→`::1` but aiohttp binds IPv4 `0.0.0.0` → always `unhealthy`
  despite a working app. Changed to `http://127.0.0.1:8080/health` in
  `docker-compose.poc.yml` + `docker-compose.prod.yml`. Verified `healthy` in
  the live range.
- Full ja4range stack recreated from the fixed tree: analytics no longer
  crash-loops, container `healthy`, stream flows end-to-end.

## Model

- Author: `opencode/deepseek-v4-flash-free` (family `deepseek`), version `deepseek-v4-flash-free-2026-08`.
- Reviewer (quality gate): `ollama/deepseek-r1:14b` (family `deepseek-r1`).
