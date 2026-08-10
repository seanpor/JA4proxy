# Derivation Log — Phase 814k

## Change

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
