# Phase 316e notes — TAP Intelligence Exporters (EDL-pull MVP)

## What shipped

One pull-based **EDL feed** as an endpoint on the existing FastAPI management
API — not the seven push exporters the outline proposed.

- `management/api/routes/edl.py` — `GET /api/v1/edl/{banned_ips|banned_cidrs|combined}`:
  - plaintext, sorted+deduped, trailing newline, `ETag`→304, `Cache-Control`,
    `X-EDL-Count`/`X-EDL-Truncated`.
  - token auth via `get_bearer_user` (`mgmt:token:*`), accepted as `X-API-Key`,
    `Authorization: Bearer`, or `?token=`.
  - read-only over `ban:{ip}` + `ban_cidr:{cidr}` (SCAN).
  - fail-open: Redis error → empty 200, never 5xx.
  - per-token sliding-window rate limit (fail-open), `max_entries` cap (logged
    truncation), conservative default off (404 when `edl.enabled` false).
- `management/api/main.py` — router registered.
- `config/proxy.yml` — `edl:` section.
- `management/tests/test_edl.py` — 12 tests.

## Why this shape (critical review → ADR-316e)

The 7-exporter outline (EDL/F5/Palo Alto/Kafka/Syslog/TAXII/MISP) was ported from
the archived Python sensor and wrong for the current architecture:
- exporters are outbound egress → don't belong in the least-privilege capture
  sensor (same anti-pattern as 316d's external blockers);
- F5 + Palo Alto both natively poll an EDL URL, so one EDL replaces both push
  clients;
- pull (we serve, they fetch) needs no firewall creds and no egress from us;
- `GET /api/v1/bans` already serves the ban set as JSON — the net-new piece is
  only the EDL *shape*.

## Deliberate non-goals (deferred, not forgotten)

- Kafka, Syslog/CEF, TAXII-server, MISP exporters — revisit on concrete demand.
- F5/Palo Alto push clients — obviated by EDL-pull.
- Source-IP allowlist — token auth is the gate; defense-in-depth source
  restriction (with correct client-IP-behind-proxy handling) is a future add.
- Prometheus exposition for the management API — none exists; shipping counters
  nothing scrapes would be dead metrics. Observability is structured
  `edl | event=served|truncated|build_error` logs.

## Tests / status

`management/tests/test_edl.py` 12/12 pass; full `management/tests` otherwise green
(657 passed). NOTE: 8 pre-existing failures in `test_phase_122_security_review.py`
(`ModuleNotFoundError: src.security.health`) are stale references to the deleted
Python proxy — present on clean main, unrelated to this phase.

## Redis

New transient key `edl:ratelimit:{identity}` (ZSET, 60s, fail-open). No new
persisted intelligence — the feed only reads existing ban keys.
