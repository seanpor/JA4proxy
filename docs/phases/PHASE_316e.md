# PHASE 316e — TAP Intelligence Exporters (EDL-pull MVP)

> **STATUS: APPROVED / IN PROGRESS.** Depends on 316a–316d.
> Re-scoped after critical review (see §1). See `docs/decisions/ADR-316e.md`.

## 1. Critical review of the original outline

The original 316e outline proposed **seven** outbound exporters (EDL, F5, Palo
Alto, Kafka, Syslog CEF, TAXII 2.1, MISP), ported from the archived Python
sensor. Grounded against the current codebase, that scope is wrong:

- **Wrong home.** Exporters are outbound network egress (HTTP/Kafka/Syslog).
  Putting them in the least-privilege capture sensor (`CAP_NET_RAW`, `~fp:*`
  ACL) is the same anti-pattern rejected for 316d's external blockers. Export
  belongs in the Python management/analytics layer, which already has the web
  framework, auth, and the `ti_feeds` subsystem (Phase 85, *inbound* TI).
- **One EDL collapses three.** F5 BIG-IP and Palo Alto NGFW both natively poll
  an **External Dynamic List** URL — a plaintext IP-per-line feed. A single EDL
  endpoint replaces the dedicated F5 *and* Palo Alto push clients and serves any
  other firewall.
- **Pull beats push on safety.** An EDL we serve (they fetch) needs no
  third-party credentials and we never initiate egress — far safer than push
  clients that hold firewall creds and exfiltrate on a timer.
- **Partial redundancy.** `GET /api/v1/bans` already returns the ban set as
  authed JSON; the net-new piece is just the EDL *shape* (plaintext, cacheable,
  token-pull) firewalls consume.
- **The rest is enterprise-SOC niche.** TAXII-server/MISP (TI-community sharing),
  Kafka (data pipeline), Syslog/CEF (SIEM) are all real but none core to the
  product's job (protecting web forms from bots). Building all seven is multiple
  phases of integrations most deployments won't use.

Decision (ADR-316e): ship **one pull-based EDL feed** in the management API;
defer Kafka/Syslog/MISP/TAXII-server until a customer needs them.

## 2. Goal

Let firewalls consume JA4proxy's active bans by pulling a plaintext blocklist
over HTTP — no per-vendor integration, no egress, no held credentials.

## 3. Scope

**In:**

- `management/api/routes/edl.py` — `GET /api/v1/edl/{banned_ips|banned_cidrs|combined}`:
  - **Auth:** a management-API token (`mgmt:token:*`, reusing `get_bearer_user`)
    presented as `X-API-Key`, `Authorization: Bearer`, or `?token=`. Mint via the
    existing `POST /api/v1/tokens`. No interactive/role redirect.
  - **Source data (read-only):** `ban:{ip}` + `ban_cidr:{cidr}` via SCAN.
  - **`PlainTextResponse`**, sorted+deduped, trailing newline, **ETag → 304**,
    `Cache-Control`, `X-EDL-Count`/`X-EDL-Truncated` headers.
  - **Fail-open:** a Redis error serves an *empty* feed (HTTP 200), never a 5xx.
  - **Per-token sliding-window rate limit** (reusing the threat-intel pattern),
    fail-open.
  - **`max_entries` cap** with logged truncation (no silent cap).
- `config/proxy.yml` `edl:` section (enabled:false default, max_entries,
  cache_ttl_seconds, rate_limit_per_min).
- Tests (`management/tests/test_edl.py`): auth required/invalid, each list type,
  ETag 304, disabled→404, unknown-list→404, fail-open, IPv6, token-via-query,
  rate-limit.
- Docs: ADR-316e + INDEX, REDIS_SCHEMA (reads ban:*/ban_cidr:*, new
  `edl:ratelimit:*`), OBSERVABILITY (structured log events),
  `docs/runbooks/edl_export.md`.

**Out / deferred:**

- **Dropped from this slice (revisit on demand):** F5 push client, Palo Alto
  push client (both obviated by EDL-pull), Kafka producer, Syslog/CEF, TAXII 2.1
  server, MISP client.
- **Source-IP allowlist** (`allowed_source_cidrs`) — token auth is the gate;
  defense-in-depth source restriction deferred (client-IP-behind-proxy handling
  warrants its own care).
- **Prometheus exposition for the management API** — none exists today; shipping
  counters with no scrape surface would be dead metrics. Observability is via
  structured `edl | event=...` log lines for now; a mgmt-API `/metrics` surface
  is its own concern.

## 4. Key decisions

- **EDL endpoint in the existing FastAPI app, not a standalone aiohttp server**
  (the archived design's separate :8091 server) — reuses auth/redis/deploy.
- **Token via the existing Redis token store** — free revocation/expiry; no new
  static-token config, no secret in proxy.yml.
- **Fail-open = empty feed, never 5xx** — an empty blocklist under-blocks (safe
  per the core asymmetry); a 5xx would break the firewall's poller.
- **Conservative default off** — `edl.enabled:false`; disabled → 404 (reveals
  nothing about token validity).

## 5. Acceptance

- `make test` (Python) green incl. `management/tests/test_edl.py`.
- Disabled by default; a valid token returns the plaintext feed; an invalid/
  absent token returns 401; a Redis failure returns an empty 200, never 5xx.
