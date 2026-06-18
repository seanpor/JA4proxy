# ADR-316e: TAP intelligence export is one pull-based EDL endpoint, not seven push exporters

**Status:** Accepted
**Date:** 2026-06-18
**Phase:** 316 (Go TAP/SPAN passive sensor — sub-phase 316e)

---

## Context

Phase 316e exposes the bans/intelligence JA4proxy produces to downstream
security tooling. The original outline — inherited from the archived Python
sensor (`5afeba26:archive/python_legacy/src/tap/export/`) — proposed **seven**
outbound exporters: an EDL server plus F5, Palo Alto, Kafka, Syslog CEF, TAXII
2.1, and MISP clients, each driven from the sensor.

A critical review before implementation found that scope wrong for the current
architecture:

1. **Wrong home.** Exporters are outbound egress (HTTP/Kafka/Syslog). Driving
   them from the least-privilege capture sensor (`CAP_NET_RAW`, Redis ACL
   `~fp:*`) is the same privilege/blast-radius expansion rejected for 316d's
   external blockers (ADR-316d). Export belongs in the Python management/
   analytics layer, which already has the web framework, auth, and the Phase-85
   `ti_feeds` subsystem.
2. **One EDL collapses three.** F5 BIG-IP and Palo Alto NGFW both natively poll
   an External Dynamic List URL. A single EDL endpoint replaces the dedicated F5
   and Palo Alto push clients and serves any other firewall.
3. **Pull is safer than push.** An EDL we serve (the firewall fetches) needs no
   third-party credentials and we never initiate egress — unlike push clients
   that hold firewall creds and exfiltrate on a timer.
4. **Partial redundancy.** `GET /api/v1/bans` already serves the ban set as
   authed JSON; the net-new piece is only the EDL *shape* (plaintext, cacheable,
   token-pull).
5. **The rest is enterprise-SOC niche.** TAXII-server/MISP, Kafka, and Syslog/CEF
   are real but none are core to protecting web forms from bots; building all
   seven is multiple phases most deployments won't use.

## Decision

Ship **one pull-based EDL feed** as an endpoint on the existing FastAPI
management API:

- `GET /api/v1/edl/{banned_ips|banned_cidrs|combined}` → `text/plain`.
- **Auth** reuses the existing management-API token store (`mgmt:token:*` via
  `get_bearer_user`), accepted as `X-API-Key`, `Authorization: Bearer`, or
  `?token=`. No new static-token config, no secret in `proxy.yml`; revocation and
  expiry come from the token store.
- **Source data** is read-only: `ban:{ip}` + `ban_cidr:{cidr}`.
- **ETag → 304**, `Cache-Control`, per-token sliding-window rate limit.
- **Fail-open:** a Redis error serves an *empty* feed (HTTP 200), never a 5xx.

F5, Palo Alto, Kafka, Syslog/CEF, TAXII-server, and MISP exporters are **dropped
from this slice** and revisited only on concrete demand.

## Consequences

- **Net-new surface is small and safe** — an endpoint on an app that already has
  auth, Redis, and deployment; no new server, port, or egress path.
- **No dead metrics.** The management API has no Prometheus exposition surface
  today; rather than ship counters nothing scrapes, observability is via
  structured `edl | event=...` logs. A mgmt-API `/metrics` surface is its own
  decision.
- **Fail-open matches the core asymmetry** — an empty blocklist under-blocks
  (recoverable); a 5xx would break the firewall's poller.
- **Future exporters, if ever needed, are independent** — each would be its own
  decision and live in the analytics/management layer, never in the sensor.
- **Source-IP allowlisting deferred** — token auth is the gate; defense-in-depth
  source restriction (with correct client-IP-behind-proxy handling) can be added
  later without changing the contract.
