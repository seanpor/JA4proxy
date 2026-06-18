# Runbook — EDL Export Feed (Phase 316e)

The EDL (External Dynamic List) feed lets firewalls **pull** JA4proxy's active
bans as a plaintext blocklist over HTTP. F5 BIG-IP and Palo Alto NGFW both
natively consume an EDL URL, so this one endpoint covers them and any other
firewall — no per-vendor integration, no outbound connections from JA4proxy, no
firewall credentials held here.

## Endpoint

```
GET /api/v1/edl/{list_name}
```

`list_name` is one of:

| list | contents | source keys |
|---|---|---|
| `banned_ips` | one IP per line (IPv4 + IPv6) | `ban:{ip}` |
| `banned_cidrs` | one CIDR per line | `ban_cidr:{cidr}` |
| `combined` | both, deduped | `ban:*` + `ban_cidr:*` |

Response is `text/plain`, sorted, one entry per line, with an `ETag` (firewalls
that send `If-None-Match` get a cheap `304`), a `Cache-Control: max-age`, and an
`X-EDL-Count` header (`X-EDL-Truncated: true` if the `max_entries` cap was hit).

## Enabling it

Off by default. In `config/proxy.yml`:

```yaml
edl:
  enabled: true
  max_entries: 100000       # cap on entries served (vendor EDLs have limits)
  cache_ttl_seconds: 60
  rate_limit_per_min: 120   # per-token sliding window; <=0 disables
```

When `enabled: false` (default) the endpoint returns `404` — it reveals nothing
about token validity.

## Authentication (machine token)

The feed is consumed by a firewall, not a human, so it uses a **management-API
token**, not interactive login. Mint one and hand it to the firewall:

```
POST /api/v1/tokens          # admin-only; returns the raw token once
```

The firewall presents it in **any** of:

- `X-API-Key: <token>` header
- `Authorization: Bearer <token>` header
- `?token=<token>` query parameter (for vendors that only support a URL)

Revoke or expire it via the normal token store (`mgmt:token:*`) — no separate EDL
secret exists. Use a dedicated token per firewall so you can revoke one without
affecting others; the token *name* appears in the `edl | event=served` logs.

### F5 / Palo Alto configuration sketch

- **Palo Alto:** Objects → External Dynamic Lists → Type *IP List*, Source
  `https://<mgmt-host>/api/v1/edl/banned_ips?token=<token>`, set a check-in
  interval ≥ 1 minute.
- **F5:** create an external data-group / IP-intelligence feed list pointing at
  the same URL with the token header.

## Behaviour under failure (fail-open)

A Redis error while building the list serves an **empty** feed with `HTTP 200`,
never a `5xx`. Rationale (core asymmetry): an empty blocklist under-blocks, which
is recoverable; a `5xx` would break the firewall's poller and could wedge it on a
stale list. The error is logged as `edl | event=build_error`.

The rate limiter is also fail-open: a Redis error skips the check rather than
rejecting a legitimate poll.

## Observability

The management API has no Prometheus surface, so the feed's signal is structured
logs (`subsystem=edl`):

- `event=served` — `list`, `client` (token name), `status` (200/304), `count`.
- `event=truncated` (WARN) — `total`, `cap`; the list exceeded `max_entries`.
- `event=build_error` (ERROR) — Redis failure; feed served empty.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `404` on every list | `edl.enabled` is false, or `list_name` misspelled. |
| `401` | No/invalid/expired token; check the `mgmt:token:*` entry and expiry. |
| `429` | Firewall polling faster than `rate_limit_per_min`; raise the limit or slow the poll. ETag/`If-None-Match` makes frequent polls cheap. |
| Empty feed but bans exist | Redis unreachable from the management API (see `event=build_error`), or the bans are CIDRs and you requested `banned_ips` (use `combined`). |
| List looks capped | `X-EDL-Truncated: true` — raise `max_entries` (mind the firewall's own EDL size limit). |

## Scope note

This is the EDL-pull MVP (ADR-316e). F5/Palo Alto push clients are obviated by
EDL-pull; Kafka, Syslog/CEF, TAXII-server, and MISP exporters were deferred until
there is concrete demand. A source-IP allowlist (defense-in-depth on top of the
token) is a documented future addition.
