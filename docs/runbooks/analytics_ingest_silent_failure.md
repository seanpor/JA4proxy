<!--
title: Analytics_Ingest_Silent_Failure
audience: Operators, Security Teams
last_reviewed: 2026-08-18
phase: 827
-->

# Runbook — analytics accepts no events (and nothing looks wrong)

## Symptom

The console's Intelligence panel is empty. No findings of any kind — not
campaigns, not slow scans, not JA4 intelligence — regardless of how much
traffic the proxy is handling.

**Everything reports healthy.** The proxy is forwarding traffic and writing to
the stream. The analytics container is up, `/health` returns 200, `/ready`
returns ready. There are no errors in either log at default verbosity.

This is the defining property of the failure: *nothing fails*. The events are
read and thrown away.

## Alerts that fire

| Alert | Meaning |
|---|---|
| `AnalyticsEventsRejectedHMAC` | Signature mismatch — the two services hold different secrets |
| `AnalyticsIngestingNothing` | Everything reaching the node is rejected, for any reason |

If neither has fired and the panel is still empty, the events may not be
reaching the stream at all — see "Nothing in the stream" below.

## Diagnose

### 1. Is anything being rejected, and why?

```bash
curl -s localhost:8080/metrics | grep ja4proxy_analytics_events_
```

```
ja4proxy_analytics_events_ingested_total   0
ja4proxy_analytics_events_rejected_total{reason="hmac"}      7749
```

`reason="hmac"` with a zero ingest count is conclusive: the proxy's signature
is not verifying here.

### 2. Do the two secrets actually match?

Both come from `ANALYTICS_HMAC_SECRET`. They land in different places:

| Service | Reads |
|---|---|
| Proxy | `config/proxy.yml` → `webhooks.stream_hmac_secret: "${ANALYTICS_HMAC_SECRET}"` |
| Analytics | `src/analytics/config.py` → `security.hmac_secret`, overridden by `ANALYTICS_HMAC_SECRET` |

```bash
docker compose --env-file .env exec proxy     printenv ANALYTICS_HMAC_SECRET | sha256sum
docker compose --env-file .env exec analytics printenv ANALYTICS_HMAC_SECRET | sha256sum
```

Compare the hashes, not the values. Different hashes → one container is running
with a stale environment; recreate it (`docker compose up -d --force-recreate`).
Restarting is not enough if the value changed in `.env`.

### 3. Is the analytics node using the placeholder?

At startup the node logs, at ERROR:

```
analytics | event=hmac_secret_not_configured | hmac_required=true but the
secret is the built-in placeholder...
```

That means `ANALYTICS_HMAC_SECRET` never reached the config — the exact
failure that happened in phase-826, where the variable was added to
docker-compose but `src/analytics/config.py` did not read it, so the
placeholder stayed in force and every signed event failed.

## Fix

```bash
# 1. Confirm the variable exists and is non-empty
make env-sync            # adds it if missing; never overwrites

# 2. Recreate BOTH services so each picks up the value
docker compose --env-file .env up -d --force-recreate proxy analytics

# 3. Confirm ingestion has started
curl -s localhost:8080/metrics | grep ja4proxy_analytics_events_ingested_total
```

The ingested counter should climb within seconds of the next connection.
Findings need enough observations to cross a detector threshold — see
`detection.*` in `config/analytics.yaml` — so the panel may stay empty for a
few minutes after ingestion resumes. That is normal; a climbing ingest counter
is the thing to verify.

## Nothing in the stream at all

If `ingested` and `rejected` are both zero, the events are not arriving:

```bash
redis-cli --user analytics -a "$ANALYTICS_REDIS_PASSWORD" --no-auth-warning \
  XLEN events:connection
```

- **XLEN 0** — the proxy is not writing. Check `webhooks.stream_enabled` and the
  proxy's Redis ACL permissions for `events:connection`.
- **XLEN climbing but nothing consumed** — the consumer is not reading. The
  classic cause is a blocking-read timeout: `socket_timeout` must exceed the
  `XREADGROUP block=` window, or every poll raises `TimeoutError` and the group
  never advances. Guarded by `tests/unit/test_redis_blocking_timeouts.py`.

## Why this needed a runbook

Every other failure in this system announces itself. This one is invisible by
construction: a rejected event is indistinguishable from no traffic, and both
services are behaving exactly as configured. The monitoring added in phase-827
(`AnalyticsEventsRejectedHMAC`, `AnalyticsIngestingNothing`, and the startup
ERROR) exists because the condition was previously found by looking at the
console and wondering why it was empty.

## Related

- `docs/runbooks/analytics_lag.md` — consumer behind, but working
- `docs/runbooks/geoip_databases.md` — the other silent "healthy but degraded" state
