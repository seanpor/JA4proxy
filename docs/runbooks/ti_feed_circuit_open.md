<!--
title: "TI feed circuit open Runbook"
audience: oncall, sre
last_reviewed: 2026-04-10
phase: 86
-->

# Runbook — TIFeedCircuitOpen

**Alert:** `TIFeedCircuitOpen`
**Source:** `monitoring/alertmanager/rules/ti_feed.yml`
**Severity:** warning
**Phase:** 85 (TI batch-poller runner)

## Symptom

`ja4proxy_ti_feed_circuit_state{feed_id="<id>"} >= 2` for more than 30 minutes.
The circuit breaker for the named feed is **OPEN** — the runner has stopped
polling it and is waiting for the open-timeout to expire before probing again.

No indicators from this feed are being refreshed. Existing rules previously
applied by this feed remain in place (they expire on their own TTLs).

## Immediate action

1. Identify the feed:
   ```
   curl -s http://analytics:9100/metrics | grep ja4proxy_ti_feed_circuit_state
   ```
2. Check recent failures broken down by reason:
   ```
   curl -s http://analytics:9100/metrics | grep ja4proxy_ti_feed_poll_total | grep <feed_id>
   ```
   Look for `result="failure"`, `result="circuit_open"`.
3. Tail the analytics container logs for the feed id:
   ```
   docker logs ja4proxy-analytics 2>&1 | grep "feed=<feed_id>"
   ```
   Common signatures: `event=poll.failed`, `event=mgmt_client_close_error`,
   `HTTP 401`, `HTTP 403`, connection refused, DNS failure.

## Common causes

| Cause | Indicator | Fix |
|---|---|---|
| Credentials rotated upstream | HTTP 401/403 in logs | Update the feed's secret in vault and `SIGHUP` the analytics container |
| Vendor outage | TCP/TLS errors, 5xx | Wait for vendor; circuit will half-open automatically |
| Feed URL changed | DNS NXDOMAIN, 404 | Update `config/proxy.yml` `threat_intel.feeds[*].url` and reload |
| Bearer token unset | `JA4PROXY_FEED_CLIENT_TOKEN is not set` | Set the env var on the analytics container |
| Network egress blocked | Connection timed out | Check firewall / DMZ egress rules |

## Recovery

The circuit breaker will transition CLOSED automatically once the underlying
problem is resolved and the next probe succeeds. To force an immediate retry
after fixing the root cause, restart the analytics container:

```
docker compose restart analytics
```

## Escalation

If the feed is critical (e.g. paid CrowdStrike / Recorded Future) and remains
open for more than 4 hours, page the on-call security engineer. Include the
analytics container logs and the output of the metrics queries above.

## Related

- `docs/phases/PHASE_85.md` §2.4 — circuit breaker design
- `docs/runbooks/ti_feed_health.md` — Phase 59 hot-path TI providers (different system)
- `src/analytics/ti_feeds/circuit_breaker.py`
