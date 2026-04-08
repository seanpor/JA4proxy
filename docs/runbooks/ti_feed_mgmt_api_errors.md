# Runbook — TIFeedMgmtApiErrors

**Alert:** `TIFeedMgmtApiErrors`
**Source:** `monitoring/alertmanager/rules/ti_feed.yml`
**Severity:** critical
**Phase:** 85 (TI batch-poller runner)

## Symptom

`rate(ja4proxy_ti_feed_mgmt_api_errors_total{feed_id="<id>"}[10m]) > 0.1`
sustained for 10 minutes.

The named feed is fetching indicators successfully from upstream but is
**failing to apply them via the Management API**. Rules from this feed are
not being created. The proxy is operating with stale data.

This is **critical** because the failure is silent from the upstream side —
metrics show successful polls, but no rules ever get written.

## Immediate action

1. Identify the feed and the failing status code:
   ```
   curl -s http://analytics:9100/metrics | \
     grep ja4proxy_ti_feed_mgmt_api_errors_total | grep <feed_id>
   ```
   The label `status_code` tells you the failure mode:
   - `401` / `403` — bearer token invalid or missing
   - `409` — entry already exists (idempotency conflict; check for duplicate feeds)
   - `422` — malformed body (parser regression — investigate immediately)
   - `429` — rate-limited; should auto-retry per §2.5; alerting means retries also failed
   - `5xx` — Management API or its dependencies are unhealthy
   - `network` — TCP/DNS failure between analytics and management containers
   - `no_token` — `JA4PROXY_FEED_CLIENT_TOKEN` env var is unset

2. Check Management API health directly:
   ```
   curl -sf -H "Authorization: Bearer $JA4PROXY_FEED_CLIENT_TOKEN" \
     http://management:8090/api/v1/health
   ```
3. Tail Management API logs:
   ```
   docker logs ja4proxy-management 2>&1 | tail -200
   ```

## Common causes

| Cause | status_code | Fix |
|---|---|---|
| Bearer token rotated, analytics not updated | 401/403 | Sync `JA4PROXY_FEED_CLIENT_TOKEN` to new value, restart analytics |
| Management API container down | network/5xx | `docker compose up -d management` |
| Phase 79 rate limiter saturated | 429 (sustained) | Reduce feed batch_size or poll frequency |
| Duplicate feeds writing same indicator | 409 spike | De-duplicate `threat_intel.feeds[*]` in config |
| Schema drift after Management API upgrade | 422 | Check Phase 85 ResourceCreate body against current API schema; rollback or patch |
| Redis backing the API down | 5xx | See `docs/runbooks/redis_outage.md` |

## Recovery

Once the underlying error clears, the next batch will write through and the
error rate decays. The alert clears at 0/s. Indicators dropped during the
failure window are picked back up on the next poll because the runner does
not advance its `added_after` cursor on failed batches.

## Escalation

This is a **critical** alert because feed-driven blocks are not landing.
Page the security on-call engineer immediately. Include:
- The `status_code` breakdown
- Management API logs
- Output of `curl /api/v1/health`
- Whether other feeds in the same runner are also affected

## Related

- `docs/phases/PHASE_85.md` §2.5 — bulk-ingest batching and retry rules
- `src/analytics/ti_feeds/mgmt_client.py`
- `docs/runbooks/management_api_outage.md` (if it exists)
