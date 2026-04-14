<!--
title: "TI feed stale Runbook"
audience: oncall, sre
last_reviewed: 2026-04-10
phase: 86
-->

# Runbook — TIFeedStale

**Alert:** `TIFeedStale`
**Source:** `deploy/monitoring/alertmanager/rules/ti_feed.yml`
**Severity:** warning
**Phase:** 85 (TI batch-poller runner)

## Symptom

`time() - ja4proxy_ti_feed_last_success_timestamp_seconds{feed_id="<id>"} > 7200`
sustained for 15 minutes.

The named feed has not recorded a **successful** poll in over 2 hours. Unlike
`TIFeedCircuitOpen`, this fires even when the circuit is CLOSED — it catches
slow-drift failure modes:

- Polls returning HTTP 200 with **zero indicators** consistently
- Upstream publisher has stalled (no new bundles for hours)
- Pagination loop never reaching the success branch
- Long-running poll exceeding the runner's interval

## Immediate action

1. Confirm the staleness and identify the feed:
   ```
   curl -s http://analytics:9100/metrics | grep ja4proxy_ti_feed_last_success_timestamp_seconds
   ```
2. Compare with poll attempts — is the runner even trying?
   ```
   curl -s http://analytics:9100/metrics | grep ja4proxy_ti_feed_poll_total | grep <feed_id>
   ```
   - **Polls happening, all `result="success"`, but counter not advancing** →
     poll succeeds but indicator-write path fails. Check
     `ja4proxy_ti_feed_mgmt_api_errors_total`.
   - **No polls at all** → runner not scheduling this feed. Check the
     analytics container is up and the feed is `enabled: true` in
     `config/proxy.yml`.
   - **Polls failing** → see `ti_feed_circuit_open.md` instead.
3. Inspect the upstream directly with curl/taxii2-client to confirm the
   publisher is producing data.

## Common causes

| Cause | Indicator | Fix |
|---|---|---|
| Upstream publisher stalled | Manual check shows no new bundles | Contact vendor; nothing to do locally |
| Feed disabled in config | `enabled: false` in `config/proxy.yml` | Re-enable + reload if intentional traffic flow expected |
| `added_after` cursor poisoned | Polls return 0 objects every time | Clear the per-feed cursor key in Redis (`feed:state:<id>:added_after`) and restart |
| Poll interval > 2h | `poll_interval_minutes` > 120 | Either lower the interval or accept the alert as expected |
| Min-confidence too high | All indicators dropped at filter stage | Lower `min_confidence` in feed config |

## Recovery

After resolving root cause, the next successful poll updates
`ja4proxy_ti_feed_last_success_timestamp_seconds` and the alert clears
within one evaluation interval.

## Escalation

If multiple feeds are stale simultaneously, suspect a runner-wide issue
(crashed worker, Redis outage, Management API down) — page security on-call.

## Related

- `docs/phases/PHASE_85.md` §2.3 — feed runner scheduling
- `docs/runbooks/ti_feed_mgmt_api_errors.md`
- `src/analytics/ti_feeds/runner.py`
