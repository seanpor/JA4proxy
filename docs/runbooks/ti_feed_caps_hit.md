<!--
title: "TI feed safety cap hit Runbook"
audience: oncall, sre
last_reviewed: 2026-04-26
phase: 101
-->

# Runbook — TIFeedCapsHit

**Alert:** `TIFeedCapsHit`
**Source:** `deploy/monitoring/alertmanager/rules/ti_feed.yml`
**Severity:** warning
**Phase:** 101 (cross-phase deferred-review register, sub-phase 101c C4)

## Symptom

`rate(ja4proxy_ti_feed_caps_hit_total{feed_id="<id>"}[15m]) > 0` sustained
for 15 minutes.

A TI feed is being constrained by one of the per-poll safety caps:

| Cap label | Defined in | Default | Meaning |
|---|---|---|---|
| `max_new_per_poll` | `FeedConfig.max_new_per_poll` | 500 | Per-poll ceiling on newly created indicators |
| `max_owned_total` | `FeedConfig.max_owned_total` | 50 000 | Hard ceiling on total active indicators per feed |
| `max_delta_per_poll` | `FeedConfig.max_delta_per_poll` | 0 (off) | Optional bound on (created − removed) per poll |

These caps are blast-radius brakes — the **only** thing standing between a
corrupted upstream feed and a flood of false-positive blocks. A non-zero hit
rate means the feed is being constrained to protect the system.

## Immediate action

1. Identify which cap fired and on which feed:
   ```
   curl -s http://analytics:9100/metrics \
     | grep ja4proxy_ti_feed_caps_hit_total
   ```
2. Inspect the most recent runner logs for the feed:
   ```
   docker logs ja4proxy-analytics 2>&1 | grep -E "feed_capped|feed=<id>" | tail -50
   ```
   Look for `event=feed_capped_new`, `event=feed_capped_owned`, or
   `event=feed_capped_delta`.
3. Check the upstream directly. Is the indicator volume actually that
   large, or has the publisher gone wild (e.g. accidentally publishing every
   IP they have ever seen)?

## Common causes

| Cause | Indicator | Fix |
|---|---|---|
| Legitimate feed growth | Steady ramp, low new/owned ratio | Raise the cap in `config/proxy.yml`; restart analytics |
| Upstream-publisher bug | Sudden 10× spike in `created` per poll | Pause the feed; contact vendor |
| Compromised feed | New indicators are off-pattern (e.g. browser JA4s) | Pause the feed immediately; rotate credentials |
| Misconfigured `max_owned_total` for a large feed | Owned count plateaus exactly at the cap | Raise the cap; consider splitting the feed |

## Recovery

- After raising a cap (or pausing a feed), the next clean poll without a
  cap-hit clears the alert within the 15-minute evaluation window.
- If you pause a feed, `TIFeedStale` will eventually fire — that is expected
  and is the correct trade-off versus a flood of false-positive blocks.

## Escalation

If multiple feeds hit caps in the same poll cycle, suspect either a runner
configuration regression (caps lowered globally) or a coordinated upstream
incident — page security on-call.

## Related

- `docs/phases/PHASE_101.md` §C4 — safety caps spec
- `src/analytics/ti_feeds/base.py` — `FeedConfig` cap fields
- `src/analytics/ti_feeds/runner.py` — `_poll_once` cap enforcement
- `docs/runbooks/ti_feed_fp_blocked.md`
