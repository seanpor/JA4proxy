# JA4proxy Prometheus Metrics Registry

> This file is the human-readable index of metrics exposed on
> ``/metrics``. It is not the source of truth for Prometheus ingestion —
> that is ``monitoring/prometheus.yml`` plus the scrape jobs in individual
> `docker-compose*.yml` files. New phases append to the bottom; never
> renumber or delete existing sections.

## Phase 85 — Threat Intelligence Ingestion

Registered in `src/analytics/ti_feeds/metrics.py`. All metrics use the
`ja4proxy_` prefix. Labels intentionally kept narrow to avoid cardinality
explosions on large multi-feed deployments.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `ja4proxy_ti_feed_poll_total` | counter | `feed_id, result` (`success`, `failure`, `skipped`, `circuit_open`) | Poll outcome counter — one increment per `poll()` call |
| `ja4proxy_ti_feed_poll_duration_seconds` | histogram | `feed_id` | Wall-clock duration of a single poll |
| `ja4proxy_ti_feed_indicators_processed_total` | counter | `feed_id, outcome` (`created`, `existing`, `below_confidence`, `unsupported`) | Per-indicator fates inside a poll |
| `ja4proxy_ti_feed_indicators_managed` | gauge | `feed_id` | Current size of the feed's `active_stix_ids` HASH |
| `ja4proxy_ti_feed_cleanup_removals_total` | counter | `feed_id` | Indicators removed by differential cleanup |
| `ja4proxy_ti_feed_circuit_state` | gauge | `feed_id` | 0=closed, 1=half_open, 2=open |
| `ja4proxy_ti_feed_last_success_timestamp_seconds` | gauge | `feed_id` | Unix timestamp of the last successful poll |
| `ja4proxy_ti_feed_mgmt_api_errors_total` | counter | `feed_id, status_code` | Management API errors observed by the feed runner (status_code may be a numeric HTTP status or the sentinel `network`/`no_token`) |

Supporting metric (seed-file loader, one-shot at startup):

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `ja4proxy_ti_feed_seed_file_entries_total` | counter | `outcome` (`created`, `error`) | Entries loaded from `config/known_bad_fingerprints.yml` |

Alertmanager rules for the eight runtime metrics live in
`monitoring/alertmanager/rules/ti_feed.yml` (`TIFeedCircuitOpen`,
`TIFeedStale`, `TIFeedMgmtApiErrors`).

Provenance model: feed-created rules are identifiable by the
`managed_by="feed"` field on `ResourceResponse` objects returned from
`/api/v1/blocklist` and by `reason="feed:{feed_id}"` on ban records. The
runner maintains the six `ti_feed:{feed_id}:*` Redis keys documented in
`docs/phases/PHASE_85.md` §2.2 as an internal sidecar index; those keys
are not exposed on `/metrics` but are readable by humans for debugging.
