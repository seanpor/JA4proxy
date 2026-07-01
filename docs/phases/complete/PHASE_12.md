# Phase 12 — Analytics Node

**Status:** COMPLETE

Phase 12 implemented the analytics node: a Redis Stream consumer that ingests
connection events from proxy instances and produces aggregate risk signals.

## Key deliverables

- `StreamConsumer` — reads from `ja4proxy:events` Redis Stream
- `AnalyticsProcessor` — computes per-IP signal aggregates, writes findings back to Redis
- Signal injection into the pipeline via `_get_analytics_signals()` (fail-open: returns `[]` on any error)
- Prometheus metrics for stream lag, processing rate, and error counts

## Implementation

- Python service: `src/analytics/` — production code, runs in the analytics container
- Go integration: `internal/security/analytics_signals.go`

## See also

- [Analytics development guide](../../developer/analytics-development.md)
- [Analytics security notes](../../security/analytics-security.md)
