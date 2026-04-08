"""Centralised Prometheus metric registry for the Phase 85 TI feed runner.

All eight metrics from PHASE_85.md §10.1 are declared here once, then
imported by the modules that increment them. Declaring a metric in more
than one module triggers a ``Duplicated timeseries`` error at import time
because ``prometheus_client`` registers every ``Counter`` / ``Gauge`` /
``Histogram`` instance into the global registry on construction.

Every metric name is namespaced with ``ja4proxy_`` per the project
convention. Labels are kept narrow — ``feed_id`` and one dimension at most,
to avoid cardinality explosions on large deployments.
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

#: Poll outcomes. ``result`` in {``success``, ``failure``, ``skipped``, ``circuit_open``}.
TI_POLL_TOTAL = Counter(
    "ja4proxy_ti_feed_poll_total",
    "TI feed poll outcomes",
    ["feed_id", "result"],
)

#: Wall-clock time per poll.
TI_POLL_DURATION = Histogram(
    "ja4proxy_ti_feed_poll_duration_seconds",
    "Wall-clock time per TI feed poll",
    ["feed_id"],
)

#: Per-indicator outcomes inside a poll.
#: ``outcome`` in {``created``, ``existing``, ``below_confidence``,
#: ``unsupported``, ``expired``}. ``expired`` is incremented by the TAXII
#: client when an indicator's ``valid_until`` is in the past at poll time.
TI_INDICATORS_PROCESSED = Counter(
    "ja4proxy_ti_feed_indicators_processed_total",
    "Per-indicator outcomes inside a TI feed poll",
    ["feed_id", "outcome"],
)

#: Current number of indicators managed by a feed (size of active_stix_ids HASH).
TI_INDICATORS_MANAGED = Gauge(
    "ja4proxy_ti_feed_indicators_managed",
    "Current number of indicators managed by a TI feed",
    ["feed_id"],
)

#: Indicators removed by differential cleanup.
TI_CLEANUP_REMOVALS = Counter(
    "ja4proxy_ti_feed_cleanup_removals_total",
    "Indicators removed by TI feed differential cleanup",
    ["feed_id"],
)

#: Circuit breaker state: 0=closed, 1=half_open, 2=open.
TI_CIRCUIT_STATE = Gauge(
    "ja4proxy_ti_feed_circuit_state",
    "TI feed circuit breaker state (0=closed, 1=half_open, 2=open)",
    ["feed_id"],
)

#: Unix timestamp of the last successful poll.
TI_LAST_SUCCESS_TS = Gauge(
    "ja4proxy_ti_feed_last_success_timestamp_seconds",
    "Unix timestamp of the last successful TI feed poll",
    ["feed_id"],
)

#: Management API round-trip failures observed by the feed runner.
TI_MGMT_API_ERRORS = Counter(
    "ja4proxy_ti_feed_mgmt_api_errors_total",
    "Management API errors observed by the TI feed runner",
    ["feed_id", "status_code"],
)

#: Seed-file entry load outcomes. ``outcome`` in {``created``, ``error``}.
TI_SEED_ENTRIES = Counter(
    "ja4proxy_ti_feed_seed_file_entries_total",
    "Seed-file fingerprint entries loaded per outcome",
    ["outcome"],
)
