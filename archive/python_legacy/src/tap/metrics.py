"""TAP-mode Prometheus metrics (Phase 20, Group 11)."""

from prometheus_client import Counter, Gauge, Histogram

# ---------------------------------------------------------------------------
# Capture metrics
# ---------------------------------------------------------------------------

TAP_PACKETS_RECEIVED_TOTAL = Counter(
    "ja4proxy_tap_packets_received_total",
    "Total packets received from the capture interface",
    ["interface"],
)

TAP_PACKETS_DROPPED_TOTAL = Counter(
    "ja4proxy_tap_packets_dropped_total",
    "Total packets dropped before processing (overflow, truncated, parse_error)",
    ["interface", "reason"],
)

TAP_RING_BUFFER_FILL_RATIO = Gauge(
    "ja4proxy_tap_ring_buffer_fill_ratio",
    "Current ring-buffer fill ratio per interface (0.0–1.0)",
    ["interface"],
)

TAP_CAPTURE_ERRORS_TOTAL = Counter(
    "ja4proxy_tap_capture_errors_total",
    "Total errors encountered during packet capture",
    ["error_type"],
)

# ---------------------------------------------------------------------------
# Reassembly metrics
# ---------------------------------------------------------------------------

TAP_STREAMS_ACTIVE = Gauge(
    "ja4proxy_tap_streams_active",
    "Number of TCP streams currently being reassembled",
)

TAP_STREAMS_TOTAL = Counter(
    "ja4proxy_tap_streams_total",
    "Total TCP streams seen since startup",
)

TAP_STREAM_EVICTIONS_TOTAL = Counter(
    "ja4proxy_tap_stream_evictions_total",
    "Total streams evicted from the reassembly table (timeout, capacity, rst, fin)",
    ["reason"],
)

TAP_OUT_OF_ORDER_SEGMENTS_TOTAL = Counter(
    "ja4proxy_tap_out_of_order_segments_total",
    "Total TCP segments received out of order",
)

TAP_REASSEMBLY_ERRORS_TOTAL = Counter(
    "ja4proxy_tap_reassembly_errors_total",
    "Total errors encountered during TCP stream reassembly",
    ["error_type"],
)

# ---------------------------------------------------------------------------
# Fingerprint metrics
# ---------------------------------------------------------------------------

TAP_FINGERPRINTS_EXTRACTED_TOTAL = Counter(
    "ja4proxy_tap_fingerprints_extracted_total",
    "Total fingerprints successfully extracted, by type",
    ["type"],
)

TAP_FINGERPRINT_EXTRACTION_ERRORS_TOTAL = Counter(
    "ja4proxy_tap_fingerprint_extraction_errors_total",
    "Total fingerprint extraction failures, by type",
    ["type"],
)

TAP_FINGERPRINT_PROCESSING_SECONDS = Histogram(
    "ja4proxy_tap_fingerprint_processing_seconds",
    "Time spent extracting a single fingerprint, by type",
    ["type"],
    buckets=[0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1],
)

# ---------------------------------------------------------------------------
# Pipeline metrics
# ---------------------------------------------------------------------------

TAP_PIPELINE_SCORE_DISTRIBUTION = Histogram(
    "ja4proxy_tap_pipeline_score_distribution",
    "Distribution of risk scores produced by the TAP pipeline",
    buckets=[0, 10, 20, 35, 55, 70, 85, 100],
)

TAP_PIPELINE_ACTIONS_TOTAL = Counter(
    "ja4proxy_tap_pipeline_actions_total",
    "Total actions emitted by the TAP pipeline (observe, flag, signal_slow, signal_block, signal_ban)",
    ["action"],
)

TAP_PIPELINE_ERRORS_TOTAL = Counter(
    "ja4proxy_tap_pipeline_errors_total",
    "Total errors encountered in the TAP pipeline",
)

# ---------------------------------------------------------------------------
# Enforcement metrics
# ---------------------------------------------------------------------------

TAP_ENFORCEMENT_BANS_TOTAL = Counter(
    "ja4proxy_tap_enforcement_bans_total",
    "Total enforcement ban actions issued, by backend (iptables, bgp, webhook)",
    ["backend"],
)

TAP_ENFORCEMENT_ERRORS_TOTAL = Counter(
    "ja4proxy_tap_enforcement_errors_total",
    "Total enforcement backend errors",
    ["backend"],
)

TAP_ENFORCEMENT_LATENCY_SECONDS = Histogram(
    "ja4proxy_tap_enforcement_latency_seconds",
    "Time taken to enforce a ban action, by backend",
    ["backend"],
    buckets=[0.001, 0.01, 0.1, 1.0, 5.0],
)

# ---------------------------------------------------------------------------
# Export metrics
# ---------------------------------------------------------------------------

TAP_EXPORT_EVENTS_TOTAL = Counter(
    "ja4proxy_tap_export_events_total",
    "Total events dispatched to intelligence exporters",
    ["exporter", "event_type"],
)

TAP_EXPORT_ERRORS_TOTAL = Counter(
    "ja4proxy_tap_export_errors_total",
    "Total export failures, by exporter",
    ["exporter"],
)

TAP_EXPORT_LATENCY_SECONDS = Histogram(
    "ja4proxy_tap_export_latency_seconds",
    "Time taken to deliver an event to an exporter",
    ["exporter"],
)

# ---------------------------------------------------------------------------
# Worker metrics
# ---------------------------------------------------------------------------

TAP_WORKER_RESTARTS_TOTAL = Counter(
    "ja4proxy_tap_worker_restarts_total",
    "Total number of times a TAP worker has been restarted after a crash",
    ["worker_id"],
)

TAP_WORKERS_ACTIVE = Gauge(
    "ja4proxy_tap_workers_active",
    "Number of TAP worker coroutines currently running",
)
