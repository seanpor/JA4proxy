"""Prometheus metrics for the Management UI server.

All metrics follow the ja4proxy_{subsystem}_{name}_{unit} naming convention.
Registered at module import time; cleaned up by conftest _clean_prometheus_registry.
"""

from prometheus_client import Counter, Gauge, Histogram

# ── Request metrics ────────────────────────────────────────────────────────────

mgmt_requests_total = Counter(
    "ja4proxy_mgmt_requests_total",
    "Total HTTP requests to the management server",
    ["method", "endpoint", "status"],
)

mgmt_request_duration_ms = Histogram(
    "ja4proxy_mgmt_request_duration_ms",
    "Management API response time in milliseconds",
    ["endpoint"],
    buckets=[1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000],
)

# ── SSE metrics ────────────────────────────────────────────────────────────────

mgmt_sse_subscribers_active = Gauge(
    "ja4proxy_mgmt_sse_subscribers_active",
    "Number of active SSE connections to the management server",
)

# ── Auth metrics ──────────────────────────────────────────────────────────────

mgmt_auth_failures_total = Counter(
    "ja4proxy_mgmt_auth_failures_total",
    "Total authentication failures against the management API",
)

# ── Action metrics ────────────────────────────────────────────────────────────

mgmt_actions_total = Counter(
    "ja4proxy_mgmt_actions_total",
    "Total admin actions taken via the management API",
    ["action"],
)

policy_changes_total = Counter(
    "ja4proxy_policy_changes_total",
    "Total security policy bypass changes",
    ["bypass"],
)

# ── Error metrics ─────────────────────────────────────────────────────────────

mgmt_redis_errors_total = Counter(
    "ja4proxy_mgmt_redis_errors_total",
    "Total Redis errors encountered by the management server",
    ["operation"],
)
