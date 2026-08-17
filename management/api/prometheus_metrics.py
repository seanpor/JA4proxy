"""Prometheus metrics for the management console.

WHY THIS EXISTS
---------------
`deploy/monitoring/alertmanager/rules/management_ui_rules.yml` has shipped ten
alerts for this service for months — including:

    ManagementUIRedisErrors    rate(ja4proxy_mgmt_redis_errors_total[5m]) > 0.1
    ManagementUIHighAuthFailures  rate(ja4proxy_mgmt_auth_failures_total[5m]) > 2

Nothing emitted those series. `prometheus_client` was not even a dependency,
there was no ``/metrics`` endpoint, and Prometheus had no scrape job for the
console. Ten alerts, all firing on nothing.

On 2026-08-17 the console's Redis credentials were wrong, every call failed with
AuthenticationError, the login rate limiter failed closed and nobody could log
in. `ManagementUIRedisErrors` describes that exact failure. It could not fire.

These are the six series those rules reference. Names and labels match the rules
verbatim — a metric whose name does not match its alert is the same as no metric
at all (see the phase-820 dead-selector class).
"""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

# A dedicated registry: the console must not inherit the proxy's default
# collectors, and tests need to build the app repeatedly without tripping
# "Duplicated timeseries in CollectorRegistry".
REGISTRY = CollectorRegistry()

# management_ui_rules.yml: rate(ja4proxy_mgmt_requests_total{status="5xx"}) / rate(...)
REQUESTS = Counter(
    "ja4proxy_mgmt_requests_total",
    "Management API requests.",
    ["method", "path", "status"],
    registry=REGISTRY,
)

# histogram_quantile(0.99, rate(ja4proxy_mgmt_request_duration_ms_bucket[5m])) > 500
# Buckets are in MILLISECONDS because the alert threshold is 500 and the metric
# name says _ms. Chosen to straddle that threshold rather than cluster below it.
REQUEST_DURATION_MS = Histogram(
    "ja4proxy_mgmt_request_duration_ms",
    "Management API request duration in milliseconds.",
    ["method", "path"],
    buckets=(5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000),
    registry=REGISTRY,
)

# rate(ja4proxy_mgmt_auth_failures_total[5m]) > 2
AUTH_FAILURES = Counter(
    "ja4proxy_mgmt_auth_failures_total",
    "Failed authentication attempts against the management API.",
    ["reason"],
    registry=REGISTRY,
)

# rate(ja4proxy_mgmt_redis_errors_total[5m]) > 0.1  ← the alert for today's outage
REDIS_ERRORS = Counter(
    "ja4proxy_mgmt_redis_errors_total",
    "Redis operations that failed from the management API.",
    ["operation"],
    registry=REGISTRY,
)

# ja4proxy_mgmt_sse_subscribers_active >= 45
SSE_SUBSCRIBERS = Gauge(
    "ja4proxy_mgmt_sse_subscribers_active",
    "Currently connected SSE subscribers.",
    registry=REGISTRY,
)

# increase(ja4proxy_mgmt_actions_total{action="dial_change"}[5m]) > 0
ACTIONS = Counter(
    "ja4proxy_mgmt_actions_total",
    "Operator actions performed through the management API.",
    ["action"],
    registry=REGISTRY,
)


def normalise_path(path: str) -> str:
    """Collapse identifiers so the `path` label stays bounded.

    CLAUDE.md forbids unbounded-cardinality labels: /api/v1/bans/1.2.3.4 as a
    distinct label value would let anyone inflate Prometheus memory by making
    requests. Numeric, IP-ish and hex-ish segments become ``{id}``.
    """
    out = []
    for seg in path.split("/"):
        if not seg:
            out.append(seg)
        elif seg.replace(".", "").replace(":", "").isdigit() or (
            len(seg) >= 16 and all(c in "0123456789abcdefABCDEF_" for c in seg)
        ):
            out.append("{id}")
        else:
            out.append(seg)
    return "/".join(out) or "/"
