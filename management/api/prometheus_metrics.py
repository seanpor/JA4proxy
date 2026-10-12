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


_KNOWN_ROOTS = {
    "",
    "login",
    "lists",
    "bans",
    "audit",
    "threat-intel",
    "under-attack",
    "security-policy",
    "intelligence-review",
    "metrics",
}

_KNOWN_API_MODULES = {
    "health",
    "ready",
    "dial",
    "config",
    "tokens",
    "nodes",
    "bans",
    "lists",
    "datacenter-policy",
    "attack-mode",
    "attack",
    "threat-intel",
    "edl",
    "compliance",
    "ip",
    "partials",
    "triage",
    "intelligence",
}


def normalise_path(path: str) -> str:
    """Collapse identifiers and unmapped paths so the `path` label stays bounded.

    CLAUDE.md forbids unbounded-cardinality labels. Unmapped/fuzzed paths collapse
    to `{unmatched}` (JA4PROXY-2026-0118) while valid routes parameterize variable
    IDs to `{id}`.
    """
    if not path or path == "/":
        return "/"

    parts = [p for p in path.strip("/").split("/") if p]
    if not parts:
        return "/"

    if len(parts) == 1:
        if parts[0] in _KNOWN_ROOTS:
            return f"/{parts[0]}"
        return "{unmatched}"

    if parts[0] in ("ip", "fingerprint") and len(parts) == 2:
        return f"/{parts[0]}/{{id}}"

    if parts[0] == "auth":
        if len(parts) >= 2 and parts[1] in ("sso", "mfa"):
            normalized = []
            for seg in parts:
                if seg.replace(".", "").replace(":", "").isdigit() or (
                    len(seg) >= 16 and all(c in "0123456789abcdefABCDEF_-" for c in seg)
                ):
                    normalized.append("{id}")
                else:
                    normalized.append(seg)
            return "/" + "/".join(normalized)
        return "{unmatched}"

    if parts[0] == "api" and len(parts) >= 2 and parts[1] == "v1":
        if len(parts) >= 3:
            module = parts[2]
            if module not in _KNOWN_API_MODULES:
                return "{unmatched}"
            normalized = ["api", "v1", module]
            for seg in parts[3:]:
                if (
                    seg.replace(".", "").replace(":", "").isdigit()
                    or (len(seg) >= 16 and all(c in "0123456789abcdefABCDEF_-" for c in seg))
                    or module in ("bans", "lists", "tokens", "nodes", "edl", "ip", "triage", "intelligence")
                ):
                    normalized.append("{id}")
                else:
                    normalized.append(seg)
            return "/" + "/".join(normalized)
        return "/api/v1"

    return "{unmatched}"
