"""
Phase 86d / 86i — Datadog Agent integration check for JA4proxy.

Two-layer integration pattern (Phase 86i):

    Layer 1 — OpenMetrics scrape (deploy/datadog/conf.d/openmetrics.d/ja4proxy.yaml)
        The Datadog Agent's built-in OpenMetrics integration scrapes the
        ja4proxy /metrics Prometheus endpoint directly, preserving every
        label (action, bypass, signal, le, ...). This is where ALL numeric
        gauges/counters/histograms live.

    Layer 2 — this custom check (deploy/datadog/checks/ja4proxy/check.py)
        Owns ONLY things Prometheus exposition cannot express:
            - service_check("ja4proxy.node_health", ...)   — discrete
              OK / WARNING / CRITICAL / UNKNOWN status derived from the
              Management API /health/deep semantic status field.
            - service_check("ja4proxy.redis_health", ...)  — split out so
              Redis issues page Redis, not node.
            - (future) cross-node derived aggregates that require the Agent
              to correlate multiple instances.

    Prior to Phase 86i this check also emitted a pile of ``self.gauge()`` /
    ``self.rate()`` calls that duplicated metrics already present in the
    Prometheus exposition — losing all labels in the process. Those calls
    have been removed; install the Layer 1 OpenMetrics config alongside
    this check to get the per-label breakdowns.

Install:
    cp -r checks/ja4proxy /etc/datadog-agent/checks.d/ja4proxy
    cp conf.d/ja4proxy.d/conf.yaml /etc/datadog-agent/conf.d/ja4proxy.d/conf.yaml
    cp conf.d/openmetrics.d/ja4proxy.yaml \\
        /etc/datadog-agent/conf.d/openmetrics.d/ja4proxy.yaml

Requires: Datadog Agent 7.40+ (Python 3 runtime).
"""

from __future__ import annotations

import socket
from typing import Any, Dict, List

from datadog_checks.base import AgentCheck, is_affirmative  # noqa: F401


class JA4proxyCheck(AgentCheck):
    """Datadog Agent check that polls JA4proxy /api/v1/health/deep and
    emits only service checks — all numeric metrics come from the
    OpenMetrics Layer 1 scrape."""

    HTTP_CONFIG_RELOAD_ENABLED = False  # manage our own session

    def __init__(self, name, init_config, instances):
        super(JA4proxyCheck, self).__init__(name, init_config, instances)
        self._http = None

    def _get_http(self):
        """Lazy-create the HTTP client (reuses Agent's connection pool)."""
        if self._http is None:
            self._http = self.http
        return self._http

    def check(self, instance: Dict[str, Any]) -> None:  # type: ignore[override]
        base_url = instance.get("management_url", "").rstrip("/")
        if not base_url:
            self.log.error("management_url is required in instance config")
            return

        tags = self._get_tags(instance)
        timeout = instance.get("timeout", 10)
        api_token = instance.get("api_token", "")

        # ── Poll health/deep endpoint ─────────────────────────────────────
        headers = {}
        if api_token:
            headers["Authorization"] = f"Bearer {api_token}"
        try:
            response = self._get_http().get(
                f"{base_url}/api/v1/health/deep",
                timeout=timeout,
                headers=headers,
            )
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            self.log.warning("Failed to poll JA4proxy: %s", exc)
            self.service_check(
                "ja4proxy.node_health",
                AgentCheck.UNKNOWN,
                tags=tags,
                message=f"Cannot reach JA4proxy: {exc}",
            )
            self.service_check(
                "ja4proxy.redis_health",
                AgentCheck.UNKNOWN,
                tags=tags,
                message=f"Cannot reach JA4proxy: {exc}",
            )
            return

        # ── Node health service check ───────────────────────────────────
        status = data.get("status", "unknown")
        if status == "ok":
            self.service_check("ja4proxy.node_health", AgentCheck.OK, tags=tags)
        elif status == "degraded":
            self.service_check(
                "ja4proxy.node_health",
                AgentCheck.WARNING,
                tags=tags,
                message=f"Node degraded: {data.get('details', '')}",
            )
        else:
            self.service_check(
                "ja4proxy.node_health",
                AgentCheck.CRITICAL,
                tags=tags,
                message=f"Node error: {status}",
            )

        # ── Redis health service check (split from node_health so on-call
        #    gets the right page) ────────────────────────────────────────
        redis = data.get("redis", {})
        if isinstance(redis, dict):
            redis_status = redis.get("status", "unknown")
        else:
            redis_status = str(redis)
        if redis_status == "ok":
            self.service_check("ja4proxy.redis_health", AgentCheck.OK, tags=tags)
        elif redis_status == "degraded":
            self.service_check(
                "ja4proxy.redis_health",
                AgentCheck.WARNING,
                tags=tags,
                message="Redis degraded",
            )
        elif redis_status == "unknown":
            self.service_check(
                "ja4proxy.redis_health",
                AgentCheck.UNKNOWN,
                tags=tags,
                message="Redis status unknown",
            )
        else:
            self.service_check(
                "ja4proxy.redis_health",
                AgentCheck.CRITICAL,
                tags=tags,
                message=f"Redis error: {redis_status}",
            )

        # NOTE: Numeric metrics (redis latency, dial setting, cert days,
        # connection counters, block rate, ban counts, ...) are emitted by
        # the Layer 1 OpenMetrics scrape against /metrics. Do not add
        # self.gauge() / self.rate() calls for those here — they would lose
        # label richness and double-count against Datadog billing.

    @staticmethod
    def _get_tags(instance: Dict[str, Any]) -> List[str]:
        """Build tag list from instance config."""
        tags = list(instance.get("tags", []))
        node = instance.get("node", socket.gethostname())
        tags.append(f"node:{node}")
        return tags
