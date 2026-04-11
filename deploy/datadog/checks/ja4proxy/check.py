"""
Phase 86d — Datadog Agent integration check for JA4proxy.

Install:
    cp -r checks/ja4proxy /etc/datadog-agent/checks.d/ja4proxy
    cp conf.d/ja4proxy.d/conf.yaml /etc/datadog-agent/conf.d/ja4proxy.d/conf.yaml

Requires: Datadog Agent 7.40+ (Python 3 runtime).
"""

from __future__ import annotations

import json
import socket
from typing import Any, Dict, List, Optional

from datadog_checks.base import AgentCheck, is_affirmative


class JA4proxyCheck(AgentCheck):
    """Datadog Agent check that polls JA4proxy /api/v1/health/deep."""

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
            return

        # ── Node health ─────────────────────────────────────────────────
        status = data.get("status", "unknown")
        if status == "ok":
            self.gauge("ja4proxy.node.healthy", 1, tags=tags)
            self.service_check("ja4proxy.node_health", AgentCheck.OK, tags=tags)
        elif status == "degraded":
            self.gauge("ja4proxy.node.healthy", 0, tags=tags)
            self.service_check(
                "ja4proxy.node_health", AgentCheck.WARNING, tags=tags,
                message=f"Node degraded: redis_latency={data.get('redis_latency_ms')}ms",
            )
        else:
            self.gauge("ja4proxy.node.healthy", -1, tags=tags)
            self.service_check(
                "ja4proxy.node_health", AgentCheck.CRITICAL, tags=tags,
                message=f"Node error: {status}",
            )

        # ── Redis latency ───────────────────────────────────────────────
        redis_ms = data.get("redis_latency_ms")
        if redis_ms is not None:
            self.gauge("ja4proxy.node.redis_latency_ms", float(redis_ms), tags=tags)

        # ── Dial setting ────────────────────────────────────────────────
        dial = data.get("dial")
        if dial is not None:
            self.gauge("ja4proxy.node.dial_setting", int(dial), tags=tags)

        # ── Certificate days remaining ──────────────────────────────────
        cert_days = data.get("cert_days_remaining")
        if cert_days is not None:
            self.gauge("ja4proxy.node.cert_days_remaining", float(cert_days), tags=tags)

        # ── Connection metrics ──────────────────────────────────────────
        active = data.get("active_connections")
        if active is not None:
            self.gauge("ja4proxy.connections.active", int(active), tags=tags)

        conn_total = data.get("connections_total")
        if conn_total is not None:
            self.rate("ja4proxy.connections.total", int(conn_total), tags=tags)

        block_rate = data.get("block_rate_pct")
        if block_rate is not None:
            self.gauge("ja4proxy.block_rate_pct", float(block_rate), tags=tags)

        active_bans = data.get("active_bans")
        if active_bans is not None:
            self.gauge("ja4proxy.bans.active", int(active_bans), tags=tags)

    @staticmethod
    def _get_tags(instance: Dict[str, Any]) -> List[str]:
        """Build tag list from instance config."""
        tags = list(instance.get("tags", []))
        node = instance.get("node", socket.gethostname())
        tags.append(f"node:{node}")
        return tags
