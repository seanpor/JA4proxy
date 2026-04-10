#!/usr/bin/env python3
"""
Phase 86e — Dynatrace EF2 runtime plugin for JA4proxy.

This plugin polls the JA4proxy Management API `/api/v1/health/deep`
endpoint and maps the JSON response to Dynatrace metrics declared in
`extension.yaml`.

Deploy:
    1. Package this file and extension.yaml into a ZIP:
       zip ja4proxy-extension.zip extension.yaml plugin.py
    2. Upload via Dynatrace Extensions API:
       curl -X POST "https://{tenant}.live.dynatrace.com/api/v2/extensions" \
         -H "Authorization: Api-Token {token}" \
         -F "file=@ja4proxy-extension.zip"

Configuration (set in Dynatrace UI under the extension settings):
    management_url  — Base URL of the JA4proxy Management API
                      (e.g. https://ja4proxy-mgmt.corp.internal)
    api_token       — Bearer token for the Management API (optional)
"""

from __future__ import annotations

import json
import ssl
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Dynatrace EF2 imports — these are provided by the Dynatrace runtime.
# They will NOT be available when running this file locally.
try:
    from dtpython import dt  # type: ignore
    from dtpython import dtlog  # type: ignore

    HAS_DT = True
except ImportError:
    HAS_DT = False


class JA4proxyPlugin:
    """Dynatrace EF2 plugin that polls JA4proxy health/deep endpoint."""

    def __init__(self, config: Dict[str, Any]):
        self.management_url = config.get("management_url", "").rstrip("/")
        self.api_token = config.get("api_token", "")
        self.timeout = config.get("timeout", 10)

        if not self.management_url:
            raise ValueError("management_url is required in plugin configuration")

        # SSL context — use system CAs by default
        self.ssl_ctx = ssl.create_default_context()

    def query(self, **kwargs) -> List[Any]:
        """
        Called by the Dynatrace runtime on each collection interval.

        Returns a list of metric series objects. Each series object maps
        to a metric key declared in extension.yaml.

        Args:
            **kwargs: Additional arguments from the Dynatrace datasource
                      configuration (e.g., feature activation flags).
        """
        if not HAS_DT:
            # Running locally — skip (no Dynatrace runtime available)
            return []

        dtlog.info(f"JA4proxyPlugin: polling {self.management_url}")

        try:
            data = self._fetch_health()
        except Exception as exc:
            dtlog.warning(f"JA4proxyPlugin: failed to poll health endpoint: {exc}")
            return self._series_on_error()

        return self._build_series(data)

    def _fetch_health(self) -> Dict[str, Any]:
        """GET /api/v1/health/deep and return parsed JSON."""
        req = urllib.request.Request(
            f"{self.management_url}/api/v1/health/deep",
            headers={"Accept": "application/json"},
        )
        if self.api_token:
            req.add_header("Authorization", f"Bearer {self.api_token}")

        with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_ctx) as resp:
            return json.loads(resp.read().decode())

    def _build_series(self, data: Dict[str, Any]) -> List[Any]:
        """Map health/deep JSON to Dynatrace metric series."""
        if not HAS_DT:
            return []

        node_name = self._extract_node_name()
        dt_now = int(datetime.now(timezone.utc).timestamp() * 1000)

        series = []

        # ja4proxy:node topology
        topology_series = dt.TopologyBuilder() \
            .series("ja4proxy:node") \
            .dimensions(node_name=node_name) \
            .build()
        series.append(topology_series)

        # Metrics
        status = data.get("status", "unknown")
        healthy_val = {"ok": 1, "degraded": 0, "error": -1}.get(status, -1)

        series.append(
            dt.series("ext:ja4proxy.node.healthy")
            .dimensions(node=node_name)
            .point(healthy_val, dt_now)
            .build()
        )

        redis_ms = data.get("redis_latency_ms")
        if redis_ms is not None:
            series.append(
                dt.series("ext:ja4proxy.node.redis_latency_ms")
                .dimensions(node=node_name)
                .point(float(redis_ms), dt_now)
                .build()
            )

        active = data.get("active_connections")
        if active is not None:
            series.append(
                dt.series("ext:ja4proxy.connections.active")
                .dimensions(node=node_name)
                .point(int(active), dt_now)
                .build()
            )

        block_rate = data.get("block_rate_pct")
        if block_rate is not None:
            series.append(
                dt.series("ext:ja4proxy.block_rate")
                .dimensions(node=node_name)
                .point(float(block_rate), dt_now)
                .build()
            )

        dial = data.get("dial")
        if dial is not None:
            series.append(
                dt.series("ext:ja4proxy.dial_setting")
                .dimensions(node=node_name)
                .point(int(dial), dt_now)
                .build()
            )

        cert_days = data.get("cert_days_remaining")
        if cert_days is not None:
            series.append(
                dt.series("ext:ja4proxy.cert_days_remaining")
                .dimensions(node=node_name)
                .point(float(cert_days), dt_now)
                .build()
            )

        active_bans = data.get("active_bans")
        if active_bans is not None:
            series.append(
                dt.series("ext:ja4proxy.active_bans")
                .dimensions(node=node_name)
                .point(int(active_bans), dt_now)
                .build()
            )

        return series

    def _series_on_error(self) -> List[Any]:
        """Return a single error metric when the health endpoint is unreachable."""
        if not HAS_DT:
            return []

        node_name = self._extract_node_name()
        dt_now = int(datetime.now(timezone.utc).timestamp() * 1000)

        return [
            dt.series("ext:ja4proxy.node.healthy")
            .dimensions(node=node_name)
            .point(-1, dt_now)
            .build()
        ]

    def _extract_node_name(self) -> str:
        """Derive a node name for topology and dimension tagging."""
        import socket
        return socket.gethostname()


# ── Entry point for Dynatrace EF2 ─────────────────────────────────────────────
# The Dynatrace runtime calls this function with the extension configuration.

def build(config: Dict[str, Any], **kwargs) -> JA4proxyPlugin:
    """Factory function called by Dynatrace EF2 runtime."""
    return JA4proxyPlugin(config)
