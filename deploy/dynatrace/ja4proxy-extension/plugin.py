#!/usr/bin/env python3
"""
Phase 86e / 86i — Dynatrace EF2 runtime plugin for JA4proxy.

Phase 86i change:
    The plugin now scrapes the ja4proxy Prometheus ``/metrics`` endpoint
    instead of polling the Management API ``/api/v1/health/deep``. This
    preserves every label (bypass, action, signal, le, ...) that the
    JSON-flattening approach previously discarded.

Deploy:
    1. Package this file and extension.yaml into a ZIP:
       zip ja4proxy-extension.zip extension.yaml plugin.py
    2. Upload via Dynatrace Extensions API:
       curl -X POST "https://{tenant}.live.dynatrace.com/api/v2/extensions" \\
         -H "Authorization: Api-Token {token}" \\
         -F "file=@ja4proxy-extension.zip"

Configuration (set in Dynatrace UI under the extension settings):
    metrics_url    — URL of the ja4proxy /metrics Prometheus endpoint
                     (e.g. http://ja4proxy-node-1:8090/metrics)
    api_token      — optional Bearer token for the /metrics endpoint
"""

from __future__ import annotations

import logging
import math
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

# Dynatrace EF2 imports — these are provided by the Dynatrace runtime.
# They will NOT be available when running this file locally.
try:
    from dtpython import (
        dt,  # type: ignore
        dtlog,  # type: ignore
    )

    HAS_DT = True
except ImportError:
    HAS_DT = False


_log = logging.getLogger("ja4proxy.dynatrace")


# ── Minimal Prometheus text-format parser ───────────────────────────────────


def _parse_labels(label_str: str) -> Dict[str, str]:
    """Parse the inside of ``{...}`` into a label dict.

    Accepts the standard Prometheus ``key="value"`` form, including the
    three backslash escapes defined by the exposition format:
    ``\\\\``, ``\\"``, and ``\\n`` (see
    https://prometheus.io/docs/instrumenting/exposition_formats/).

    H15 (PHASE_101): the previous implementation toggled an ``in_quote``
    flag on every ``"`` with no regard for escape sequences, so a label
    value like ``path="a\\"b,c"`` was mis-split at the embedded comma,
    dropping the remainder of the labelset. That broke every sample
    produced by the management API's request-label exporter.
    """
    labels: Dict[str, str] = {}
    if not label_str:
        return labels
    # Tokenise: walk the string honouring backslash escapes inside quoted
    # values. Split on un-quoted commas only.
    parts: List[str] = []
    buf = ""
    in_quote = False
    i = 0
    while i < len(label_str):
        ch = label_str[i]
        if in_quote and ch == "\\" and i + 1 < len(label_str):
            # Consume the escape as a unit — it belongs to the value and
            # must not terminate the quoted region.
            buf += label_str[i : i + 2]
            i += 2
            continue
        if ch == '"':
            in_quote = not in_quote
            buf += ch
        elif ch == "," and not in_quote:
            parts.append(buf)
            buf = ""
        else:
            buf += ch
        i += 1
    if buf:
        parts.append(buf)

    for p in parts:
        if "=" not in p:
            continue
        k, _, v = p.partition("=")
        key = k.strip()
        val = v.strip()
        # Strip one surrounding pair of quotes then decode escape sequences.
        if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
            val = val[1:-1]
        # Unescape in a single pass to avoid double-decoding (e.g. "\\\\n"
        # must stay as a literal backslash followed by an 'n').
        out = []
        j = 0
        while j < len(val):
            if val[j] == "\\" and j + 1 < len(val):
                nxt = val[j + 1]
                if nxt == "n":
                    out.append("\n")
                elif nxt == "\\":
                    out.append("\\")
                elif nxt == '"':
                    out.append('"')
                else:
                    # Unknown escape — preserve both bytes verbatim so we
                    # don't silently corrupt the label value.
                    out.append(val[j : j + 2])
                j += 2
                continue
            out.append(val[j])
            j += 1
        labels[key] = "".join(out)
    return labels


def parse_prometheus_text(text: str) -> List[Tuple[str, Dict[str, str], float]]:
    """Parse Prometheus text exposition into a list of
    ``(metric_name, labels, value)`` triples.

    Handles counter, gauge, and histogram ``_bucket`` / ``_sum`` / ``_count``
    lines. HELP/TYPE comment lines are ignored. Non-numeric values, NaN,
    and malformed lines are skipped.
    """
    samples: List[Tuple[str, Dict[str, str], float]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Split off the trailing value.
        if "{" in line and "}" in line:
            name_part, _, rest = line.partition("{")
            label_part, _, value_part = rest.partition("}")
            name = name_part.strip()
            labels = _parse_labels(label_part)
            value_str = value_part.strip().split()[0] if value_part.strip() else ""
        else:
            # No labels: `name value [timestamp]`
            pieces = line.split()
            if len(pieces) < 2:
                continue
            name = pieces[0]
            labels = {}
            value_str = pieces[1]
        if not value_str:
            continue
        try:
            value = float(value_str)
        except ValueError:
            continue
        # H15 (PHASE_101): Prometheus treats NaN as a valid sample (some
        # counters emit it to signal "value unknown this scrape"), but
        # pushing NaN/Inf into Dynatrace corrupts the downstream time
        # series. ``float("NaN")`` and ``float("Inf")`` both succeed, so
        # the ValueError guard above is not enough — filter explicitly.
        if math.isnan(value) or math.isinf(value):
            _log.debug(
                "ja4proxy dynatrace: skipping non-finite sample name=%s value=%r",
                name,
                value_str,
            )
            continue
        samples.append((name, labels, value))
    return samples


def scrape_metrics(url: str, api_token: str = "", timeout: float = 10.0) -> List[Tuple[str, Dict[str, str], float]]:
    """Fetch a Prometheus ``/metrics`` endpoint and return parsed samples.

    On any failure (network, HTTP, parse), logs a single error line and
    returns an empty list — never raises. This preserves the fail-open
    principle: a broken Dynatrace scrape must never interrupt the proxy.
    """
    req = urllib.request.Request(url, headers={"Accept": "text/plain"})
    if api_token:
        req.add_header("Authorization", f"Bearer {api_token}")
    try:
        ctx = ssl.create_default_context() if url.startswith("https") else None
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # nosemgrep
            body = resp.read().decode("utf-8", errors="replace")
    except Exception as exc:  # OSError, HTTPError, URLError, ssl.SSLError
        _log.error("ja4proxy dynatrace scrape failed: url=%s err=%s", url, exc)
        return []
    try:
        return parse_prometheus_text(body)
    except Exception as exc:
        _log.error("ja4proxy dynatrace parse failed: %s", exc)
        return []


# ── Plugin class ────────────────────────────────────────────────────────────


class JA4proxyPlugin:
    """Dynatrace EF2 plugin that scrapes the ja4proxy /metrics endpoint."""

    def __init__(self, config: Dict[str, Any]):
        # Back-compat: accept either `metrics_url` (new) or derive from
        # `management_url` (pre-86i config).
        metrics_url = config.get("metrics_url", "")
        if not metrics_url:
            mgmt = config.get("management_url", "").rstrip("/")
            if mgmt:
                metrics_url = f"{mgmt}/metrics"
        self.metrics_url = metrics_url
        self.api_token = config.get("api_token", "")
        self.timeout = config.get("timeout", 10)

        if not self.metrics_url:
            raise ValueError(
                "metrics_url (or management_url) is required in plugin configuration"
            )

    def query(self, **kwargs) -> List[Any]:
        """Called by the Dynatrace runtime on each collection interval.

        Returns a list of metric series objects mapped from the Prometheus
        exposition. M25 (PHASE_101): the ``ja4proxy:node`` topology entity
        is emitted on **every** tick, including when ``scrape_metrics``
        returns no samples. Dynatrace needs a live topology record to
        surface the node as "scrape failing" rather than "node missing".
        """
        if not HAS_DT:
            # Running locally — skip (no Dynatrace runtime available)
            return []

        dtlog.info(f"JA4proxyPlugin: scraping {self.metrics_url}")
        samples = scrape_metrics(
            self.metrics_url,
            api_token=self.api_token,
            timeout=self.timeout,
        )
        # Always produce at least the topology entity, even if the scrape
        # returned nothing.
        return self._build_series(samples)

    def _build_series(
        self, samples: List[Tuple[str, Dict[str, str], float]]
    ) -> List[Any]:
        """Map Prometheus samples to Dynatrace metric series.

        Only a curated subset is forwarded — declared in extension.yaml.
        """
        if not HAS_DT:
            return []

        node_name = self._extract_node_name()
        dt_now = int(datetime.now(timezone.utc).timestamp() * 1000)

        # prometheus name -> dynatrace metric key
        name_map = {
            "ja4proxy_connections_active": "ext:ja4proxy.connections.active",
            "ja4proxy_redis_latency_seconds": "ext:ja4proxy.node.redis_latency_ms",
            "ja4proxy_block_rate": "ext:ja4proxy.block_rate",
            "ja4proxy_dial_setting": "ext:ja4proxy.dial_setting",
            "ja4proxy_cert_days_remaining": "ext:ja4proxy.cert_days_remaining",
            "ja4proxy_bans_active": "ext:ja4proxy.active_bans",
            "ja4proxy_node_healthy": "ext:ja4proxy.node.healthy",
        }

        series: List[Any] = []
        series.append(
            dt.TopologyBuilder()
            .series("ja4proxy:node")
            .dimensions(node_name=node_name)
            .build()
        )

        for name, labels, value in samples:
            dt_key = name_map.get(name)
            if not dt_key:
                continue
            # redis latency: convert seconds -> ms for back-compat.
            if name == "ja4proxy_redis_latency_seconds":
                value = value * 1000.0
            builder = dt.series(dt_key).dimensions(node=node_name, **labels)
            series.append(builder.point(value, dt_now).build())

        return series

    def _extract_node_name(self) -> str:
        """Derive a node name for topology and dimension tagging."""
        import socket
        return socket.gethostname()


# ── Entry point for Dynatrace EF2 ─────────────────────────────────────────────


def build(config: Dict[str, Any], **kwargs) -> JA4proxyPlugin:
    """Factory function called by Dynatrace EF2 runtime."""
    return JA4proxyPlugin(config)
