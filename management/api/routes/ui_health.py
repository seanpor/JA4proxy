"""Four-state UI health endpoint (/api/v1/health/ui) — Phase 824d.

Probes every console partial in-process and classifies each into one of four states:
- OK: Rendered with data.
- EMPTY: Rendered, legitimately no data in window (does NOT make aggregate RED).
- DEGRADED: Dependency unavailable (e.g. Redis down, Prometheus unreachable); fail-open (does NOT make aggregate RED).
- BROKEN: Route missing, 5xx, non-HTML, or timeout (makes aggregate RED).

Aggregate rule:
  status is RED if any panel is BROKEN, otherwise GREEN.
  degraded is the count of DEGRADED panels.

Security:
  - Requires Role.auditor (all authenticated users).
  - Probes in-process via httpx.AsyncClient(transport=ASGITransport(app=request.app)).
  - Forwards caller cookie credentials so probes execute under the same session.
  - Reason codes are strictly mapped to fixed identifiers; upstream exceptions are never exposed.
  - Excludes /api/v1/health/ui itself to prevent recursion.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Request
from httpx import ASGITransport, AsyncClient

from ..auth import require_role
from ..models import Role

router = APIRouter(tags=["health"])
logger = logging.getLogger(__name__)

# Markers per panel to distinguish DEGRADED (dependency down) vs EMPTY vs OK.
# Based on template markup inspection:
# - alerts-bar: "Alerts Monitoring Degraded" (Prometheus unavailable)
# - panel1-5: "UNAVAILABLE"
# - health-cards: "DOWN" (Redis card value)
# - infrastructure: "No heartbeat" or "DISCONNECTED" or "DOWN"
# Empty markers:
# - attack-top: "No high-activity IPs"
# - attack-fingerprint-table: "No fingerprint data"
# - audit: "No audit events found"
# - bans: "No active bans"
# - intelligence: "No high-confidence findings active"
# - intelligence-review: "No matching findings to review"
# - list-table: "No entries yet"
# - triage-queue: "No IPs in the grey zone"
# - threat-posture: "No events in the"
PANEL_MARKERS: dict[str, dict[str, list[str]]] = {
    "alerts-bar": {
        "degraded": ["Alerts Monitoring Degraded"],
        "empty": [],
    },
    "panel1-harm": {
        "degraded": ["UNAVAILABLE"],
        "empty": ["OK (0)"],
    },
    "panel2-decisions": {
        "degraded": ["UNAVAILABLE"],
        "empty": ["OK (0)"],
    },
    "panel3-liveness": {
        "degraded": ["UNAVAILABLE"],
        "empty": ["OK (0)"],
    },
    "panel4-reliability": {
        "degraded": ["UNAVAILABLE"],
        "empty": ["OK (0)"],
    },
    "panel5-changes": {
        "degraded": ["UNAVAILABLE"],
        "empty": ["OK (0)", "No recent dial changes"],
    },
    "health-cards": {
        "degraded": [">DOWN<", "value\">DOWN<", "Redis</span>\n          <span class=\"text-xs font-mono font-bold text-slate-100\">DOWN"],
        "empty": [],
    },
    "infrastructure": {
        "degraded": ["DISCONNECTED", "No heartbeat"],
        "empty": [],
    },
    "attack-top": {
        "degraded": [],
        "empty": ["No high-activity IPs"],
    },
    "attack-fingerprint-table": {
        "degraded": [],
        "empty": ["No fingerprint data"],
    },
    "audit": {
        "degraded": [],
        "empty": ["No audit events found"],
    },
    "bans": {
        "degraded": [],
        "empty": ["No active bans"],
    },
    "intelligence": {
        "degraded": [],
        "empty": ["No high-confidence findings active"],
    },
    "intelligence-review": {
        "degraded": [],
        "empty": ["No matching findings to review"],
    },
    "list-table": {
        "degraded": [],
        "empty": ["No entries yet"],
    },
    "triage-queue": {
        "degraded": [],
        "empty": ["No IPs in the grey zone"],
    },
    "threat-posture": {
        "degraded": [],
        "empty": ["No events in the"],
    },
}

PROBE_TIMEOUT_SECONDS = 3.0


def _get_target_panels() -> dict[str, str]:
    """Map canonical panel_id -> probe URL from the template route catalogue."""
    try:
        from management.tests.hx_targets import hx_targets  # type: ignore[import-not-found]
        targets = hx_targets()
    except Exception as exc:  # noqa: BLE001
        logger.warning("ui_health | failed to import hx_targets: %s", exc)
        return {}

    panels: dict[str, str] = {}
    for method, url, path in targets:
        if method != "GET":
            continue
        if path.startswith("/api/v1/health/ui"):
            continue
        pid = path.rstrip("/").split("/")[-1]
        # Prefer simpler non-query or canonical url if not already present
        if pid not in panels or "?" not in url:
            panels[pid] = url
    return panels


@router.get("/api/v1/health/ui")
async def ui_health(
    request: Request,
    _user=Depends(require_role(Role.auditor)),
) -> dict[str, Any]:
    """Report aggregate and per-panel health across all console partials."""
    panels_map = _get_target_panels()
    headers: dict[str, str] = {}
    if "cookie" in request.headers:
        headers["cookie"] = request.headers["cookie"]
    if "authorization" in request.headers:
        headers["authorization"] = request.headers["authorization"]

    transport = ASGITransport(app=request.app)
    results: list[dict[str, Any]] = []
    degraded_count = 0
    is_broken = False

    async with AsyncClient(
        transport=transport,
        base_url="http://internal-ui-health",
        headers=headers,
        timeout=PROBE_TIMEOUT_SECONDS,
    ) as client:
        for pid in sorted(panels_map.keys()):
            url = panels_map[pid]
            start_t = time.perf_counter()
            panel_entry: dict[str, Any] = {"id": pid}

            try:
                resp = await client.get(url)
                elapsed_ms = int((time.perf_counter() - start_t) * 1000)
                panel_entry["ms"] = elapsed_ms

                if resp.status_code == 404:
                    panel_entry["state"] = "BROKEN"
                    panel_entry["reason"] = "route_missing"
                    is_broken = True
                elif resp.status_code >= 500:
                    panel_entry["state"] = "BROKEN"
                    panel_entry["reason"] = "http_5xx"
                    is_broken = True
                elif "text/html" not in resp.headers.get("content-type", ""):
                    panel_entry["state"] = "BROKEN"
                    panel_entry["reason"] = "non_html"
                    is_broken = True
                else:
                    # Content-based classification
                    body = resp.text
                    markers = PANEL_MARKERS.get(pid, {})
                    degraded_markers = markers.get("degraded", [])
                    empty_markers = markers.get("empty", [])

                    # Special case for health-cards: check for 'DOWN' on the Redis card
                    is_degraded = any(m in body for m in degraded_markers)
                    if pid == "health-cards" and ("DOWN" in body and "Redis" in body):
                        is_degraded = True

                    if is_degraded:
                        panel_entry["state"] = "DEGRADED"
                        panel_entry["reason"] = "dependency_unavailable"
                        degraded_count += 1
                    elif any(m in body for m in empty_markers):
                        panel_entry["state"] = "EMPTY"
                        panel_entry["reason"] = "empty"
                    elif pid == "attack-mode-indicator" and body == "":
                        panel_entry["state"] = "EMPTY"
                        panel_entry["reason"] = "empty"
                    else:
                        panel_entry["state"] = "OK"

            except httpx.TimeoutException:
                elapsed_ms = int((time.perf_counter() - start_t) * 1000)
                panel_entry["ms"] = elapsed_ms
                panel_entry["state"] = "BROKEN"
                panel_entry["reason"] = "timeout"
                is_broken = True
            except Exception as exc:  # noqa: BLE001
                elapsed_ms = int((time.perf_counter() - start_t) * 1000)
                panel_entry["ms"] = elapsed_ms
                panel_entry["state"] = "BROKEN"
                panel_entry["reason"] = "http_5xx"
                is_broken = True
                logger.warning("ui_health | panel %s failed: %s", pid, exc)

            results.append(panel_entry)

    aggregate_status = "RED" if is_broken else "GREEN"
    return {
        "status": aggregate_status,
        "degraded": degraded_count,
        "panels": results,
    }
