"""
Lightweight aiohttp HTTP server for TAP-mode-only endpoints (Phase 20, Group 2).

Routes:
    GET /api/v1/mode                        — operational stats
    GET /api/v1/fingerprints/ip/{ip}        — connection history for an IP
    GET /api/v1/fingerprints/ja4/{fp}       — usage stats for a JA4 fingerprint
    GET /health                             — TAP health struct (§13.4)

When Phase 13 management server is implemented, these routes migrate to it.
"""

import json
import logging
from typing import Any, Optional

from aiohttp import web

logger = logging.getLogger(__name__)


class TapHttpServer:
    """Lightweight aiohttp HTTP server for TAP-mode endpoints.

    Port: ``tap.http_port`` (default 8090). Started by TapSensor.run().
    """

    def __init__(
        self,
        config: dict,
        redis: Any,
        edl_server: Any = None,
        taxii_server: Any = None,
        sensor: Any = None,
    ) -> None:
        tap_cfg = config.get("tap") or {}
        self._port: int = int(tap_cfg.get("http_port", 8090))
        self._interface: str = tap_cfg.get("interface", "eth0")
        self._redis = redis
        self._edl_server = edl_server
        self._taxii_server = taxii_server
        self._sensor = sensor
        self._runner: Optional[web.AppRunner] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _create_app(self) -> web.Application:
        """Build and return the aiohttp Application (routes only, no I/O)."""
        app = web.Application()
        app.router.add_get("/api/v1/mode", self._handle_mode)
        app.router.add_get("/api/v1/fingerprints/ip/{ip}", self._handle_fp_ip)
        app.router.add_get(
            "/api/v1/fingerprints/ja4/{fingerprint}", self._handle_fp_ja4
        )
        app.router.add_get("/health", self._handle_health)
        return app

    async def start(self) -> None:
        """Bind and start serving on the configured port."""
        app = self._create_app()
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "0.0.0.0", self._port)
        await site.start()
        logger.info(
            json.dumps(
                {
                    "type": "system",
                    "level": "INFO",
                    "subsystem": "tap_http",
                    "event": "http_server_started",
                    "port": self._port,
                }
            )
        )

    async def stop(self) -> None:
        """Stop the HTTP server and release the port."""
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None

    # ------------------------------------------------------------------
    # Route handlers
    # ------------------------------------------------------------------

    async def _handle_mode(self, request: web.Request) -> web.Response:
        """GET /api/v1/mode → JSON with mode, interface, stream/packet counts."""
        stats: dict = {}
        if self._sensor is not None and hasattr(self._sensor, "get_stats"):
            stats = self._sensor.get_stats() or {}

        data = {
            "mode": "tap",
            "interface": self._interface,
            "streams_active": stats.get("streams_active", 0),
            "packets_captured": stats.get("packets_captured", 0),
            "packets_dropped": stats.get("packets_dropped", 0),
        }
        return web.json_response(data)

    async def _handle_health(self, request: web.Request) -> web.Response:
        """GET /health → JSON TAP health struct (§13.4)."""
        redis_status = "healthy"
        overall = "healthy"

        # Check Redis connectivity
        try:
            self._redis.ping()
        except Exception:
            redis_status = "unhealthy"
            overall = "unhealthy"

        # Collect exporter / enforcement statuses from sensor (if wired)
        export_status: dict = {}
        enforcement_status: dict = {}
        if self._sensor is not None:
            if hasattr(self._sensor, "get_exporter_status"):
                export_status = self._sensor.get_exporter_status() or {}
            if hasattr(self._sensor, "get_enforcement_status"):
                enforcement_status = self._sensor.get_enforcement_status() or {}

        # Degrade overall if any non-critical component is degraded
        all_statuses = list(export_status.values()) + list(enforcement_status.values())
        if overall == "healthy" and any(v == "degraded" for v in all_statuses):
            overall = "degraded"

        body = {
            "status": overall,
            "mode": "tap",
            "redis": redis_status,
            "enforcement": enforcement_status,
            "export": export_status,
        }
        http_status = 503 if overall == "unhealthy" else 200
        return web.json_response(body, status=http_status)

    async def _handle_fp_ip(self, request: web.Request) -> web.Response:
        """GET /api/v1/fingerprints/ip/{ip} → JSON connection history."""
        ip = request.match_info["ip"]

        # When FingerprintStore is wired (Group 7), delegate to sensor.get_ip_history()
        if self._sensor is not None and hasattr(self._sensor, "get_ip_history"):
            history = await self._sensor.get_ip_history(ip)
            if history is None:
                raise web.HTTPNotFound(reason=f"No history for IP {ip}")
            return web.json_response({"ip": ip, "connections": history})

        # Skeleton: query Redis fp:ip:{ip} sorted set directly
        try:
            raw = self._redis.zrange(f"fp:ip:{ip}", 0, 9, withscores=True)
        except Exception:
            raw = []

        if not raw:
            raise web.HTTPNotFound(reason=f"No history for IP {ip}")

        connections = [
            {
                "conn_id": (k.decode() if isinstance(k, bytes) else k),
                "timestamp": ts,
            }
            for k, ts in raw
        ]
        return web.json_response({"ip": ip, "connections": connections})

    async def _handle_fp_ja4(self, request: web.Request) -> web.Response:
        """GET /api/v1/fingerprints/ja4/{fingerprint} → JSON usage stats."""
        fingerprint = request.match_info["fingerprint"]

        try:
            raw = self._redis.get(f"fp:ja4:count:{fingerprint}")
            count = int(raw) if raw is not None else 0
        except Exception:
            count = 0

        return web.json_response({"fingerprint": fingerprint, "count": count})
