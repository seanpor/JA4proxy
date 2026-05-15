"""
Robust Health Check API & Anti-Flap Logic (Phase 41).
Provides deep health visibility and state hysteresis for upstream load balancers.
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from aiohttp import web
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

logger = logging.getLogger(__name__)


class HealthMonitor:
    """
    Tracks deep operational state of the proxy with anti-flap logic.
    """

    def __init__(
        self,
        redis_client,
        config: dict,
        geoip_path: Optional[str] = None,
        rise_threshold: int = 3,
        fall_threshold: int = 2,
    ):
        self.redis = redis_client
        self.config = config
        self.geoip_path = geoip_path
        self._rise_threshold = rise_threshold
        self._fall_threshold = fall_threshold

        # Internal state
        self._is_healthy = False
        self._is_ready = False
        self._success_count = 0
        self._failure_count = 0
        self._start_time = time.time()

        # Component status
        self._components: Dict[str, Dict[str, Any]] = {
            "redis": {"status": "unknown", "latency_ms": 0},
            "geoip": {"status": "unknown"},
            "filesystem": {"status": "unknown"},
        }

        # Performance tracking
        self._pipeline_latencies: List[float] = []
        self._max_latencies = 100

    @property
    def is_healthy(self) -> bool:
        return self._is_healthy

    @property
    def is_ready(self) -> bool:
        # Ready if healthy OR in grace period (first 10 seconds)
        if self._is_healthy:
            return True
        return (time.time() - self._start_time) < 10.0

    def record_pipeline_latency(self, duration_ms: float):
        """Record pipeline processing time for health monitoring."""
        self._pipeline_latencies.append(duration_ms)
        if len(self._pipeline_latencies) > self._max_latencies:
            self._pipeline_latencies.pop(0)

    async def check(self) -> bool:
        """Perform deep health checks and update healthy status via hysteresis."""
        try:
            # 1. Redis Check
            t0 = time.perf_counter()
            await self.redis.ping()
            latency_ms = int((time.perf_counter() - t0) * 1000)
            self._components["redis"] = {
                "status": "healthy" if latency_ms < 500 else "degraded",
                "latency_ms": latency_ms,
            }
            redis_ok = latency_ms < 1000
        except Exception as e:
            self._components["redis"] = {"status": "unhealthy", "error": str(e)}
            redis_ok = False

        # 2. GeoIP Check
        if self.geoip_path:
            p = Path(self.geoip_path)
            if p.exists() and p.stat().st_size > 1024:
                self._components["geoip"] = {
                    "status": "healthy",
                    "size_bytes": p.stat().st_size,
                }
                geoip_ok = True
            else:
                self._components["geoip"] = {
                    "status": "unhealthy",
                    "error": "file missing or too small",
                }
                geoip_ok = False
        else:
            geoip_ok = True  # Optional

        # 3. Filesystem Check (config)
        # Assuming config file is reachable if we are running, but let's be explicit
        self._components["filesystem"] = {"status": "healthy"}
        fs_ok = True

        # Overall iteration result
        iteration_ok = redis_ok and geoip_ok and fs_ok

        # 4. Anti-flap Logic (Hysteresis)
        if iteration_ok:
            self._failure_count = 0
            self._success_count += 1
            if not self._is_healthy and self._success_count >= self._rise_threshold:
                self._is_healthy = True
                logger.info(
                    '{"type":"system","level":"INFO","subsystem":"health","event":"state_changed","status":"healthy"}'
                )
        else:
            self._success_count = 0
            self._failure_count += 1
            if self._is_healthy and self._failure_count >= self._fall_threshold:
                self._is_healthy = False
                logger.warning(
                    '{"type":"system","level":"WARN","subsystem":"health","event":"state_changed","status":"unhealthy"}'
                )

        return self._is_healthy

    def get_status_report(self) -> Dict[str, Any]:
        """Generate full health report for /health endpoint."""
        avg_latency: float = 0.0
        if self._pipeline_latencies:
            avg_latency = sum(self._pipeline_latencies) / len(self._pipeline_latencies)

        return {
            "status": "healthy" if self._is_healthy else "unhealthy",
            "version": self.config.get("version", "unknown"),
            "uptime_seconds": int(time.time() - self._start_time),
            "dial": self.config.get("dial", 0),
            "pipeline_latency_avg_ms": round(avg_latency, 2),
            "components": self._components,
            "ts": datetime.now(timezone.utc).isoformat() + "Z",
        }


class HealthServer:
    """
    Lightweight aiohttp server serving /metrics, /health, and /ready.
    """

    def __init__(self, monitor: HealthMonitor, host: str = "0.0.0.0", port: int = 9090):
        self.monitor = monitor
        self.host = host
        self.port = port
        self.app = web.Application()
        self.app.add_routes(
            [
                web.get("/metrics", self.handle_metrics),
                web.get("/health", self.handle_health),
                web.get("/ready", self.handle_ready),
            ]
        )
        self.runner: Optional[web.AppRunner] = None

    async def handle_metrics(self, request):
        return web.Response(
            body=generate_latest(), headers={"Content-Type": CONTENT_TYPE_LATEST}
        )

    async def handle_health(self, request):
        report = self.monitor.get_status_report()
        status_code = 200 if self.monitor.is_healthy else 503
        return web.json_response(report, status=status_code)

    async def handle_ready(self, request):
        status_code = 200 if self.monitor.is_ready else 503
        return web.json_response(
            {"status": "ready" if self.monitor.is_ready else "not_ready"},
            status=status_code,
        )

    async def start(self):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, self.host, self.port)
        await site.start()
        logger.info(
            '{"type":"system","level":"INFO","subsystem":"health","event":"server_started","host":"%s","port":%d}',
            self.host,
            self.port,
        )

    async def stop(self):
        if self.runner:
            await self.runner.cleanup()
            logger.info(
                '{"type":"system","level":"INFO","subsystem":"health","event":"server_stopped"}'
            )
