"""Health endpoints.

GET /api/v1/health       — surface health (always 200; auth optional)
GET /api/v1/health/deep  — deep Redis health check (requires Auditor role)
GET /api/v1/ready        — readiness probe for load balancers (public, no auth)

Failure policy for /health: always returns HTTP 200. Redis / GeoIP failures
set the relevant field to "unavailable" and overall status to "degraded". The
endpoint must never return HTTP 500 from an infrastructure failure.
"""

import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ..auth import require_role
from ..models import HealthResponse, Role
from ..redis_client import get_redis, get_redis_client

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])

# Module-level start time for uptime tracking
_START_TIME: float = time.monotonic()


@router.get("/api/v1/health", response_model=HealthResponse)
async def health(
    request: Request,
    redis=Depends(get_redis),
) -> HealthResponse:
    """Return system health status.

    Never raises — all failures are caught and reflected in the response body.
    """
    uptime = time.monotonic() - _START_TIME

    # ── Redis check ───────────────────────────────────────────────────────────
    redis_status = "unavailable"
    proxy_instances = 0
    try:
        await redis.ping()
        redis_status = "ok"
        # Estimate proxy instances via a heartbeat key pattern.
        # Proxy instances write "proxy:heartbeat:{instance_id}" keys periodically.
        keys = await redis.keys("proxy:heartbeat:*")
        proxy_instances = len(keys) if keys else 0
    except Exception as exc:  # noqa: BLE001
        logger.warning("health | event=redis_unavailable | error=%s", exc)

    # ── GeoIP check ───────────────────────────────────────────────────────────
    geoip_status = _check_geoip()

    overall = "ok" if redis_status == "ok" else "degraded"

    return HealthResponse(
        status=overall,
        redis=redis_status,
        proxy_instances=proxy_instances,
        geoip=geoip_status,
        uptime_seconds=round(uptime, 2),
    )


def _check_geoip() -> str:
    """Check whether the GeoIP database file is present."""
    geoip_path = os.environ.get("GEOIP_DB_PATH", "/opt/geoip/GeoLite2-City.mmdb")
    if os.path.exists(geoip_path):
        return "ok"
    return "unavailable"


@router.get("/api/v1/health/deep")
async def health_deep(
    current_user=Depends(require_role(Role.auditor)),
    redis=Depends(get_redis),
):
    """Deep health check — verifies Redis connectivity and returns latency.

    Returns HTTP 200 when Redis is healthy, 503 when degraded.
    Requires at minimum the Auditor role.
    """
    ts = datetime.now(timezone.utc).isoformat()
    try:
        await redis.ping()
        return {
            "status": "ok",
            "redis": {"status": "ok"},
            "timestamp": ts,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("health_deep | event=redis_error | error=%s", exc)
        return JSONResponse(
            status_code=503,
            content={
                "status": "degraded",
                "redis": {"status": "error", "error": str(exc)},
                "timestamp": ts,
            },
        )


@router.get("/api/v1/ready")
async def ready(redis=Depends(get_redis)):
    """Readiness probe — no authentication required.

    Returns 200 {"ready": True} when Redis is reachable and accessible.
    Returns 503 {"ready": False, "reason": ...} on any failure.

    Intended for load-balancer health checks that must not require auth.
    """
    try:
        await redis.ping()
        await redis.get("config:dial")
        return {"ready": True}
    except Exception as exc:  # noqa: BLE001
        logger.warning("ready | event=redis_error | error=%s", exc)
        return JSONResponse(
            status_code=503,
            content={"ready": False, "reason": str(exc)},
        )
