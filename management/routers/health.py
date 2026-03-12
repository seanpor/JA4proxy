"""Health check router for JA4Proxy Management UI."""

from typing import Any, Dict, Optional

import redis.exceptions
from fastapi import APIRouter, Header, HTTPException, Request, status

from ..server import authenticate

router = APIRouter()


@router.get("/health")
async def health(request: Request) -> Dict[str, Any]:
    """Unauthenticated health check."""
    try:
        await request.app.state.redis.ping()
        return {"status": "healthy", "components": {"redis": "healthy"}}
    except Exception as e:
        return {"status": "degraded", "error": str(e)}


@router.get("/ready")
async def ready(request: Request) -> Dict[str, Any]:
    """Readiness check."""
    try:
        await request.app.state.redis.ping()
        return {"status": "ready", "dependencies": {"redis": True}}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Readiness check failed: {e}",
        )


@router.get("/api/v1/health/detail")
async def health_detail(
    request: Request,
    authorization: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """Authenticated detailed health check."""
    await authenticate(request, authorization)

    try:
        await request.app.state.redis.ping()
        return {"status": "healthy", "redis": True, "version": "13.1.0"}
    except Exception:
        return {"status": "degraded", "redis": "error", "version": "13.1.0"}
