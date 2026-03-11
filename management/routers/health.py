"""Health check router for JA4Proxy Management UI."""

from typing import Dict, Any, Optional
from fastapi import APIRouter, Request, Header
import redis.asyncio as aioredis

from ..server import authenticate

router = APIRouter()


@router.get("/health")
async def health() -> Dict[str, Any]:
    """Unauthenticated health check."""
    try:
        # Get Redis from request app state
        redis = None
        if hasattr(health, "_redis"):
            redis = health._redis
        else:
            redis = await aioredis.from_url("redis://localhost:6379", decode_responses=True)
            health._redis = redis
        
        await redis.ping()
        return {
            "status": "healthy",
            "components": {
                "redis": "healthy"
            }
        }
    except Exception as e:
        return {
            "status": "degraded",
            "error": str(e)
        }


@router.get("/ready")
async def ready() -> Dict[str, Any]:
    """Readiness check."""
    try:
        redis = None
        if hasattr(ready, "_redis"):
            redis = ready._redis
        else:
            redis = await aioredis.from_url("redis://localhost:6379", decode_responses=True)
            ready._redis = redis
        
        await redis.ping()
        return {
            "status": "ready",
            "dependencies": {
                "redis": True
            }
        }
    except Exception as e:
        from fastapi import HTTPException, status
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Readiness check failed: {e}"
        )


@router.get("/api/v1/health/detail")
async def health_detail(
    request: Request,
    authorization: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """Authenticated detailed health check."""
    await authenticate(request, authorization)
    
    try:
        redis = request.app.state.redis
        await redis.ping()
        return {
            "status": "healthy",
            "redis": True,
            "version": "13.1.0"
        }
    except Exception:
        return {
            "status": "degraded",
            "redis": "error",
            "version": "13.1.0"
        }
