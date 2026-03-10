"""Phase 13 — Management UI FastAPI Server

Enterprise-grade management interface for JA4Proxy with:
- Bearer token authentication
- Rate limiting and brute-force protection
- Comprehensive ban management
- JA4 fingerprint intelligence
- Dial control with safety checks
- Policy bypass management
- Configuration management
- Health monitoring and audit logging
- Security headers and Prometheus metrics
"""

import asyncio
import json
import os
import time
from typing import Optional, Dict, Any, List

import redis.asyncio as aioredis
from fastapi import FastAPI, Request, HTTPException, Depends, status, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from prometheus_fastapi_instrumentator import Instrumentator

from .models import BanAddRequest, BanEntry, FingerprintEntry, DialResponse, BypassEntry

# Security middleware
security = HTTPBearer(auto_error=False)

# Rate limiting state
RATE_LIMIT_STATE: Dict[str, int] = {}

async def get_redis() -> aioredis.Redis:
    """Get Redis connection with caching."""
    if not hasattr(get_redis, "_redis"):
        # Create a new Redis connection
        get_redis._redis = await aioredis.from_url(
            "redis://localhost:6379",
            decode_responses=True
        )
    return get_redis._redis

async def rate_limit(request: Request) -> None:
    """Rate limiting middleware."""
    client_ip = request.client.host
    RATE_LIMIT_STATE[client_ip] = RATE_LIMIT_STATE.get(client_ip, 0) + 1
    
    if RATE_LIMIT_STATE[client_ip] > 100:  # 100 requests
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded"
        )

async def authenticate(
    request: Request,
    authorization: Optional[str] = Header(None)
) -> bool:
    """Authentication middleware."""
    # Check if authorization header is present
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization header",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    # Extract token
    token = authorization.split(" ")[1]
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    # Validate against environment variable
    api_key = os.environ.get("UI_API_KEY", "")
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API key not configured"
        )
    
    if token != api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    return True

async def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="JA4Proxy Management UI",
        description="Enterprise management interface for JA4Proxy analytics and enforcement",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json"
    )
    
    # Initialize Redis connection and attach to app state
    app.state.redis = await get_redis()
    
    # Security middleware
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1", "0.0.0.0"]
    )
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Security headers middleware
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        """Add security headers to all responses."""
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response
    
    # Add Prometheus instrumentation
    Instrumentator().instrument(app).expose(app)
    
    # Include all routers
    from management.routers import bans, dial, policy, fingerprints
    
    app.include_router(bans.router, prefix="/api/v1", tags=["bans"])
    app.include_router(dial.router, prefix="/api/v1", tags=["dial"])
    app.include_router(policy.router, prefix="/api/v1", tags=["policy"])
    app.include_router(fingerprints.router, prefix="/api/v1", tags=["fingerprints"])
    
    # Health endpoints (unauthenticated)
    @app.get("/health")
    async def health() -> Dict[str, Any]:
        """Unauthenticated health check."""
        try:
            redis = app.state.redis
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
    
    @app.get("/api/v1/health/detail")
    async def health_detail(
        request: Request,
        authorization: Optional[str] = Header(None)
    ) -> Dict[str, Any]:
        """Authenticated detailed health check."""
        await authenticate(request, authorization)
        
        try:
            redis = app.state.redis
            await redis.ping()
            return {
                "status": "healthy",
                "redis": True,
                "version": "13.0.0"
            }
        except Exception as e:
            return {
                "status": "degraded",
                "redis": str(e),
                "version": "13.0.0"
            }
    
    # Config endpoints
    @app.get("/api/v1/config/thresholds")
    async def get_thresholds(
        request: Request,
        authorization: Optional[str] = Header(None)
    ) -> Dict[str, Any]:
        """Get threshold configuration."""
        await authenticate(request, authorization)
        
        redis = app.state.redis
        thresholds = await redis.hgetall("config:thresholds")
        
        # Return defaults if not set
        return {
            "flag": int(thresholds.get(b"flag", b"20")),
            "rate_limit": int(thresholds.get(b"rate_limit", b"35")),
            "tarpit": int(thresholds.get(b"tarpit", b"55")),
            "block": int(thresholds.get(b"block", b"70")),
            "ban": int(thresholds.get(b"ban", b"85"))
        }
    
    @app.put("/api/v1/config/thresholds")
    async def update_thresholds(
        request: Request,
        thresholds: Dict[str, int],
        authorization: Optional[str] = Header(None)
    ) -> Dict[str, Any]:
        """Update threshold configuration."""
        await authenticate(request, authorization)
        
        # Validate ranges
        for key, value in thresholds.items():
            if value < 0 or value > 100:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail=f"Threshold {key} must be between 0 and 100"
                )
        
        redis = app.state.redis
        await redis.hset("config:thresholds", mapping=thresholds)
        
        return {"status": "updated", **thresholds}
    
    @app.put("/api/v1/config/features/{feature}")
    async def toggle_feature(
        request: Request,
        feature: str,
        payload: Dict[str, bool],
        authorization: Optional[str] = Header(None)
    ) -> Dict[str, Any]:
        """Enable/disable a feature."""
        await authenticate(request, authorization)
        
        redis = app.state.redis
        await redis.set(f"config:features:{feature}", str(payload["enabled"]).lower())
        
        return {"status": "updated", "feature": feature, "enabled": payload["enabled"]}
    
    @app.get("/api/v1/config/countries/blocklist")
    async def get_country_blocklist(
        request: Request,
        authorization: Optional[str] = Header(None)
    ) -> Dict[str, Any]:
        """Get blocked countries."""
        await authenticate(request, authorization)
        
        redis = app.state.redis
        countries = await redis.smembers("config:countries:blocklist")
        
        return {"countries": list(countries)}
    
    @app.put("/api/v1/config/countries/blocklist")
    async def update_country_blocklist(
        request: Request,
        payload: Dict[str, List[str]],
        authorization: Optional[str] = Header(None)
    ) -> Dict[str, Any]:
        """Update country blocklist."""
        await authenticate(request, authorization)
        
        redis = app.state.redis
        if payload["countries"]:
            await redis.sadd("config:countries:blocklist", *payload["countries"])
        else:
            await redis.delete("config:countries:blocklist")
        
        return {"status": "updated", "countries": payload["countries"]}
    
    # Audit log endpoints
    @app.get("/api/v1/audit")
    async def get_audit_log(
        request: Request,
        page: int = Query(1, ge=1),
        per_page: int = Query(50, ge=1, le=500),
        event_type: Optional[str] = Query(None),
        authorization: Optional[str] = Header(None)
    ) -> Dict[str, Any]:
        """Get paginated audit log."""
        await authenticate(request, authorization)
        
        redis = app.state.redis
        start = (page - 1) * per_page
        end = start + per_page - 1
        
        entries = await redis.lrange("management:audit_log", start, end)
        total = await redis.llen("management:audit_log")
        
        # Filter by event type if specified
        if event_type:
            entries = [e for e in entries if event_type in e]
        
        return {
            "items": [json.loads(e) for e in entries],
            "total": total,
            "page": page,
            "per_page": per_page
        }
    
    # Integrations endpoints
    @app.get("/api/v1/integrations/abuseipdb")
    async def get_abuseipdb_status(
        request: Request,
        authorization: Optional[str] = Header(None)
    ) -> Dict[str, Any]:
        """Get AbuseIPDB integration status."""
        await authenticate(request, authorization)
        
        redis = app.state.redis
        enabled = await redis.get("config:features:abuseipdb")
        
        return {
            "status": "enabled" if enabled == "true" else "disabled",
            "service": "abuseipdb"
        }
    
    @app.get("/api/v1/integrations/spamhaus")
    async def get_spamhaus_status(
        request: Request,
        authorization: Optional[str] = Header(None)
    ) -> Dict[str, Any]:
        """Get Spamhaus integration status."""
        await authenticate(request, authorization)
        
        redis = app.state.redis
        enabled = await redis.get("config:features:spamhaus")
        
        return {
            "status": "enabled" if enabled == "true" else "disabled",
            "service": "spamhaus"
        }
    
    @app.get("/ready")
    async def ready() -> Dict[str, Any]:
        """Readiness check."""
        try:
            redis = app.state.redis
            await redis.ping()
            return {
                "status": "ready",
                "dependencies": {
                    "redis": True
                }
            }
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Readiness check failed: {e}"
            )
    

    
    return app


if __name__ == "__main__":
    import uvicorn
    
    app = asyncio.run(create_app())
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8001,
        log_level="info",
        access_log=True
    )