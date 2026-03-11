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
import logging
import os
import sys
import time
import ipaddress
from typing import Optional, Dict, Any, List

import redis.asyncio as aioredis
import redis.exceptions as redis_exc
from fastapi import FastAPI, Request, HTTPException, Depends, status, Header, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from prometheus_fastapi_instrumentator import Instrumentator

from .models import BanAddRequest, BanEntry, FingerprintEntry, DialResponse, BypassEntry

# Configure logger
logger = logging.getLogger("management")

# Security middleware
security = HTTPBearer(auto_error=False)

# Rate limiting state
RATE_LIMIT_STATE: Dict[str, int] = {}

# Configuration state
app_config: Dict[str, Any] = {}

def _get_client_ip(request: Request) -> str:
    """Extract client IP from request."""
    # Try X-Forwarded-For first (for proxy setups)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Take the first IP in the list (original client)
        return forwarded.split(",")[0].strip()
    return request.client.host

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
    # Startup guard: check UI_API_KEY before creating app
    api_key = os.environ.get("UI_API_KEY", "")
    if not api_key:
        logger.critical(
            "management | event=startup_abort | reason=UI_API_KEY_not_set"
        )
        sys.exit(1)
    
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
    
    # Load configuration
    app.state.config = {
        "management_ui": {
            "allowed_cidr": os.environ.get("MANAGEMENT_ALLOWED_CIDR", ""),
            "max_sse_subscribers": int(os.environ.get("MAX_SSE_SUBSCRIBERS", "50")),
            "max_dial_changes_per_hour": int(os.environ.get("MAX_DIAL_CHANGES_PER_HOUR", "10")),
            "max_auth_failures_per_minute": int(os.environ.get("MAX_AUTH_FAILURES_PER_MINUTE", "10"))
        }
    }
    
    # allowed_cidr middleware
    @app.middleware("http")
    async def enforce_allowed_cidr(request: Request, call_next):
        """Block requests from outside the configured management CIDR."""
        # Health and ready endpoints are exempt
        if request.url.path in ["/health", "/ready"]:
            return await call_next(request)
        
        allowed_cidr = app.state.config["management_ui"].get("allowed_cidr", "")
        if allowed_cidr:
            client_ip = _get_client_ip(request)
            try:
                network = ipaddress.ip_network(allowed_cidr, strict=False)
                addr = ipaddress.ip_address(client_ip)
                if addr not in network:
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Access denied: IP not in allowed CIDR"}
                    )
            except ValueError:
                # Malformed config — fail open, log at startup
                pass
        return await call_next(request)
    
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
    
    # Global handler: any unhandled RedisError returns 503 instead of 500
    @app.exception_handler(redis_exc.RedisError)
    async def _redis_error_handler(request: Request, exc: redis_exc.RedisError):
        return JSONResponse(status_code=503, content={"detail": "Redis unavailable"})

    # Add Prometheus instrumentation
    Instrumentator().instrument(app).expose(app)
    
    # Include all routers
    from management.routers import bans, dial, policy, fingerprints, config, health, audit, integrations, events
    
    app.include_router(bans.router, prefix="/api/v1", tags=["bans"])
    app.include_router(dial.router, prefix="/api/v1", tags=["dial"])
    app.include_router(policy.router, prefix="/api/v1", tags=["policy"])
    app.include_router(fingerprints.router, prefix="/api/v1", tags=["fingerprints"])
    app.include_router(config.router, prefix="/api/v1", tags=["config"])
    app.include_router(integrations.router, prefix="/api/v1", tags=["integrations"])
    app.include_router(audit.router, prefix="/api/v1", tags=["audit"])
    app.include_router(events.router, prefix="/api/v1", tags=["events"])
    app.include_router(health.router, tags=["health"])
    

    

    
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