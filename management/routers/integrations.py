"""Integrations status router for JA4Proxy Management UI."""

from typing import Dict, Any, Optional
from fastapi import APIRouter, Request, Header
import time

from ..server import authenticate

router = APIRouter()


@router.get("/integrations/abuseipdb")
async def get_abuseipdb_status(
    request: Request,
    authorization: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """Get AbuseIPDB integration status."""
    await authenticate(request, authorization)
    
    redis = request.app.state.redis
    enabled = await redis.get("config:features:abuseipdb")
    
    return {
        "status": "enabled" if enabled == "true" else "disabled",
        "service": "abuseipdb"
    }


@router.get("/integrations/spamhaus")
async def get_spamhaus_status(
    request: Request,
    authorization: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """Get Spamhaus integration status."""
    await authenticate(request, authorization)
    
    redis = request.app.state.redis
    enabled = await redis.get("config:features:spamhaus")
    
    return {
        "status": "enabled" if enabled == "true" else "disabled",
        "service": "spamhaus"
    }


@router.get("/integrations/rdap")
async def get_rdap_status(
    request: Request,
    authorization: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """Get RDAP integration status."""
    await authenticate(request, authorization)
    
    redis = request.app.state.redis
    block_expansion = await redis.get("config:features:rdap_block_expansion")
    
    return {
        "status": "enabled" if block_expansion == "true" else "disabled",
        "service": "rdap",
        "block_expansion": block_expansion == "true"
    }


@router.get("/integrations/analytics")
async def get_analytics_status(
    request: Request,
    authorization: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """Get analytics integration status."""
    await authenticate(request, authorization)
    
    redis = request.app.state.redis
    enabled = await redis.get("config:features:analytics")
    
    # Get last event age
    last_event_age = None
    try:
        events = await redis.xrevrange("ja4proxy:events", count=1)
        if events:
            last_event_time = float(events[0][1][0][b"timestamp"].decode())
            last_event_age = int(time.time() - last_event_time)
    except Exception:
        pass
    
    return {
        "status": "enabled" if enabled == "true" else "disabled",
        "service": "analytics",
        "last_event_age_s": last_event_age
    }
