"""Audit log router for JA4Proxy Management UI."""

from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Request, Header, Query
import json

from ..server import authenticate

router = APIRouter()


@router.get("/audit")
async def get_audit_log(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    event_type: Optional[str] = Query(None),
    authorization: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """Get paginated audit log."""
    await authenticate(request, authorization)
    
    redis = request.app.state.redis
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
