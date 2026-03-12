"""Configuration management router for JA4Proxy Management UI."""

import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import redis.exceptions
from fastapi import APIRouter, Header, HTTPException, Request, status

from ..models import ThresholdConfig
from ..server import authenticate

router = APIRouter()


@router.get("/config/thresholds")
async def get_thresholds(
    request: Request,
    authorization: Optional[str] = Header(None),
) -> Dict[str, int]:
    """Get threshold configuration."""
    await authenticate(request, authorization)

    r = request.app.state.redis
    thresholds = await r.hgetall("config:thresholds")

    return {
        "flag": int(thresholds.get("flag", "20")),
        "rate_limit": int(thresholds.get("rate_limit", "35")),
        "tarpit": int(thresholds.get("tarpit", "55")),
        "block": int(thresholds.get("block", "70")),
        "ban": int(thresholds.get("ban", "85")),
    }


@router.put("/config/thresholds")
async def update_thresholds(
    request: Request,
    thresholds: ThresholdConfig,
    authorization: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """Update threshold configuration with validation."""
    await authenticate(request, authorization)

    if not (
        thresholds.flag
        <= thresholds.rate_limit
        <= thresholds.tarpit
        <= thresholds.block
        <= thresholds.ban
    ):
        raise HTTPException(
            status_code=422,
            detail="Thresholds must be in ascending order: flag <= rate_limit <= tarpit <= block <= ban",
        )

    r = request.app.state.redis
    await r.hset(
        "config:thresholds",
        mapping={
            "flag": str(thresholds.flag),
            "rate_limit": str(thresholds.rate_limit),
            "tarpit": str(thresholds.tarpit),
            "block": str(thresholds.block),
            "ban": str(thresholds.ban),
        },
    )

    entry = json.dumps(
        {
            "event": "thresholds_updated",
            "thresholds": thresholds.model_dump(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
    await r.lpush("management:audit_log", entry)
    await r.ltrim("management:audit_log", 0, 999)

    return {"status": "updated", **thresholds.model_dump()}


@router.put("/config/features/{feature}")
async def toggle_feature(
    request: Request,
    feature: str,
    payload: Dict[str, bool],
    authorization: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """Enable/disable a feature."""
    await authenticate(request, authorization)

    r = request.app.state.redis
    await r.set(f"config:features:{feature}", str(payload["enabled"]).lower())

    return {"status": "updated", "feature": feature, "enabled": payload["enabled"]}


@router.get("/config/countries/blocklist")
async def get_country_blocklist(
    request: Request,
    authorization: Optional[str] = Header(None),
) -> Dict[str, List[str]]:
    """Get blocked countries."""
    await authenticate(request, authorization)

    r = request.app.state.redis
    countries = await r.smembers("config:countries:blocklist")

    return {"countries": list(countries)}


@router.put("/config/countries/blocklist")
async def update_country_blocklist(
    request: Request,
    payload: Dict[str, List[str]],
    authorization: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """Update country blocklist."""
    await authenticate(request, authorization)

    r = request.app.state.redis
    if payload["countries"]:
        await r.sadd("config:countries:blocklist", *payload["countries"])
    else:
        await r.delete("config:countries:blocklist")

    entry = json.dumps(
        {
            "event": "country_blocklist_updated",
            "countries": payload["countries"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
    await r.lpush("management:audit_log", entry)
    await r.ltrim("management:audit_log", 0, 999)

    return {"status": "updated", "countries": payload["countries"]}
