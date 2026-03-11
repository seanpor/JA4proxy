"""Security policy bypass management router.

Endpoints:
  GET /api/v1/policy/bypasses
  PUT /api/v1/policy/bypasses/{bypass_name}
  GET /api/v1/policy/audit

Redis keys:
  policy:bypass:{name}   — string "true"/"false"
  management:policy_audit — LIST of changes (LPUSH+LTRIM 1000)
"""

import logging
import time

import redis.exceptions
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from management.auth import require_api_key
from management.metrics import mgmt_redis_errors_total, policy_changes_total
from management.models import VALID_BYPASS_NAMES, BypassEntry, BypassUpdateRequest, PaginatedResponse
from management.redis_helpers import publish_invalidation, write_audit_log, get_audit_log

logger = logging.getLogger("management.routers.policy")
router = APIRouter()

# Human-readable descriptions for each bypass
_BYPASS_DESCRIPTIONS = {
    "alpn_browser_bypass": "h2/h1 ALPN traffic bypasses scoring (browser traffic). Disable to score browser connections.",
    "ja4_whitelist_bypass": "JA4 fingerprints in the whitelist bypass scoring. Disable to score whitelisted fingerprints.",
    "mtls_bypass": "Valid mTLS client certificates bypass scoring. Disable to score mTLS clients.",
    "static_ip_allowlist": "IPs in the static allowlist bypass scoring.",
    "ja4_blacklist_bypass": "JA4 fingerprints in the blacklist are immediately blocked (RST). Disable to score them instead.",
    "country_blacklist_bypass": "Connections from blocked countries are immediately blocked. Disable to score them instead.",
    "spamhaus_bypass": "Spamhaus DROP/EDROP matches are immediately blocked. Disable to route through scorer with +80 signal.",
    "tls_version_bypass": "TLS 1.0/1.1 connections are immediately blocked. Disable to score old TLS instead.",
}


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.get("/policy/bypasses")
async def list_bypasses(
    request: Request,
    _key: str = Depends(require_api_key),
) -> list[dict]:
    """Return the current state of all 8 security policy bypasses."""
    r = request.app.state.redis
    result = []

    try:
        for name in sorted(VALID_BYPASS_NAMES):
            raw = await r.get(f"policy:bypass:{name}")
            # Default: all bypasses are enabled unless explicitly set to "false"
            enabled = raw != "false" if raw is not None else True
            result.append({
                "name": name,
                "enabled": enabled,
                "description": _BYPASS_DESCRIPTIONS.get(name, ""),
            })
    except redis.exceptions.RedisError as exc:
        mgmt_redis_errors_total.labels(operation="list_bypasses").inc()
        logger.error("management | event=redis_error | op=list_bypasses | error=%s", exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")
    except Exception as exc:
        mgmt_redis_errors_total.labels(operation="list_bypasses").inc()
        raise HTTPException(status_code=503, detail="Service unavailable")

    return result


@router.put("/policy/bypasses/{bypass_name}")
async def update_bypass(
    bypass_name: str,
    request: Request,
    payload: BypassUpdateRequest,
    _key: str = Depends(require_api_key),
) -> dict:
    """Enable or disable a security policy bypass.

    Writes to policy:bypass:{name} and publishes config_reload.
    WARN logged when disabling an ALLOW bypass (increases false positive risk).
    """
    if bypass_name not in VALID_BYPASS_NAMES:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown bypass: {bypass_name!r}. Valid names: {sorted(VALID_BYPASS_NAMES)}",
        )

    r = request.app.state.redis
    actor_ip = _get_client_ip(request)

    try:
        # Read current state
        raw = await r.get(f"policy:bypass:{bypass_name}")
        old_enabled = raw != "false" if raw is not None else True

        # Write new state
        await r.set(f"policy:bypass:{bypass_name}", "true" if payload.enabled else "false")

        # Emit WARN if disabling an ALLOW bypass
        if not payload.enabled and bypass_name in (
            "alpn_browser_bypass", "ja4_whitelist_bypass", "mtls_bypass", "static_ip_allowlist"
        ):
            logger.warning(
                "WARN | policy | event=bypass_disabled | bypass=%s | "
                "effect=browser traffic will be scored; false positive risk elevated",
                bypass_name,
            )

        # Publish config_reload so all proxy instances pick up the change
        await publish_invalidation(r,{"event": "config_reload"})

        # Write to policy audit log
        import json
        audit_entry = {
            "event": "bypass_changed",
            "bypass": bypass_name,
            "old_value": old_enabled,
            "new_value": payload.enabled,
            "changed_by": actor_ip,
            "timestamp": str(time.time()),
        }
        await r.lpush("management:policy_audit", json.dumps(audit_entry))
        await r.ltrim("management:policy_audit", 0, 999)

        # Also write to general audit log
        await write_audit_log(
            r,
            event_type="bypass_changed",
            actor_ip=actor_ip,
            detail={
                "bypass": bypass_name,
                "old_value": old_enabled,
                "new_value": payload.enabled,
            },
        )
    except redis.exceptions.RedisError as exc:
        mgmt_redis_errors_total.labels(operation="update_bypass").inc()
        logger.error(
            "management | event=redis_error | op=update_bypass | bypass=%s | error=%s",
            bypass_name,
            exc,
        )
        raise HTTPException(status_code=503, detail="Redis unavailable")
    except Exception as exc:
        mgmt_redis_errors_total.labels(operation="update_bypass").inc()
        raise HTTPException(status_code=503, detail="Service unavailable")

    policy_changes_total.labels(bypass=bypass_name).inc()
    logger.info(
        "management | event=bypass_changed | actor_ip=%s | bypass=%s | enabled=%s",
        actor_ip,
        bypass_name,
        payload.enabled,
    )
    return {
        "name": bypass_name,
        "enabled": payload.enabled,
        "description": _BYPASS_DESCRIPTIONS.get(bypass_name, ""),
    }


@router.get("/policy/audit", response_model=PaginatedResponse)
async def get_policy_audit(
    request: Request,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    _key: str = Depends(require_api_key),
) -> PaginatedResponse:
    """Return paginated policy audit log entries."""
    r = request.app.state.redis
    try:
        items, total = await get_audit_log(
            r, page=page, per_page=per_page, key="management:policy_audit"
        )
    except redis.exceptions.RedisError as exc:
        mgmt_redis_errors_total.labels(operation="get_policy_audit").inc()
        raise HTTPException(status_code=503, detail="Redis unavailable")
    except Exception as exc:
        mgmt_redis_errors_total.labels(operation="get_policy_audit").inc()
        raise HTTPException(status_code=503, detail="Service unavailable")

    return PaginatedResponse(items=items, total=total, page=page, per_page=per_page)
