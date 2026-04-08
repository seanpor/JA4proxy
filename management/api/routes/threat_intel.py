"""Phase 85 — Threat intelligence feed management API.

Routes
------
GET    /api/v1/threat-intel/feeds                     — list all feeds (Auditor)
GET    /api/v1/threat-intel/feeds/{feed_id}           — single-feed status (Auditor)
POST   /api/v1/threat-intel/feeds/{feed_id}/enable    — runtime enable (Operator)
POST   /api/v1/threat-intel/feeds/{feed_id}/disable   — runtime disable (Operator)
POST   /api/v1/threat-intel/feeds/{feed_id}/poll      — trigger immediate poll (Operator)

The routes talk to the runner indirectly: the enable/disable endpoints flip
the ``ti_feed:{feed_id}:runtime_enabled`` Redis key (read by the runner on
every poll cycle), and the status endpoints read ``ti_feed:{feed_id}:poll_state``.

Audit attribution:

* ``ti_feed.enabled``  — operator token holder
* ``ti_feed.disabled`` — operator token holder
* ``ti_feed.manual_poll`` — operator token holder (poll itself is attributed
  to ``ti_feed:{feed_id}`` on any rules it creates, via
  ``src/analytics/ti_feeds/runner.py``)
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..audit_utils import write_audit
from ..auth import require_role
from ..models import (
    Role,
    TIFeedListResponse,
    TIFeedPollResponse,
    TIFeedStatus,
    TIFeedToggleResponse,
)
from ..proxy_config import get_proxy_config
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["threat-intel"])


_POLL_STATE_KEY = "ti_feed:{feed_id}:poll_state"
_RUNTIME_ENABLED_KEY = "ti_feed:{feed_id}:runtime_enabled"
_ACTIVE_STIX_KEY = "ti_feed:{feed_id}:active_stix_ids"
_TRIGGER_STREAM = "ti_feed:manual_poll_triggers"


def _client_ip(request: Request) -> str:
    """Extract the real client IP, honouring X-Forwarded-For."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


async def _load_feed_configs() -> list[dict[str, Any]]:
    """Return the ``threat_intel.feeds`` list from the active proxy config.

    Returns an empty list if threat-intel is not configured or the
    proxy_config helper returns None (first-run before initial load).
    """
    try:
        cfg = get_proxy_config()
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "threat_intel | event=config_load_failed | error=%s", exc
        )
        return []
    if not isinstance(cfg, dict):
        return []
    ti_cfg = cfg.get("threat_intel") or {}
    feeds = ti_cfg.get("feeds") or []
    if not isinstance(feeds, list):
        return []
    return [f for f in feeds if isinstance(f, dict) and "id" in f]


def _parse_iso(timestamp: Optional[str]) -> Optional[datetime]:
    if not timestamp:
        return None
    try:
        return datetime.fromisoformat(timestamp)
    except ValueError:
        return None


def _decode(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.decode()
    return value


async def _load_feed_status(
    redis: Any,
    feed_cfg: dict[str, Any],
) -> TIFeedStatus:
    """Read the ``poll_state`` and ``runtime_enabled`` keys for one feed."""
    feed_id = str(feed_cfg.get("id", ""))
    feed_type = str(feed_cfg.get("type", "unknown"))

    # runtime override
    runtime_override: Optional[bool] = None
    try:
        raw = await redis.get(_RUNTIME_ENABLED_KEY.format(feed_id=feed_id))
        decoded = _decode(raw)
        if decoded is not None:
            runtime_override = decoded == "1"
    except Exception:  # noqa: BLE001
        pass

    # poll_state HASH
    poll_state_raw: dict[Any, Any] = {}
    try:
        poll_state_raw = (
            await redis.hgetall(_POLL_STATE_KEY.format(feed_id=feed_id))
        ) or {}
    except Exception:  # noqa: BLE001
        pass
    poll_state = {
        _decode(k): _decode(v) for k, v in poll_state_raw.items()
    }

    # indicators managed (HLEN on the active HASH)
    indicators_managed = 0
    try:
        indicators_managed = int(
            await redis.hlen(_ACTIVE_STIX_KEY.format(feed_id=feed_id))
        )
    except Exception:  # noqa: BLE001
        pass

    last_poll_at = poll_state.get("last_success_ts")
    circuit_state = poll_state.get("circuit_state", "closed")
    # phase-85 (security review C2): the runner stores upstream error
    # bodies in ``last_error`` for operator triage. Those bodies can echo
    # back the bearer/api token from a 401/403 response. Strip the value
    # at the API boundary so Auditor-tier callers see only a category.
    raw_last_error = poll_state.get("last_error") or None
    last_error: Optional[str] = None
    if raw_last_error:
        if "HTTP 4" in raw_last_error or "HTTP 5" in raw_last_error:
            last_error = raw_last_error.split(":", 1)[0]
        elif raw_last_error.startswith("network:"):
            last_error = "network"
        else:
            last_error = "error"
    failure_count = int(poll_state.get("failure_count", "0") or 0)

    # Derived next_poll_at from poll_interval_minutes
    next_poll_at: Optional[str] = None
    interval_minutes = int(feed_cfg.get("poll_interval_minutes", 60) or 60)
    last_dt = _parse_iso(last_poll_at)
    if last_dt is not None:
        try:
            from datetime import timedelta

            next_poll_at = (
                last_dt + timedelta(minutes=interval_minutes)
            ).isoformat()
        except Exception:  # noqa: BLE001
            pass

    # status projection: green / yellow / red
    if circuit_state == "open":
        status_str = "unhealthy"
    elif failure_count > 0:
        status_str = "degraded"
    elif last_poll_at is None:
        status_str = "pending"
    else:
        status_str = "healthy"

    configured_enabled = bool(feed_cfg.get("enabled", False))
    effective_enabled = (
        runtime_override if runtime_override is not None else configured_enabled
    )

    return TIFeedStatus(
        id=feed_id,
        type=feed_type,
        enabled=effective_enabled,
        runtime_override=runtime_override,
        status=status_str,
        circuit_state=circuit_state,
        last_poll_at=last_poll_at,
        next_poll_at=next_poll_at,
        indicators_managed=indicators_managed,
        last_24h_additions=int(poll_state.get("last_created", "0") or 0),
        last_24h_removals=int(poll_state.get("last_removed", "0") or 0),
        last_error=last_error,
        error_count_24h=failure_count,
    )


# ── Routes ────────────────────────────────────────────────────────────────────


@router.get(
    "/api/v1/threat-intel/feeds",
    response_model=TIFeedListResponse,
    summary="List all threat-intel feeds",
)
async def list_feeds(
    current_user=Depends(require_role(Role.auditor)),
    redis=Depends(get_redis),
) -> TIFeedListResponse:
    """Return every configured feed with its current status."""
    feed_configs = await _load_feed_configs()
    feeds: list[TIFeedStatus] = []
    for cfg in feed_configs:
        feeds.append(await _load_feed_status(redis, cfg))
    return TIFeedListResponse(feeds=feeds, count=len(feeds))


@router.get(
    "/api/v1/threat-intel/feeds/{feed_id}",
    response_model=TIFeedStatus,
    summary="Get a single threat-intel feed by id",
)
async def get_feed(
    feed_id: str,
    current_user=Depends(require_role(Role.auditor)),
    redis=Depends(get_redis),
) -> TIFeedStatus:
    """Return the status of a single feed."""
    feed_configs = await _load_feed_configs()
    for cfg in feed_configs:
        if str(cfg.get("id")) == feed_id:
            return await _load_feed_status(redis, cfg)
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Feed '{feed_id}' not found",
    )


@router.post(
    "/api/v1/threat-intel/feeds/{feed_id}/enable",
    response_model=TIFeedToggleResponse,
    summary="Enable a threat-intel feed at runtime",
)
async def enable_feed(
    feed_id: str,
    request: Request,
    current_user=Depends(require_role(Role.operator)),
    redis=Depends(get_redis),
) -> TIFeedToggleResponse:
    """Flip the runtime toggle to enabled. Runner picks it up on next cycle."""
    identity, role = current_user
    feed_configs = await _load_feed_configs()
    if not any(str(cfg.get("id")) == feed_id for cfg in feed_configs):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Feed '{feed_id}' not found",
        )

    await redis.set(_RUNTIME_ENABLED_KEY.format(feed_id=feed_id), "1")
    logger.info(
        "threat_intel | event=feed_enabled | feed=%s | user=%s",
        feed_id,
        identity,
    )
    await write_audit(
        redis,
        actor_id=identity,
        actor_ip=_client_ip(request),
        action_type="ti_feed.enabled",
        resource_type="ti_feed",
        resource_id=feed_id,
        before_value=None,
        after_value={"runtime_enabled": True},
        role=role.value,
    )
    return TIFeedToggleResponse(
        feed_id=feed_id,
        enabled=True,
        message=f"Feed '{feed_id}' enabled at runtime",
    )


@router.post(
    "/api/v1/threat-intel/feeds/{feed_id}/disable",
    response_model=TIFeedToggleResponse,
    summary="Disable a threat-intel feed at runtime",
)
async def disable_feed(
    feed_id: str,
    request: Request,
    current_user=Depends(require_role(Role.operator)),
    redis=Depends(get_redis),
) -> TIFeedToggleResponse:
    """Flip the runtime toggle to disabled. Runner stops polling at next cycle."""
    identity, role = current_user
    feed_configs = await _load_feed_configs()
    if not any(str(cfg.get("id")) == feed_id for cfg in feed_configs):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Feed '{feed_id}' not found",
        )

    await redis.set(_RUNTIME_ENABLED_KEY.format(feed_id=feed_id), "0")
    logger.info(
        "threat_intel | event=feed_disabled | feed=%s | user=%s",
        feed_id,
        identity,
    )
    await write_audit(
        redis,
        actor_id=identity,
        actor_ip=_client_ip(request),
        action_type="ti_feed.disabled",
        resource_type="ti_feed",
        resource_id=feed_id,
        before_value=None,
        after_value={"runtime_enabled": False},
        role=role.value,
    )
    return TIFeedToggleResponse(
        feed_id=feed_id,
        enabled=False,
        message=f"Feed '{feed_id}' disabled at runtime",
    )


@router.post(
    "/api/v1/threat-intel/feeds/{feed_id}/poll",
    response_model=TIFeedPollResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger an immediate poll of a threat-intel feed",
)
async def trigger_poll(
    feed_id: str,
    request: Request,
    current_user=Depends(require_role(Role.operator)),
    redis=Depends(get_redis),
) -> TIFeedPollResponse:
    """Ask the runner to poll a feed right now.

    The feed runner does not live in the same process as the management API
    (the runner is part of the analytics container). We signal it via a
    Redis stream entry it reads in its poll loop — the runner
    (``runner.FeedRunner.trigger_poll``) converts that into an immediate
    poll on the next scheduling tick, typically within a second.

    Returns:
        202 Accepted with a ``poll_id`` the caller can correlate against
        the feed's next ``poll_complete`` ECS log line.
    """
    identity, role = current_user
    feed_configs = await _load_feed_configs()
    if not any(str(cfg.get("id")) == feed_id for cfg in feed_configs):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Feed '{feed_id}' not found",
        )

    poll_id = uuid.uuid4().hex

    try:
        await redis.xadd(
            _TRIGGER_STREAM,
            {
                "feed_id": feed_id,
                "poll_id": poll_id,
                "requested_by": identity,
                "requested_at": datetime.now(timezone.utc).isoformat(),
            },
            maxlen=1000,
            approximate=True,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "threat_intel | event=trigger_xadd_failed | feed=%s | error=%s",
            feed_id,
            exc,
        )

    logger.info(
        "threat_intel | event=feed_manual_poll | feed=%s | poll_id=%s | user=%s",
        feed_id,
        poll_id,
        identity,
    )
    await write_audit(
        redis,
        actor_id=identity,
        actor_ip=_client_ip(request),
        action_type="ti_feed.manual_poll",
        resource_type="ti_feed",
        resource_id=feed_id,
        before_value=None,
        after_value={"poll_id": poll_id},
        role=role.value,
    )

    return TIFeedPollResponse(
        poll_id=poll_id,
        feed_id=feed_id,
        message=f"Poll triggered for feed '{feed_id}'",
    )
