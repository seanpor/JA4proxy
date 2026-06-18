"""Background task: poll config:dial_override and auto-revert the dial when due.

config:dial_override is a persistent (no-TTL) JSON record:
    {"original_value": int, "override_value": int, "expires_at_epoch": int}

Every ~10s we check it; once now >= expires_at_epoch we restore config:dial to
original_value, write an audit entry under a system actor, and delete the record.
Polling (not keyspace-expiry notifications) so a restart at the wrong moment can
never strand the dial at an elevated setting.
"""
import asyncio
import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_OVERRIDE_KEY = "config:dial_override"
_DIAL_KEY = "config:dial"
_POLL_SECONDS = 10


async def run_dial_revert_poller(redis_factory) -> None:
    """Long-running coroutine. Call asyncio.create_task(run_dial_revert_poller(...))."""
    logger.info("dial_revert | event=poller_started | interval_s=%s", _POLL_SECONDS)
    while True:
        try:
            async with redis_factory() as redis:
                raw = await redis.get(_OVERRIDE_KEY)
                if raw:
                    rec = json.loads(raw)
                    now = int(datetime.now(timezone.utc).timestamp())
                    if now >= int(rec["expires_at_epoch"]):
                        original = int(rec["original_value"])
                        await redis.set(_DIAL_KEY, str(original))
                        await redis.rpush("management:audit_log", json.dumps({
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "user": "system:dial_revert",
                            "action": "dial_change",
                            "detail": {"to": original, "reason": "auto_revert"},
                        }))
                        await redis.delete(_OVERRIDE_KEY)
                        logger.info("dial_revert | event=reverted | value=%s", original)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("dial_revert | event=poll_error")
        await asyncio.sleep(_POLL_SECONDS)
