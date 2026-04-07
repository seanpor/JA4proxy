"""Shared audit log writer for all management API routes.

All write operations that mutate state must call ``write_audit`` so that
the management audit log contains a consistent, queryable record of every
change with full actor attribution.

Schema (new — Phase 79 Cluster 5)
----------------------------------
{
    "timestamp":     "<ISO 8601>",
    "actor_id":      "token:<name>  or  <username>",
    "actor_ip":      "<client IP>",
    "action_type":   "<resource>.<verb>",   e.g. "allowlist.created"
    "resource_type": "<resource>",           e.g. "allowlist"
    "resource_id":   "<uuid> | <ip> | null",
    "before_value":  {…} | null,
    "after_value":   {…} | null,
    "session_id":    "<opaque> | null",
    "role":          "auditor|analyst|operator|admin",
}
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

_AUDIT_KEY = "management:audit_log"
_MAX_ENTRIES = 1000


async def write_audit(
    redis,
    *,
    actor_id: str,
    actor_ip: str,
    action_type: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    before_value: Optional[Any] = None,
    after_value: Optional[Any] = None,
    session_id: Optional[str] = None,
    role: str,
) -> None:
    """Append an enhanced audit entry to management:audit_log.

    Never raises — write failures are logged and swallowed so that the
    primary operation is not affected by audit log unavailability.

    Args:
        redis: The async Redis client.
        actor_id: Identity string of the actor (e.g. "token:my-token" or "admin").
        actor_ip: IP address of the actor's HTTP client.
        action_type: Dot-separated action identifier (e.g. "allowlist.created").
        resource_type: The type of resource mutated (e.g. "allowlist", "ban", "dial").
        resource_id: Optional UUID or identifier of the specific resource.
        before_value: State of the resource before the change (None for creates).
        after_value: State of the resource after the change (None for deletes).
        session_id: Optional opaque session identifier.
        role: String role of the actor ("auditor", "analyst", "operator", "admin").
    """
    entry = json.dumps(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor_id": actor_id,
            "actor_ip": actor_ip,
            "action_type": action_type,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "before_value": before_value,
            "after_value": after_value,
            "session_id": session_id,
            "role": role,
        }
    )
    try:
        await redis.lpush(_AUDIT_KEY, entry)
        await redis.ltrim(_AUDIT_KEY, 0, _MAX_ENTRIES - 1)
    except Exception:
        logger.exception(
            "audit | event=write_failed | action_type=%s | actor=%s",
            action_type,
            actor_id,
        )
