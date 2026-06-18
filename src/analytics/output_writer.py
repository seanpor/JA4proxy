"""Analytics output writer — Redis interface for analytics findings.

This module is the authoritative Redis output contract for the analytics engine.
All analytics data written to Redis flows through this module.

Redis key schema
----------------
analytics:finding:{uuid}          Hash — one finding per key
analytics:findings:index          Sorted set — created_at epoch -> uuid
analytics:heartbeat               String — ISO8601 timestamp, TTL = 2 * poll interval
analytics:active_connections      String — integer count, written by tarpit or analytics

Finding hash field definitions
-------------------------------
Field               Type    Constraints
confidence          float   0.0 <= x <= 1.0
tier                str     HIGH | MEDIUM | LOW
type                str     beaconing | campaign | drift | slowscan
subject_ip          str     optional; valid IPv4/IPv6 or empty string
subject_ja4         str     optional; max 64 chars or empty string
description         str     max 500 chars; PLAIN TEXT — no HTML
evidence_count      int     >= 0
model_version       str     max 32 chars (e.g. "1.2.3")
model_trained_at    str     ISO8601 datetime
fp_rate_estimate    float   0.0 <= x <= 1.0 (model's own FP rate estimate)
suggested_action    str     monitor | watchlist | investigate | block
created_at          str     ISO8601 datetime (set by this module)
dismissed           str     "0" | "1"

TTLs
----
HIGH findings:   86400 seconds (24 hours)
MEDIUM findings: 43200 seconds (12 hours)
LOW findings:    14400 seconds (4 hours)
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

# Schema constant — single source of truth for field definitions.
# The management console validates against this same schema (see partials.py).
# NOTE: Both copies must stay identical. A parity test at
# tests/unit/test_schema_parity.py verifies this.

FINDING_SCHEMA: dict[str, dict] = {
    "confidence":       {"type": float,  "required": True,  "min": 0.0,  "max": 1.0},
    "tier":             {"type": str,    "required": True,  "enum": {"HIGH", "MEDIUM", "LOW"}},
    "type":             {"type": str,    "required": True,  "enum": {"beaconing", "campaign", "drift", "slowscan"}},
    "subject_ip":       {"type": str,    "required": False, "max_len": 45},
    "subject_ja4":      {"type": str,    "required": False, "max_len": 64},
    "description":      {"type": str,    "required": True,  "max_len": 500},
    "evidence_count":   {"type": int,    "required": True,  "min": 0},
    "model_version":    {"type": str,    "required": True,  "max_len": 32},
    "model_trained_at": {"type": str,    "required": True,  "max_len": 32},
    "fp_rate_estimate": {"type": float,  "required": True,  "min": 0.0,  "max": 1.0},
    "suggested_action": {"type": str,    "required": True,  "enum": {"monitor", "watchlist", "investigate", "block"}},
    "created_at":       {"type": str,    "required": True,  "max_len": 32},
    "dismissed":        {"type": str,    "required": True,  "enum": {"0", "1"}},
}

_TIER_TTL = {
    "HIGH":   86400,
    "MEDIUM": 43200,
    "LOW":    14400,
}

_ANALYTICS_KEY_PREFIX = "analytics:"
_FINDING_PREFIX = "analytics:finding:"
_FINDINGS_INDEX = "analytics:findings:index"
_HEARTBEAT_KEY = "analytics:heartbeat"
_ACTIVE_CONNECTIONS_KEY = "analytics:active_connections"


def _tier_from_confidence(confidence: float) -> str:
    """Convert a float confidence to a tier label."""
    if confidence >= 0.90:
        return "HIGH"
    if confidence >= 0.70:
        return "MEDIUM"
    return "LOW"


async def write_finding(
    redis: aioredis.Redis,
    *,
    confidence: float,
    type: str,
    description: str,
    evidence_count: int,
    model_version: str,
    model_trained_at: str,
    fp_rate_estimate: float,
    suggested_action: str,
    subject_ip: str = "",
    subject_ja4: str = "",
) -> Optional[str]:
    """Write a new analytics finding to Redis.

    Returns the finding UUID if successful, None if the write failed.
    All writes go to analytics:* namespace — the ACL restricts this container
    to that namespace only (see config/redis_acl.conf, Phase 236).
    """
    tier = _tier_from_confidence(confidence)
    finding_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()
    now_epoch = datetime.now(timezone.utc).timestamp()

    mapping = {
        "confidence":       str(confidence),
        "tier":             tier,
        "type":             type,
        "subject_ip":       subject_ip,
        "subject_ja4":      subject_ja4,
        "description":      description[:500],
        "evidence_count":   str(evidence_count),
        "model_version":    model_version[:32],
        "model_trained_at": model_trained_at[:32],
        "fp_rate_estimate": str(fp_rate_estimate),
        "suggested_action": suggested_action,
        "created_at":       now_iso,
        "dismissed":        "0",
    }

    key = f"{_FINDING_PREFIX}{finding_id}"
    ttl = _TIER_TTL.get(tier, 14400)

    try:
        pipe = redis.pipeline()
        pipe.hset(key, mapping=mapping)
        pipe.expire(key, ttl)
        pipe.zadd(_FINDINGS_INDEX, {finding_id: now_epoch})
        pipe.zremrangebyrank(_FINDINGS_INDEX, 0, -1001)
        await pipe.execute()
        logger.info(
            "output_writer | event=finding_written | id=%s | tier=%s | type=%s",
            finding_id, tier, type,
        )
        return finding_id
    except Exception as exc:
        logger.warning(
            "output_writer | event=write_failed | id=%s | error=%s",
            finding_id, exc,
        )
        return None


async def update_heartbeat(redis: aioredis.Redis, poll_interval_seconds: int = 30) -> None:
    """Write the analytics heartbeat key.

    Called once per analytics poll cycle. The management console reads this
    key's TTL to determine whether analytics is running. If analytics stops,
    the key expires and the console shows 'Analytics DOWN'.

    TTL is set to 2 * poll_interval so one missed cycle does not trigger an alarm.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    ttl = poll_interval_seconds * 2
    try:
        await redis.set(_HEARTBEAT_KEY, now_iso, ex=ttl)
    except Exception as exc:
        logger.warning("output_writer | event=heartbeat_failed | error=%s", exc)


async def write_active_connections(redis: aioredis.Redis, count: int) -> None:
    """Write the current number of active (tarpitted) connections.

    The tarpit service may write this directly; if not, the analytics engine
    can estimate it from the event stream. The management console displays this
    value in the infrastructure row.
    """
    try:
        await redis.set(_ACTIVE_CONNECTIONS_KEY, str(count), ex=120)
    except Exception as exc:
        logger.warning(
            "output_writer | event=active_connections_write_failed | count=%s | error=%s",
            count, exc,
        )
