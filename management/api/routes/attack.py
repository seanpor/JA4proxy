"""Attack view API endpoints (Phase 247 + Phase 250).

Routes
------
GET /api/v1/attack/top                 — top attacking IPs (Phase 247)
GET /api/v1/attack/top-fingerprints    — top attacking JA4 fingerprints (Phase 250)

Both endpoints read the recent event stream (last 300s) and are designed to be
polled every 5 seconds by the Under Attack dashboard.
"""

import asyncio
import json
import logging
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from ..auth import require_role
from ..ja4_corpus import browser_label, is_known_browser
from ..models import Role
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["attack"])

_STREAM_KEY = "events:connection"
_ATTACK_WINDOW_SECONDS = 300  # 5 minutes


def detect_botnet_signal(
    unique_ip_count: int,
    avg_score: float,
    is_browser: bool,
    attack_mode: bool = False,
) -> str:
    """Classify a fingerprint's botnet threat level.

    Returns: "botnet" | "suspect" | "tool" | "browser" | "unknown"

    Conservative thresholds: a fingerprint needs BOTH spread (multiple IPs)
    AND elevated scores to qualify as a botnet signal.
    Attack mode lowers thresholds to catch emerging campaigns faster.
    """
    if is_browser:
        return "browser"
    if attack_mode:
        if unique_ip_count >= 3 and avg_score >= 50:
            return "botnet"
        if unique_ip_count >= 2 and avg_score >= 30:
            return "suspect"
    else:
        if unique_ip_count >= 5 and avg_score >= 60:
            return "botnet"
        if unique_ip_count >= 3 and avg_score >= 40:
            return "suspect"
    if unique_ip_count >= 2:
        return "tool"
    return "unknown"


async def _read_attack_window(redis, window_seconds: int = _ATTACK_WINDOW_SECONDS) -> list:
    """Read events from the last window_seconds from the event stream.

    Returns a list of dicts (parsed event payloads) in reverse-chronological order.
    Returns empty list on Redis error (fail open).
    """
    min_ms = int((time.time() - window_seconds) * 1000)
    min_id = f"{min_ms}-0"
    try:
        raw = await redis.xrevrange(_STREAM_KEY, max="+", min=min_id, count=500)
        events = []
        for _entry_id, fields in raw:
            raw_event = fields.get("event")
            if not raw_event:
                continue
            try:
                events.append(json.loads(raw_event))
            except (ValueError, TypeError):
                continue
        return events
    except Exception as exc:
        logger.warning("attack | event=stream_read_error | error=%s", exc)
        return []


@router.get("/api/v1/attack/top")
async def top_attackers(
    window: int = Query(_ATTACK_WINDOW_SECONDS, description="Window in seconds"),
    _user=Depends(require_role(Role.auditor)),
    redis=Depends(get_redis),
) -> JSONResponse:
    """Top attacking IPs in the last window_seconds, sorted by max risk score."""
    events = await _read_attack_window(redis, window)

    ip_scores: dict[str, float] = {}
    ip_counts: dict[str, int] = defaultdict(int)
    ip_actions: dict[str, str] = {}
    ip_ja4: dict[str, str] = {}
    ip_block_counts: dict[str, int] = defaultdict(int)

    for ev in events:
        ip = ev.get("source.ip", "")
        if not ip:
            continue
        score = float(ev.get("event.risk_score", 0) or 0)
        action = ev.get("event.action", "")
        ja4 = ev.get("ja4proxy.fingerprint.ja4", "")
        ip_counts[ip] += 1
        if action in ("block", "ban", "tarpit"):
            ip_block_counts[ip] += 1
        if score > ip_scores.get(ip, -1):
            ip_scores[ip] = score
            ip_actions[ip] = action
            if ja4:
                ip_ja4[ip] = ja4

    top = sorted(ip_scores.items(), key=lambda x: x[1], reverse=True)[:20]

    # Batch ban-status lookup (bounded to top 20 — polled every 5s by the
    # Under Attack dashboard, so keep this cheap).
    ban_expires: dict[str, Optional[str]] = {}
    try:
        for ip, _score in top:
            ttl = await redis.ttl(f"ban:{ip}")
            if ttl and ttl > 0:
                ban_expires[ip] = (
                    datetime.now(timezone.utc) + timedelta(seconds=ttl)
                ).isoformat()
            elif ttl == -1:
                ban_expires[ip] = None  # permanent ban, no expiry
    except Exception as exc:  # noqa: BLE001
        logger.warning("attack | event=ban_status_lookup_error | error=%s", exc)

    return JSONResponse({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window_seconds": window,
        "attackers": [
            {
                "ip": ip,
                "max_score": round(score, 1),
                "connection_count": ip_counts.get(ip, 0),
                "block_count": ip_block_counts.get(ip, 0),
                "last_action": ip_actions.get(ip, ""),
                "ja4": ip_ja4.get(ip, ""),
                "current_status": "banned" if ip in ban_expires else "active",
                "ban_expires": ban_expires.get(ip),
            }
            for ip, score in top
        ],
    })


@router.get("/api/v1/attack/top-fingerprints")
async def top_fingerprints(
    attack_mode: bool = Query(False, description="Lower thresholds for Attack Mode"),
    _user=Depends(require_role(Role.auditor)),
    redis=Depends(get_redis),
) -> JSONResponse:
    """Top JA4 fingerprints active in the last 5 minutes, with botnet signal.

    Sorted by unique_ip_count DESC (the key botnet indicator).
    Fail open: returns empty list if Redis is unavailable.
    """
    events = await _read_attack_window(redis)

    # Aggregate per fingerprint.
    fp_connections: dict[str, int] = defaultdict(int)
    fp_ips: dict[str, set] = defaultdict(set)
    fp_scores: dict[str, list] = defaultdict(list)
    fp_actions: dict[str, set] = defaultdict(set)
    fp_ja4t: dict[str, set] = defaultdict(set)
    fp_countries: dict[str, set] = defaultdict(set)
    fp_asns: dict[str, set] = defaultdict(set)

    for ev in events:
        ja4 = ev.get("ja4proxy.fingerprint.ja4", "")
        if not ja4:
            continue
        ip = ev.get("source.ip", "")
        score = float(ev.get("event.risk_score", 0) or 0)
        action = ev.get("event.action", "")
        ja4t = ev.get("ja4proxy.fingerprint.ja4t", "")
        country = ev.get("source.geo.country_iso_code", "")
        asn = ev.get("source.as.number", "")

        fp_connections[ja4] += 1
        if ip:
            fp_ips[ja4].add(ip)
        fp_scores[ja4].append(score)
        if action:
            fp_actions[ja4].add(action)
        if ja4t:
            fp_ja4t[ja4].add(ja4t)
        if country:
            fp_countries[ja4].add(country)
        if asn:
            fp_asns[ja4].add(str(asn))

    if not fp_connections:
        return JSONResponse({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "window_seconds": _ATTACK_WINDOW_SECONDS,
            "fingerprints": [],
        })

    # Batch blacklist/whitelist check.
    fps_list = list(fp_connections.keys())
    try:
        blacklisted_raw = await redis.smismember("ja4:blacklist", fps_list)
        whitelisted_raw = await redis.smismember("ja4:whitelist", fps_list)
    except Exception:
        # smismember unavailable (older Redis or missing method) — fall back.
        try:
            blacklisted_raw = await asyncio.gather(
                *[redis.sismember("ja4:blacklist", fp) for fp in fps_list]
            )
            whitelisted_raw = await asyncio.gather(
                *[redis.sismember("ja4:whitelist", fp) for fp in fps_list]
            )
        except Exception as exc:
            logger.warning("attack | event=list_check_error | error=%s", exc)
            blacklisted_raw = [False] * len(fps_list)
            whitelisted_raw = [False] * len(fps_list)

    blacklisted = {fp: bool(v) for fp, v in zip(fps_list, blacklisted_raw)}
    whitelisted = {fp: bool(v) for fp, v in zip(fps_list, whitelisted_raw)}

    results = []
    for fp in fps_list:
        scores = fp_scores[fp]
        unique_ips = fp_ips[fp]
        avg_score = sum(scores) / len(scores) if scores else 0.0
        max_score = max(scores) if scores else 0
        is_browser = is_known_browser(fp)
        signal = detect_botnet_signal(len(unique_ips), avg_score, is_browser, attack_mode)
        # sample_ips: only for non-browser fingerprints (up to 5 for drill-down).
        sample = sorted(unique_ips)[:5] if not is_browser else []

        results.append({
            "ja4": fp,
            "browser_label": browser_label(fp),
            "total_connections": fp_connections[fp],
            "unique_ip_count": len(unique_ips),
            "avg_score": round(avg_score, 1),
            "max_score": int(max_score),
            "is_known_browser": is_browser,
            "is_blacklisted": blacklisted.get(fp, False),
            "is_whitelisted": whitelisted.get(fp, False),
            "botnet_signal": signal,
            "ja4t_values": sorted(fp_ja4t[fp]),
            "countries": sorted(fp_countries[fp]),
            "asn_count": len(fp_asns[fp]),
            "sample_ips": sample,
        })

    # Sort by unique_ip_count DESC, then total_connections DESC.
    results.sort(key=lambda x: (-x["unique_ip_count"], -x["total_connections"]))

    return JSONResponse({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window_seconds": _ATTACK_WINDOW_SECONDS,
        "fingerprints": results[:20],
    })
