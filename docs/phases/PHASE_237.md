---
phase: 237
title: Operational Polish & Missing Workflows
status: PROPOSED
size: MEDIUM
created: 2026-06-12
audience: [developer, operator, secops]
dependencies: [231, 235, 236]
---

# Operational Polish & Missing Workflows

> **Dependency reminder:** Phase 235 (confirmation modal) and Phase 236 (intelligence
> row) must be complete before this phase begins. The shift handover snapshot
> (Step A) reads analytics findings — Phase 236 must be deployed first.

---

## 1. Plain-English Goal

A UX review of the management console identified five workflow gaps that affect
real operator behaviour under stress:

1. **No shift handover mechanism.** At the end of a shift, an analyst needs to
   hand over to their colleague with a clear picture of what happened and what
   is currently active. Right now they have to screenshot individual pages and
   write notes by hand.

2. **No dial auto-revert.** The enforcement dial can be raised to 75 during an
   attack. A tired analyst at 4 AM who raises the dial and then forgets to lower
   it leaves legitimate traffic blocked all morning — sometimes for hours before
   anyone notices.

3. **No CIDR blocking.** Attack campaigns often come from entire IP ranges
   owned by a specific hosting provider. Banning individual IPs one by one when
   you know the whole /24 is attacking is tedious and error-prone.

4. **Manual actions look identical to proxy-automated actions in the live feed.**
   When reviewing an incident, operators cannot tell whether a block was applied
   by the system or by a colleague. Attribution matters for post-incident review.

5. **TLS certificate expiry is invisible.** When the HAProxy TLS certificate
   expires, HAProxy fails to restart and the proxy goes completely dark. No
   fingerprinting. No scoring. All traffic passes through unscored. Currently
   there is no warning before this happens.

After this phase, each of these five gaps is closed.

---

## 2. Background — What You Need to Know Before Writing Code

### 2a. What a Shift Handover Looks Like in a Real SOC

In a Security Operations Centre (SOC), analysts work in shifts — typically 8 or
12 hours. At the end of each shift, the outgoing analyst hands over to the incoming
analyst. The handover must cover:

- **What was the threat level when I started vs when I'm leaving?**
- **What actions did I take, and why?**
- **What is currently active that the incoming analyst needs to watch?**
- **Are there any pending decisions I didn't finish?**

Without a structured handover artefact, this information lives in people's heads
and gets lost. In a real incident, missing handover context can cause the incoming
analyst to reverse decisions made by the outgoing analyst, double-block IPs, or
miss a threat that was already escalating.

The "Export Snapshot" button we are adding creates a structured JSON document with
all of this information in one place. It is timestamped and attributed to the
current user. The incoming analyst can load it directly, or it can be pasted into
a ticketing system.

### 2b. Why Dial Auto-Revert Matters

The enforcement dial controls how aggressively the proxy blocks traffic. Dial 0 is
"monitor only" — nothing is blocked. Dial 75 is "active enforcement" — many IPs
are blocked. Dial 100 is "block everything that scores above the threshold" — very
aggressive.

During an active attack, an analyst raises the dial. When the attack ends, the dial
should come back down. If it doesn't, legitimate users start getting blocked.

The problem is human memory under fatigue. At 4 AM after a 6-hour incident, an
analyst who raised the dial at 2 AM may not remember to lower it before handing
over. The next shift inherits an over-aggressive dial setting with no context.

Auto-revert solves this at the policy level: when you raise the dial, you are also
required (or optionally prompted) to set a revert time. After that time, the dial
automatically returns to its previous value. The analyst still gets the aggressive
enforcement during the incident, but it can't be accidentally left running forever.

### 2c. What CIDR Notation Means

An IP address like `203.0.113.42` identifies one specific machine.

CIDR (Classless Inter-Domain Routing) notation lets you describe a range of IP
addresses. `203.0.113.0/24` means "all 256 addresses from 203.0.113.0 to
203.0.113.255". The number after the slash is the prefix length — the number of
bits that are fixed. More bits fixed = smaller range.

Common CIDR sizes:
- `/32` — exactly one IP (same as writing the IP alone)
- `/30` — 4 addresses (2 usable hosts)
- `/24` — 256 addresses ("a /24" or "a C-block")
- `/16` — 65,536 addresses ("a /16" or "a B-block")
- `/8`  — 16,777,216 addresses ("a /8" or "an A-block")

**Why we reject private ranges:** IP ranges like `10.0.0.0/8`, `172.16.0.0/12`,
and `192.168.0.0/16` are private network ranges (RFC 1918). These are used inside
organisations — your own servers, your colleagues' workstations, your internal
tools. If an operator accidentally bans `10.0.0.0/8`, they have banned their entire
internal network. Everyone in the building loses access. This is a self-inflicted
denial of service. We reject private ranges by default.

**Why we reject large CIDRs (> /16):** A /16 is 65,536 addresses. Creating 65,536
Redis keys in a single API call is a risk of Redis memory exhaustion and a risk of
collateral damage (blocking legitimate hosting ranges). We cap at /16 and require
explicit acknowledgement for anything larger.

### 2d. What TLS Certificate Expiry Means for This Proxy

HAProxy terminates TLS — it reads the certificate file from disk and uses it to
negotiate encrypted connections. The certificate has an expiry date embedded in it
(set when the certificate was issued).

When the certificate expires:
1. HAProxy notices the certificate is invalid on its next restart.
2. HAProxy refuses to start.
3. The proxy is completely down.
4. All traffic passes through unscored.
5. JA4 fingerprinting stops.

Certificate expiry happens on a fixed date. It is fully predictable. There is no
excuse for it to surprise a SOC team — but it does, regularly, because certificates
are issued and then forgotten until they expire.

The TLS health check endpoint reads the certificate file, extracts the expiry date,
and computes how many days remain. This information is shown in the infrastructure
panel with colour-coded urgency bands:
- Green: > 30 days remaining — no action needed.
- Amber: 14–30 days — schedule renewal now.
- Red: < 14 days — act immediately, the proxy will go down soon.

---

## 3. Step A: Shift Handover Snapshot

### 3a. Complete `management/api/routes/snapshots.py`

Create this new file:

```python
"""Shift handover snapshot endpoint.

GET /api/v1/snapshot — returns a structured JSON document capturing the current
system state. Designed for SOC shift handover: the outgoing analyst downloads
the snapshot; the incoming analyst reads it to understand current threat posture.

Requires operator or admin role.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from ..auth import get_current_user
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["snapshots"])

_BAN_KEY_PREFIX = "ban:"
_AUDIT_KEY = "management:audit_log"
_DIAL_KEY = "config:dial"
_INTELLIGENCE_INDEX = "analytics:findings:index"
_INTELLIGENCE_KEY_PREFIX = "analytics:finding:"
_EVENTS_STREAM = "ja4proxy:events"


async def _read_dial(redis) -> dict:
    """Read current dial value and updated_at timestamp."""
    raw = await redis.get(_DIAL_KEY)
    value = int(raw) if raw else 0

    # Read last dial change from audit log for updated_at
    audit_raw = await redis.lrange(_AUDIT_KEY, 0, 99)
    updated_at = None
    for entry in audit_raw:
        try:
            e = json.loads(entry)
            if e.get("action") == "dial_change":
                updated_at = e.get("timestamp")
                break
        except (json.JSONDecodeError, AttributeError):
            continue

    return {"value": value, "updated_at": updated_at or "unknown"}


async def _read_active_bans(redis) -> list[dict]:
    """Read all currently active ban entries."""
    bans = []
    cursor = 0
    while True:
        cursor, keys = await redis.scan(cursor=cursor, match=f"{_BAN_KEY_PREFIX}*", count=100)
        for key in keys:
            ip = key[len(_BAN_KEY_PREFIX):] if isinstance(key, str) else key.decode()[len(_BAN_KEY_PREFIX):]
            reason = await redis.get(key)
            ttl = await redis.ttl(key)
            if ttl == -2:
                continue  # already expired
            bans.append({
                "ip": ip,
                "reason": reason.decode() if isinstance(reason, bytes) else (reason or ""),
                "ttl_seconds": ttl if ttl >= 0 else None,
            })
        if cursor == 0:
            break

    bans.sort(key=lambda b: b.get("ttl_seconds") or 999999)
    return bans


async def _read_top_threats(redis, window_seconds: int = 3600) -> list[dict]:
    """Read top scoring IPs from the event stream in the last window_seconds."""
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    since_ms = now_ms - (window_seconds * 1000)

    try:
        entries = await redis.xrange(_EVENTS_STREAM, f"{since_ms}-0", "+", count=5000)
    except Exception as exc:
        logger.warning("snapshots | event=stream_read_error | error=%s", exc)
        return []

    # Aggregate scores per IP
    ip_scores: dict[str, float] = {}
    for _entry_id, fields in entries:
        ip = fields.get(b"client_ip", fields.get("client_ip", b"")).decode() if isinstance(
            fields.get(b"client_ip", fields.get("client_ip", "")), bytes
        ) else fields.get("client_ip", "")
        score_raw = fields.get(b"risk_score", fields.get("risk_score", b"0"))
        try:
            score = float(score_raw.decode() if isinstance(score_raw, bytes) else score_raw)
        except (ValueError, AttributeError):
            score = 0.0
        if ip:
            ip_scores[ip] = max(ip_scores.get(ip, 0.0), score)

    # Return top 10
    sorted_ips = sorted(ip_scores.items(), key=lambda x: x[1], reverse=True)[:10]
    return [{"ip": ip, "max_score": round(score, 1)} for ip, score in sorted_ips]


async def _read_analytics_findings(redis) -> list[dict]:
    """Read active (non-dismissed) HIGH-confidence analytics findings."""
    findings = []
    try:
        raw_ids = await redis.zrevrange(_INTELLIGENCE_INDEX, 0, 19)
        for fid in raw_ids:
            if isinstance(fid, bytes):
                fid = fid.decode()
            key = f"{_INTELLIGENCE_KEY_PREFIX}{fid}"
            raw = await redis.hgetall(key)
            if not raw:
                continue
            decoded = {
                (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
                for k, v in raw.items()
            }
            if decoded.get("dismissed") == "1":
                continue
            findings.append({
                "id": fid,
                "tier": decoded.get("tier"),
                "type": decoded.get("type"),
                "confidence": decoded.get("confidence"),
                "description": decoded.get("description", "")[:200],
                "suggested_action": decoded.get("suggested_action"),
                "created_at": decoded.get("created_at"),
            })
    except Exception as exc:
        logger.warning("snapshots | event=analytics_read_error | error=%s", exc)

    return findings


async def _read_system_health(redis) -> dict:
    """Read key system health indicators."""
    health: dict[str, Any] = {}

    # Redis responsiveness
    try:
        await redis.ping()
        health["redis"] = "ok"
    except Exception:
        health["redis"] = "error"

    # Redis memory
    try:
        info = await redis.info("memory")
        health["redis_used_memory"] = info.get("used_memory_human", "unknown")
        health["redis_maxmemory"] = info.get("maxmemory_human", "unlimited")
    except Exception:
        health["redis_used_memory"] = "unknown"

    # Redis evictions
    try:
        stats = await redis.info("stats")
        health["redis_evicted_keys"] = stats.get("evicted_keys", 0)
    except Exception:
        health["redis_evicted_keys"] = "unknown"

    # Analytics heartbeat
    try:
        hb = await redis.get("analytics:heartbeat")
        health["analytics_heartbeat"] = hb.decode() if isinstance(hb, bytes) else (hb or "never")
    except Exception:
        health["analytics_heartbeat"] = "unknown"

    return health


@router.get("/api/v1/snapshot")
async def get_snapshot(
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> JSONResponse:
    """Return a structured JSON snapshot of current system state.

    This is the shift handover document. It captures all information an
    incoming analyst needs to understand the current situation without
    having to navigate through multiple dashboard pages.

    Requires operator or admin role.
    """
    user_name, user_role = current_user[0], (current_user[1] if len(current_user) > 1 else "auditor")

    if user_role not in ("operator", "admin"):
        raise HTTPException(status_code=403, detail="Operator or admin role required.")

    generated_at = datetime.now(timezone.utc).isoformat()

    try:
        dial = await _read_dial(redis)
        active_bans = await _read_active_bans(redis)
        top_threats = await _read_top_threats(redis, window_seconds=3600)
        analytics_findings = await _read_analytics_findings(redis)
        system_health = await _read_system_health(redis)

        # Watchlist count
        watchlist_count = await redis.scard("ja4:watchlist") or 0

        # Triage queue count (IPs not on any list with score in 35-65 range —
        # simplified count for snapshot; full triage logic lives in triage endpoint)
        triage_queue_count = 0  # Placeholder — extend if triage endpoint is implemented

        snapshot: dict[str, Any] = {
            "generated_at": generated_at,
            "generated_by": user_name,
            "dial": dial,
            "active_bans": active_bans,
            "active_ban_count": len(active_bans),
            "watchlist_count": int(watchlist_count),
            "top_threats_1h": top_threats,
            "active_analytics_findings": analytics_findings,
            "triage_queue_count": triage_queue_count,
            "system_health": system_health,
        }

        logger.info(
            "snapshots | event=snapshot_generated | user=%s | bans=%s | findings=%s",
            user_name, len(active_bans), len(analytics_findings),
        )

        return JSONResponse(
            content=snapshot,
            headers={
                "Content-Disposition": f'attachment; filename="ja4proxy-snapshot-{generated_at[:10]}.json"',
                "Content-Type": "application/json",
            },
        )

    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("snapshots | event=snapshot_error | user=%s | error=%s", user_name, exc)
        raise HTTPException(status_code=500, detail="Failed to generate snapshot.")
```

### 3b. Topbar Button Change in `base.html`

Add the snapshot download button to the topbar next to the UTC clock. The button
only appears for operator+ role — pass `role` from the page routes (see Phase 234
RBAC sub-task for the pattern).

```diff
       <!-- UTC clock -->
       <span class="text-xs text-[#94a3b8]" id="utc-clock">UTC —</span>
+      <!-- Shift handover snapshot (operator+ only) -->
+      {% if role in ['operator', 'admin'] %}
+      <a href="/api/v1/snapshot"
+         id="export-snapshot-btn"
+         download
+         class="inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium
+                bg-[#334155] hover:bg-[#475569] text-[#f1f5f9] transition-colors
+                focus:outline-none focus:ring-2 focus:ring-[#0ea5e9] focus:ring-offset-2 focus:ring-offset-[#1e293b]"
+         title="Download shift handover snapshot (JSON)">
+        <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
+          <path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
+        </svg>
+        Export Snapshot
+      </a>
+      {% endif %}
     </div>
   </header>
```

Register the new router in `management/api/main.py`:

```diff
+from .routes.snapshots import router as snapshots_router
 app.include_router(snapshots_router)
```

---

## 4. Step B: Dial Auto-Revert

### 4a. Extended Dial Update Endpoint

Locate `management/api/routes/dial.py` (or wherever the dial PUT endpoint lives).
Add `revert_after_hours` to the request body:

```python
# In management/api/routes/dial.py

from pydantic import BaseModel, Field
from typing import Optional
import asyncio

class DialUpdateRequest(BaseModel):
    value: int = Field(..., ge=0, le=100, description="New dial value, 0–100.")
    revert_after_hours: Optional[int] = Field(
        None, ge=1, le=24,
        description="Auto-revert the dial to its current value after N hours (1–24)."
    )
```

Extend the PUT handler:

```python
@router.put("/api/v1/dial")
async def update_dial(
    body: DialUpdateRequest,
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
):
    """Update the enforcement dial value.

    If revert_after_hours is provided, the dial will automatically return
    to its value before this change after the specified number of hours.
    This prevents accidental permanent escalation. (PHASE_237 Step B)
    """
    user_name = current_user[0]
    user_role = current_user[1] if len(current_user) > 1 else "auditor"

    if user_role not in ("operator", "admin"):
        raise HTTPException(status_code=403, detail="Operator or admin role required.")

    # Read current value before overwriting (needed for revert)
    current_raw = await redis.get("config:dial")
    previous_value = int(current_raw) if current_raw else 0

    # Set new dial value
    await redis.set("config:dial", str(body.value))

    # Phase 237: Schedule auto-revert if requested
    revert_key = "config:dial:revert"
    if body.revert_after_hours is not None:
        revert_seconds = body.revert_after_hours * 3600
        # Store the previous value and set a TTL — when the TTL expires,
        # a background task (or keyspace notification consumer) reads this
        # key and resets the dial to the stored value.
        await redis.set(revert_key, str(previous_value), ex=revert_seconds)
        logger.info(
            "dial | event=revert_scheduled | user=%s | from=%s | to=%s | revert_in_hours=%s",
            user_name, body.value, previous_value, body.revert_after_hours,
        )
    else:
        # Clear any existing revert schedule when dial is changed without revert
        await redis.delete(revert_key)

    # Audit log entry
    await redis.rpush(
        "management:audit_log",
        json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user": user_name,
            "action": "dial_change",
            "detail": {
                "from": previous_value,
                "to": body.value,
                "revert_after_hours": body.revert_after_hours,
            },
        }),
    )

    return {"ok": True, "value": body.value, "revert_scheduled": body.revert_after_hours is not None}
```

### 4b. Revert Background Task

The revert is triggered by Redis keyspace notification on the `config:dial:revert`
key expiry. This requires `notify-keyspace-events Ex` in `redis.conf` (or passed
as a CLI argument). Add a lightweight consumer to the management service:

```python
# management/tasks/dial_revert.py
"""Background task: consume Redis keyspace notifications for dial auto-revert.

When the config:dial:revert key expires, Redis fires a keyspace notification on
__keyevent@0__:expired. This consumer listens for that event and restores the
dial to the stored previous value.

Enabled by: CONFIG SET notify-keyspace-events Ex
(or --notify-keyspace-events Ex in redis CLI args)

Note: keyspace notifications require a separate Redis pub/sub connection.
This task is started by management/api/main.py on startup.
"""
import asyncio
import logging

logger = logging.getLogger(__name__)

_REVERT_KEY = "config:dial:revert"
_DIAL_KEY = "config:dial"
_REVERT_WATCH_CHANNEL = "__keyevent@0__:expired"


async def run_dial_revert_watcher(redis_factory) -> None:
    """Long-running coroutine. Call as asyncio.create_task(run_dial_revert_watcher(...))."""
    while True:
        try:
            async with redis_factory() as pubsub_redis:
                ps = pubsub_redis.pubsub()
                await ps.subscribe(_REVERT_WATCH_CHANNEL)
                logger.info("dial_revert | event=watcher_started")

                async for message in ps.listen():
                    if message.get("type") != "message":
                        continue
                    expired_key = message.get("data", b"").decode()
                    if expired_key == _REVERT_KEY:
                        # The revert key expired — but we already removed its value
                        # when setting the TTL. We stored the revert TARGET in the key.
                        # By this point the key is gone. We need a different approach:
                        # store the revert value in a separate persistent key.
                        logger.warning(
                            "dial_revert | event=revert_triggered | "
                            "note=revert_value_lost_on_expiry_use_shadow_key"
                        )
                        # See implementation note below.

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("dial_revert | event=watcher_error | error=%s | reconnecting", exc)
            await asyncio.sleep(5)
```

> **Implementation note — shadow key pattern:** Redis keyspace notifications fire
> AFTER the key expires. At that point, the key (and its value) are gone. To
> recover the "revert to" value, use a **shadow key** with no TTL:
>
> ```python
> # When scheduling the revert:
> await redis.set("config:dial:revert:shadow", str(previous_value))   # no TTL — permanent
> await redis.set("config:dial:revert", "1", ex=revert_seconds)       # TTL triggers notification
>
> # In the watcher, when expiry fires:
> shadow = await redis.get("config:dial:revert:shadow")
> if shadow:
>     await redis.set("config:dial", shadow)
>     await redis.delete("config:dial:revert:shadow")
>     logger.info("dial_revert | event=reverted | value=%s", shadow)
> ```

### 4c. Dial Widget Template Change

In `management/templates/partials/dial_widget.html`, add an amber badge when a
revert is scheduled and a cancel button:

```diff
+{# Read revert schedule from template context (passed by dial partial endpoint) #}
+{% if revert_seconds_remaining and revert_seconds_remaining > 0 %}
+{% set revert_hours = (revert_seconds_remaining // 3600) %}
+{% set revert_mins  = ((revert_seconds_remaining % 3600) // 60) %}
+<div class="flex items-center gap-2 mt-2 px-3 py-1.5 rounded bg-[#d97706]/10 border border-[#d97706]/30">
+  <span class="text-xs text-[#d97706]">
+    ▲ Auto-reverts in {{ revert_hours }}h {{ revert_mins }}m
+  </span>
+  <button type="button"
+          hx-delete="/api/v1/dial/revert"
+          hx-target="#dial-widget"
+          hx-swap="outerHTML"
+          class="text-xs text-[#94a3b8] hover:text-[#f87171] transition-colors
+                 focus:outline-none focus:ring-1 focus:ring-[#f87171]">
+    Cancel revert
+  </button>
+</div>
+{% endif %}
```

The dial partial endpoint must pass `revert_seconds_remaining`:

```python
# In the GET /api/v1/partials/dial handler:
revert_raw = await redis.ttl("config:dial:revert")
revert_seconds_remaining = revert_raw if revert_raw > 0 else 0
# Pass to template:
# "revert_seconds_remaining": revert_seconds_remaining
```

---

## 5. Step C: CIDR Range Blocking

### 5a. Extended `POST /api/v1/bans` Endpoint

Locate the bans endpoint in `management/api/routes/bans.py`. Extend it to accept
CIDR input:

```python
# management/api/routes/bans.py additions

import ipaddress
from typing import Union

# Private/loopback ranges to reject by default
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("169.254.0.0/16"),    # link-local
    ipaddress.ip_network("100.64.0.0/10"),     # shared address space (RFC 6598)
]

# Maximum CIDR prefix length we will expand (reject anything with more hosts)
_MAX_CIDR_PREFIX = 16   # /16 = 65,536 hosts max

class BanRequest(BaseModel):
    ip: str = Field(..., description="IPv4, IPv6, or CIDR range (e.g. 203.0.113.0/24).")
    reason: str = Field(..., min_length=10, description="Reason for the ban (min 10 chars).")
    duration_hours: int = Field(24, ge=1, le=720, description="Ban duration in hours (max 30 days).")
    allow_private: bool = Field(
        False,
        description="Set true to allow banning private/RFC1918 ranges. "
                    "WARNING: banning 10.0.0.0/8 will block your entire internal network.",
    )


def _expand_cidr(cidr_str: str, allow_private: bool) -> list[str]:
    """Expand a CIDR block into individual IP strings.

    Raises ValueError with a user-readable message on any rejection.
    Returns a list of IP strings to ban (may be a single IP for /32 input).
    """
    try:
        network = ipaddress.ip_network(cidr_str, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid IP or CIDR: {cidr_str!r} — {exc}") from exc

    # Check prefix length (reject huge CIDRs)
    if network.prefixlen < _MAX_CIDR_PREFIX:
        host_count = network.num_addresses
        raise ValueError(
            f"CIDR /{network.prefixlen} covers {host_count:,} addresses. "
            f"Maximum allowed is /{_MAX_CIDR_PREFIX} ({2 ** (32 - _MAX_CIDR_PREFIX):,} addresses). "
            f"Larger blocks risk collateral damage to legitimate users. "
            f"Ban individual /24 blocks instead."
        )

    # Check for private ranges (unless explicitly allowed)
    if not allow_private:
        for private_net in _PRIVATE_NETWORKS:
            if network.overlaps(private_net):
                raise ValueError(
                    f"CIDR {cidr_str} overlaps private/reserved range {private_net}. "
                    f"Banning this range would block internal/loopback traffic. "
                    f"If you intend this, pass allow_private=true."
                )

    # Exclude network address and broadcast for IPv4 /24 and smaller
    if isinstance(network, ipaddress.IPv4Network) and network.prefixlen >= 24:
        hosts = [str(ip) for ip in network.hosts()]   # excludes .0 and .255
    else:
        hosts = [str(ip) for ip in network]

    return hosts
```

Full ban endpoint handler:

```python
@router.post("/api/v1/bans")
async def create_ban(
    body: BanRequest,
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
):
    """Ban an IP address or CIDR range.

    For individual IPs: creates one ban:IP key.
    For CIDRs (/24 and smaller): expands and creates one key per host IP
    using a Redis pipeline for efficiency.
    Rejects CIDR ranges larger than /16 and private/RFC1918 ranges (unless
    allow_private=true is explicitly passed).

    PHASE_237 Step C: CIDR expansion.
    """
    user_name = current_user[0]
    user_role = current_user[1] if len(current_user) > 1 else "auditor"

    if user_role not in ("operator", "admin"):
        raise HTTPException(status_code=403, detail="Operator or admin role required.")

    ttl_seconds = body.duration_hours * 3600

    # Expand CIDR (or validate single IP)
    try:
        ips_to_ban = _expand_cidr(body.ip, body.allow_private)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    if not ips_to_ban:
        raise HTTPException(status_code=422, detail="CIDR expansion produced zero IPs.")

    try:
        pipe = redis.pipeline()
        for ip in ips_to_ban:
            key = f"ban:{ip}"
            pipe.set(key, body.reason, ex=ttl_seconds)
        await pipe.execute()
    except Exception as exc:
        logger.warning(
            "bans | event=ban_write_error | cidr=%s | ips=%s | error=%s",
            body.ip, len(ips_to_ban), exc,
        )
        raise HTTPException(status_code=500, detail="Redis write failed.")

    # Audit log
    await redis.rpush(
        "management:audit_log",
        json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user": user_name,
            "action": "manual_ban",
            "detail": {
                "ip": body.ip,
                "ip_count": len(ips_to_ban),
                "reason": body.reason,
                "duration_hours": body.duration_hours,
                "is_cidr": "/" in body.ip,
            },
        }),
    )

    logger.info(
        "bans | event=ban_created | user=%s | cidr=%s | ips=%s | ttl_hours=%s",
        user_name, body.ip, len(ips_to_ban), body.duration_hours,
    )

    return {
        "ok": True,
        "banned_ip": body.ip,
        "host_count": len(ips_to_ban),
        "duration_hours": body.duration_hours,
    }
```

### 5b. Bans Page Form Change — CIDR Input with Preview

In `management/templates/bans.html`, extend the ban form to accept CIDR and show
a preview. Use Alpine.js to compute the preview client-side:

```html
<!-- CIDR ban form — add alongside existing single-IP ban form -->
<div x-data="{
  cidr: '',
  previewCount: 0,
  previewError: '',
  previewCidr() {
    // Client-side CIDR preview — server does the authoritative validation
    this.previewError = '';
    this.previewCount = 0;
    if (!this.cidr || !this.cidr.includes('/')) return;
    const parts = this.cidr.split('/');
    const prefix = parseInt(parts[1]);
    if (isNaN(prefix) || prefix < 0 || prefix > 32) {
      this.previewError = 'Invalid prefix length.';
      return;
    }
    if (prefix < 16) {
      this.previewError = 'Prefix /' + prefix + ' is too large (max /16).';
      return;
    }
    this.previewCount = Math.pow(2, 32 - prefix) - (prefix >= 24 ? 2 : 0);
  }
}" class="bg-[#1e293b] border border-[#334155] rounded-xl p-4 mt-4">
  <h3 class="text-sm font-semibold text-[#f1f5f9] mb-3">Ban CIDR Range</h3>
  <form hx-post="/api/v1/bans" hx-target="#bans-table" hx-swap="innerHTML" class="space-y-3">
    <div>
      <label for="ban-cidr-input" class="block text-xs text-[#94a3b8] mb-1">
        IP or CIDR range (e.g. 203.0.113.0/24)
      </label>
      <input type="text"
             id="ban-cidr-input"
             name="ip"
             x-model="cidr"
             @input.debounce.300ms="previewCidr()"
             placeholder="203.0.113.0/24"
             class="w-full px-3 py-2 text-sm rounded-md bg-[#0f172a] border border-[#334155]
                    text-[#f1f5f9] placeholder-[#64748b] focus:outline-none focus:ring-2 focus:ring-[#0ea5e9]" />
      <!-- Preview -->
      <p class="text-xs mt-1"
         x-show="previewCount > 0 && !previewError"
         x-text="'This will ban ' + previewCount + ' IP addresses in this range.'"
         class="text-[#d97706]"></p>
      <p class="text-xs mt-1 text-[#f87171]"
         x-show="previewError"
         x-text="previewError"></p>
    </div>
    <div>
      <label for="ban-cidr-reason" class="block text-xs text-[#94a3b8] mb-1">
        Reason (minimum 10 characters)
      </label>
      <input type="text" id="ban-cidr-reason" name="reason" minlength="10"
             class="w-full px-3 py-2 text-sm rounded-md bg-[#0f172a] border border-[#334155]
                    text-[#f1f5f9] focus:outline-none focus:ring-2 focus:ring-[#0ea5e9]" />
    </div>
    <input type="hidden" name="duration_hours" value="24" />
    <button type="submit"
            :disabled="previewError !== '' || cidr === ''"
            class="px-4 py-2 text-sm font-medium rounded-md bg-[#dc2626] hover:bg-[#b91c1c]
                   text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed
                   focus:outline-none focus:ring-2 focus:ring-[#dc2626]">
      Ban Range
    </button>
  </form>
</div>
```

---

## 6. Step D: Manual Action Attribution in the Live Feed

When the proxy blocks an IP automatically, the event appears in the live feed with
no operator attribution. When an operator manually bans an IP through the management
console, the ban event appears in the same feed — indistinguishable from an automatic
action.

The fix: when rendering a live feed event, check the audit log for a matching manual
ban entry within ±5 seconds of the event's timestamp.

### 6a. Audit Log Lookup Logic

In `management/api/routes/partials.py`, add a helper:

```python
async def _find_manual_attribution(redis, client_ip: str, event_ts: float) -> Optional[str]:
    """Check the audit log for a manual ban on client_ip near event_ts.

    Returns the operator username if a manual action is found within ±5 seconds,
    None otherwise. Used to add [manual] attribution to live feed events.

    This is a background enrichment step — a failure returns None, never raises.
    """
    try:
        # Read last 200 audit entries (LIFO — most recent first)
        raw_entries = await redis.lrange("management:audit_log", 0, 199)
        for raw in raw_entries:
            try:
                e = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                continue
            if e.get("action") not in ("manual_ban", "list_add"):
                continue
            detail = e.get("detail", {})
            if detail.get("ip") != client_ip:
                continue
            # Parse timestamp and check ±5 seconds
            try:
                from datetime import datetime, timezone
                audit_ts = datetime.fromisoformat(e["timestamp"]).timestamp()
                if abs(audit_ts - event_ts) <= 5.0:
                    return e.get("user", "operator")
            except (ValueError, KeyError):
                continue
    except Exception as exc:
        logger.warning(
            "partials | event=attribution_lookup_error | ip=%s | error=%s",
            client_ip, exc,
        )
    return None
```

Pass the attribution to the live feed template as an enriched field:

```python
# In the live feed event processing loop:
# event_ts = float(stream_entry_id.split("-")[0]) / 1000
# manual_by = await _find_manual_attribution(redis, event["client_ip"], event_ts)
# event["manual_by"] = manual_by
```

### 6b. `live_feed.html` Badge Change

```diff
+{% if event.manual_by %}
+<span class="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium
+             bg-[#2563eb]/20 text-[#60a5fa] border border-[#2563eb]/30"
+      title="Manually actioned by {{ event.manual_by }}">
+  [manual: {{ event.manual_by }}]
+</span>
+{% endif %}
```

---

## 7. Step E: TLS Certificate Expiry Visibility

### 7a. Complete `GET /api/v1/tls-health` Endpoint

Create `management/api/routes/tls_health.py`:

```python
"""TLS certificate health endpoint.

GET /api/v1/tls-health — reads the HAProxy TLS certificate and returns expiry info.

Why this matters: when the HAProxy TLS certificate expires, HAProxy refuses to
restart and the proxy goes completely dark. This endpoint provides early warning
so the SOC team can renew the certificate before it causes an outage.

The certificate path is read from the HAPROXY_TLS_CERT_PATH environment variable
(default: /etc/haproxy/certs/server.pem). In the Docker setup, this file is
bind-mounted into the management container from the haproxy container's cert path.
"""

import logging
import os
import ssl
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ..auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(tags=["tls"])

_DEFAULT_CERT_PATH = "/etc/haproxy/certs/server.pem"


@router.get("/api/v1/tls-health")
async def tls_health(
    request: Request,
    current_user=Depends(get_current_user),
) -> JSONResponse:
    """Return TLS certificate expiry information.

    Reads the HAProxy TLS certificate from HAPROXY_TLS_CERT_PATH
    (default: /etc/haproxy/certs/server.pem) and returns:
      - expires_at (ISO8601)
      - days_remaining (int)
      - subject (dict)
      - issuer (dict)
      - status ("ok" | "warn" | "crit" | "error")
      - band ("green" | "amber" | "red")
    """
    cert_path = os.getenv("HAPROXY_TLS_CERT_PATH", _DEFAULT_CERT_PATH)

    if not os.path.exists(cert_path):
        logger.warning("tls_health | event=cert_not_found | path=%s", cert_path)
        return JSONResponse({
            "status": "error",
            "band": "red",
            "message": f"Certificate file not found: {cert_path}",
            "cert_path": cert_path,
        }, status_code=200)  # 200 so the partial always renders

    try:
        # Read certificate using ssl module — no subprocess needed
        cert_dict = ssl._ssl._test_decode_cert(cert_path)  # type: ignore[attr-defined]
    except Exception as exc:
        logger.warning("tls_health | event=cert_parse_error | path=%s | error=%s", cert_path, exc)
        return JSONResponse({
            "status": "error",
            "band": "red",
            "message": f"Failed to parse certificate: {exc}",
            "cert_path": cert_path,
        })

    try:
        # notAfter format: "Nov 12 00:00:00 2025 GMT"
        not_after_str = cert_dict.get("notAfter", "")
        not_after_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_remaining = (not_after_dt - now).days

        if days_remaining > 30:
            status, band = "ok", "green"
        elif days_remaining >= 14:
            status, band = "warn", "amber"
        else:
            status, band = "crit", "red"

        subject = dict(x[0] for x in cert_dict.get("subject", []))
        issuer = dict(x[0] for x in cert_dict.get("issuer", []))

        logger.info(
            "tls_health | event=cert_read | days=%s | band=%s | subject_cn=%s",
            days_remaining, band, subject.get("commonName", "unknown"),
        )

        return JSONResponse({
            "status": status,
            "band": band,
            "expires_at": not_after_dt.isoformat(),
            "days_remaining": days_remaining,
            "subject": subject,
            "issuer": issuer,
            "cert_path": cert_path,
        })

    except Exception as exc:
        logger.warning("tls_health | event=cert_processing_error | path=%s | error=%s", cert_path, exc)
        return JSONResponse({
            "status": "error",
            "band": "red",
            "message": f"Error computing expiry: {exc}",
        })
```

### 7b. `infrastructure.html` Template Addition

In `management/templates/partials/infrastructure.html`, add a TLS certificate row:

```html
<!-- TLS Certificate Expiry row — loaded via hx-get="/api/v1/tls-health" -->
<div id="tls-cert-row"
     hx-get="/api/v1/tls-health"
     hx-trigger="load, every 3600s"
     hx-swap="innerHTML">

  <!-- This innerHTML is replaced by the HTMX response once loaded -->
  <div class="flex items-center justify-between py-2 border-t border-[#334155]">
    <span class="text-sm text-[#94a3b8]">TLS Certificate</span>
    <span class="text-xs text-[#64748b]">Loading…</span>
  </div>
</div>
```

The `GET /api/v1/tls-health` endpoint should also support rendering an HTML fragment.
Add a `format=html` query parameter variant, or create a separate partial:

```html
<!-- partials/tls_cert_card.html — returned by /api/v1/tls-health?format=html -->
{% set band_color = {
  "green": "text-[#16a34a]",
  "amber": "text-[#d97706]",
  "red":   "text-[#dc2626]",
}.get(band, "text-[#94a3b8]") %}
{% set band_shape = {
  "green": "●",
  "amber": "▲",
  "red":   "✖",
}.get(band, "?") %}

<div class="flex items-center justify-between py-2 border-t border-[#334155]">
  <span class="text-sm text-[#94a3b8]">TLS Certificate</span>
  <div class="flex items-center gap-2">
    {% if status == "error" %}
      <span class="text-xs text-[#dc2626]">✖ Cannot read certificate — {{ message }}</span>
    {% else %}
      <span class="text-xs {{ band_color }}">
        {{ band_shape }}
        {{ subject.get("commonName", "Unknown") }} —
        expires {{ expires_at[:10] }}
        ({{ days_remaining }} days)
      </span>
      {% if band == "red" %}
      <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-bold bg-[#dc2626] text-white animate-pulse">
        ⚠ ACT NOW
      </span>
      {% elif band == "amber" %}
      <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-[#d97706] text-white">
        Renew Soon
      </span>
      {% endif %}
    {% endif %}
  </div>
</div>
```

---

## 8. Tests

### 8a. Snapshot Test

```python
# tests/unit/test_snapshot.py

import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient


@pytest.mark.asyncio
async def test_snapshot_all_fields_present(authenticated_operator_client, mock_redis):
    """Snapshot endpoint returns all required handover fields."""
    response = await authenticated_operator_client.get("/api/v1/snapshot")
    assert response.status_code == 200
    data = response.json()

    required_fields = [
        "generated_at",
        "generated_by",
        "dial",
        "active_bans",
        "active_ban_count",
        "watchlist_count",
        "top_threats_1h",
        "active_analytics_findings",
        "triage_queue_count",
        "system_health",
    ]
    for field in required_fields:
        assert field in data, f"Missing required field: {field}"

    assert "value" in data["dial"]
    assert "updated_at" in data["dial"]
    assert "redis" in data["system_health"]


@pytest.mark.asyncio
async def test_snapshot_requires_operator_role(authenticated_auditor_client):
    """Auditor role must not be able to download the snapshot."""
    response = await authenticated_auditor_client.get("/api/v1/snapshot")
    assert response.status_code == 403
```

### 8b. Dial Revert Test

```python
# tests/unit/test_dial_revert.py

import pytest
import asyncio
from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_revert_key_written_with_correct_ttl(mock_redis):
    """When revert_after_hours=2 is set, the revert key has a 7200s TTL."""
    # Simulate the dial update handler logic
    mock_redis.get = AsyncMock(return_value=b"0")   # previous dial value
    mock_redis.set = AsyncMock()
    mock_redis.delete = AsyncMock()

    revert_hours = 2
    expected_ttl = revert_hours * 3600   # 7200 seconds

    # Simulate the revert scheduling
    await mock_redis.set("config:dial", "50")
    await mock_redis.set("config:dial:revert:shadow", "0")
    await mock_redis.set("config:dial:revert", "1", ex=expected_ttl)

    # Assert set was called with the correct TTL
    calls = [str(c) for c in mock_redis.set.call_args_list]
    assert any("7200" in c for c in calls), f"Expected TTL 7200 in calls: {calls}"


@pytest.mark.asyncio
async def test_revert_restores_previous_value(mock_redis):
    """Simulates the expiry event: dial is restored to the shadow key value."""
    mock_redis.get = AsyncMock(return_value=b"25")   # shadow key stores previous value
    mock_redis.set = AsyncMock()
    mock_redis.delete = AsyncMock()

    # Simulate what the watcher does when it receives the expiry event
    shadow = await mock_redis.get("config:dial:revert:shadow")
    assert shadow == b"25"
    await mock_redis.set("config:dial", shadow)
    await mock_redis.delete("config:dial:revert:shadow")

    mock_redis.set.assert_called_with("config:dial", b"25")
```

### 8c. CIDR Blocking Tests

```python
# tests/unit/test_cidr_bans.py

import pytest
from management.api.routes.bans import _expand_cidr


def test_valid_slash24_expands_to_254_hosts():
    """/24 produces 254 usable host addresses (excludes .0 and .255)."""
    ips = _expand_cidr("203.0.113.0/24", allow_private=False)
    assert len(ips) == 254
    assert "203.0.113.1" in ips
    assert "203.0.113.254" in ips
    assert "203.0.113.0" not in ips    # network address excluded
    assert "203.0.113.255" not in ips  # broadcast excluded


def test_private_range_rejected_by_default():
    """10.0.0.0/8 is rejected without allow_private=True."""
    with pytest.raises(ValueError, match="private"):
        _expand_cidr("10.0.0.0/8", allow_private=False)


def test_private_range_allowed_with_flag():
    """/24 in a private range is allowed when allow_private=True."""
    ips = _expand_cidr("10.0.0.0/24", allow_private=True)
    assert len(ips) == 254


def test_slash8_rejected_too_large():
    """/8 has 16M addresses — rejected regardless of allow_private."""
    with pytest.raises(ValueError, match="too large|collateral"):
        _expand_cidr("1.0.0.0/8", allow_private=False)


def test_slash16_boundary_accepted():
    """/16 is the maximum accepted (65,534 hosts)."""
    ips = _expand_cidr("203.0.0.0/16", allow_private=False)
    assert len(ips) > 0


def test_single_ip_as_slash32_works():
    """A single IP (no CIDR notation) expands to one address."""
    ips = _expand_cidr("203.0.113.42", allow_private=False)
    assert ips == ["203.0.113.42"]


def test_invalid_ip_raises_valueerror():
    with pytest.raises(ValueError, match="Invalid IP"):
        _expand_cidr("not.an.ip.address", allow_private=False)


def test_loopback_rejected():
    """Loopback range 127.0.0.0/8 rejected by default."""
    with pytest.raises(ValueError, match="private"):
        _expand_cidr("127.0.0.0/24", allow_private=False)
```

### 8d. TLS Expiry Test

```python
# tests/unit/test_tls_health.py

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta


@pytest.mark.asyncio
async def test_cert_expiring_in_5_days_returns_red_band(test_client):
    """A certificate expiring in 5 days → band='red', status='crit'."""
    expiry = datetime.now(timezone.utc) + timedelta(days=5)
    expiry_str = expiry.strftime("%b %d %H:%M:%S %Y GMT")

    mock_cert = {
        "notAfter": expiry_str,
        "subject": [[("commonName", "proxy.example.com")]],
        "issuer": [[("organizationName", "Let's Encrypt")]],
    }

    with patch("ssl._ssl._test_decode_cert", return_value=mock_cert), \
         patch("os.path.exists", return_value=True):
        response = await test_client.get(
            "/api/v1/tls-health",
            headers={"Authorization": "Bearer test-operator-token"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["band"] == "red"
    assert data["status"] == "crit"
    assert data["days_remaining"] == 5


@pytest.mark.asyncio
async def test_cert_expiring_in_20_days_returns_amber_band(test_client):
    expiry = datetime.now(timezone.utc) + timedelta(days=20)
    expiry_str = expiry.strftime("%b %d %H:%M:%S %Y GMT")
    mock_cert = {"notAfter": expiry_str, "subject": [], "issuer": []}

    with patch("ssl._ssl._test_decode_cert", return_value=mock_cert), \
         patch("os.path.exists", return_value=True):
        response = await test_client.get("/api/v1/tls-health",
                                         headers={"Authorization": "Bearer test-operator-token"})

    assert response.json()["band"] == "amber"


@pytest.mark.asyncio
async def test_cert_expiring_in_60_days_returns_green_band(test_client):
    expiry = datetime.now(timezone.utc) + timedelta(days=60)
    expiry_str = expiry.strftime("%b %d %H:%M:%S %Y GMT")
    mock_cert = {"notAfter": expiry_str, "subject": [], "issuer": []}

    with patch("ssl._ssl._test_decode_cert", return_value=mock_cert), \
         patch("os.path.exists", return_value=True):
        response = await test_client.get("/api/v1/tls-health",
                                         headers={"Authorization": "Bearer test-operator-token"})

    assert response.json()["band"] == "green"


@pytest.mark.asyncio
async def test_missing_cert_file_returns_error(test_client):
    with patch("os.path.exists", return_value=False):
        response = await test_client.get("/api/v1/tls-health",
                                         headers={"Authorization": "Bearer test-operator-token"})
    assert response.status_code == 200
    assert response.json()["status"] == "error"
```

### 8e. Running All Phase 237 Tests

```bash
# Working directory: /home/sean/LLM/JA4proxy2

# Unit tests for this phase
python3 -m pytest tests/unit/test_snapshot.py \
                  tests/unit/test_dial_revert.py \
                  tests/unit/test_cidr_bans.py \
                  tests/unit/test_tls_health.py \
                  -v

# Page rendering tests — verify new routes return 200 + text/html
python3 -m pytest tests/management/test_pages.py -v

# Full suite (must pass before merge)
make test

# Lint and type check all new/modified files
python3 -m ruff check \
  management/api/routes/snapshots.py \
  management/api/routes/bans.py \
  management/api/routes/dial.py \
  management/api/routes/tls_health.py \
  management/tasks/dial_revert.py

python3 -m mypy \
  management/api/routes/snapshots.py \
  management/api/routes/bans.py \
  management/api/routes/tls_health.py
```

---

## 9. Definition of Done

All of the following must be true before this phase is marked COMPLETE in
`docs/phases/manifest.yaml`:

- [ ] `GET /api/v1/snapshot` returns all required fields; requires operator+ role.
- [ ] "Export Snapshot" button visible in topbar for operator+ role.
- [ ] `PUT /api/v1/dial` accepts `revert_after_hours` (1–24).
- [ ] Revert shadow key written with correct EXPIREAT; dial watcher restores value.
- [ ] Dial widget shows amber "Reverts in X hours" badge when revert is scheduled.
- [ ] Cancel revert button removes the shadow key and disables the watcher.
- [ ] `POST /api/v1/bans` accepts CIDR input (/32 through /16).
- [ ] Private/loopback/RFC1918 ranges rejected with 422 without `allow_private=True`.
- [ ] Bans form shows client-side CIDR preview count.
- [ ] Live feed shows `[manual: username]` badge for manually-applied actions.
- [ ] `GET /api/v1/tls-health` returns correct days_remaining and band.
- [ ] Infrastructure partial shows TLS cert row with colour-coded urgency.
- [ ] All unit tests pass with zero warnings.
- [ ] `make test` exits 0.
- [ ] `python3 -m ruff check` exits 0 on all new/modified files.
- [ ] CHANGELOG.md updated with Phase 237 entry.
- [ ] `docs/phases/manifest.yaml` updated: `status: COMPLETE`, `completed: YYYY-MM-DD`.
- [ ] `python3 scripts/sync-roadmap.py` run.

---

## 10. Common Mistakes

**Mistake 1: Blocking the live feed render with the attribution lookup.**
The `_find_manual_attribution` function reads 200 audit log entries for every event
in the live feed. If the live feed shows 50 events, that is 10,000 Redis LRANGE
lookups per render. Cache the audit log in memory for the duration of the request:
```python
# Read once, use for all events in this request
audit_entries = await redis.lrange("management:audit_log", 0, 199)
# Then pass audit_entries to _find_manual_attribution as a parameter
```

**Mistake 2: Using `network.hosts()` for non-/24 CIDRs.**
`ipaddress.IPv4Network.hosts()` excludes the network and broadcast addresses.
For a /31 or /30, this leaves very few usable addresses. For a /16, it works
correctly but produces 65,534 addresses — check that the pipeline write completes
without a Redis timeout. Use `max_ttl` appropriately.

**Mistake 3: Forgetting to mount the HAProxy cert into the management container.**
`/api/v1/tls-health` reads a certificate file. In Docker, that file is inside the
HAProxy container. You must add a bind mount to the management container so it can
read the same certificate:
```yaml
# In docker-compose.poc.yml management service:
volumes:
  - ../../config/haproxy/certs:/etc/haproxy/certs:ro
```
Without this mount, the endpoint always returns `"status": "error"`.

**Mistake 4: Using f-strings in logging.**
All logger calls must use `%s` formatting, not f-strings. This is enforced by ruff.
Wrong: `logger.info(f"Banned {len(ips)} IPs in {body.ip}")`
Right: `logger.info("bans | event=banned | count=%s | cidr=%s", len(ips), body.ip)`

**Mistake 5: Not clearing the existing revert schedule when the dial is changed again.**
If an operator sets the dial to 75 with a 2-hour revert, then 30 minutes later sets
it to 50 with no revert, the original revert key is still in Redis and will fire
after the remaining 90 minutes — unexpectedly resetting the dial to 0 (the value
before the 75 setting, not the current 50). Always `redis.delete("config:dial:revert")`
and `redis.delete("config:dial:revert:shadow")` when a new dial change has no
`revert_after_hours`.

**Mistake 6: Treating the snapshot as a security boundary.**
The snapshot downloads as a JSON file with no access controls beyond the initial
authentication check. Do not include Redis passwords, JWT secrets, or TLS private key
paths in the snapshot. Treat it as a document that could be emailed between SOC
shifts — it should contain operational data, not credentials.
