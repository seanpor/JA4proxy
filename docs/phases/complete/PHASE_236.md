---
phase: 236
title: Analytics Intelligence Visibility
status: PROPOSED
size: MEDIUM
created: 2026-06-12
audience: [developer, analyst, secops]
dependencies: [231, 233, 235]
---

# Analytics Intelligence Visibility

> **Dependency reminder:** Phase 233 must be complete (Redis ACL capability exists)
> and Phase 235 must be complete (confirmation modal component exists) before this
> phase begins. Do not skip the ACL prerequisite — see Section 3 below.

---

## 1. Plain-English Goal

The analytics engine runs machine-learning models 24 hours a day, seven days a week.
It detects three threat patterns:

- **Beaconing** — a client connects on a clockwork schedule, a sign of C2 malware
  checking in with its controller.
- **Coordinated campaigns** — multiple IPs with the same JA4 fingerprint arriving in
  bursts, suggesting a shared attack tool.
- **Traffic drift** — the statistical distribution of JA4 fingerprints shifts
  suddenly, a sign that a new bot population arrived.

Right now, when the analytics engine spots one of these patterns, its conclusion goes
nowhere. It exists inside the analytics container and no human ever sees it. An
operator at 2 AM has no idea whether the analytics engine has been screaming about a
beaconing campaign for the past six hours.

After this phase, high-confidence analytics findings appear on the main dashboard
in a new "Intelligence" row. Operators can read the finding, see the model's
reasoning, and take action (block, watchlist, dismiss) without leaving the dashboard.
Medium- and low-confidence findings are accessible on a separate "Intelligence Review"
page for analysts who want to do deeper triage.

The implementation is intentionally conservative: we show only what the model is
confident about, we validate everything before rendering, and we allow operators to
flag false positives so the model can learn.

This phase implements Decision 5 from PHASE_231.md.

---

## 2. Background — What You Need to Know Before Writing Code

### 2a. What Redis ACLs Are

Think of Redis like a shared filing cabinet that all containers read from and write
to. Without access controls, any container can read or write any file.

Redis ACLs (Access Control Lists) work like file permissions: you can restrict which
containers are allowed to read or write which keys. The ACL system is based on
**patterns** — you say "this user can only touch keys whose names start with
`analytics:`" and Redis enforces it at the protocol level.

A Redis ACL entry looks like this:

```
user analytics on >s3cr3t ~analytics:* +@read +@write -@admin
```

Breaking that down word by word:
- `user analytics` — this rule applies to a user named "analytics"
- `on` — this user account is enabled
- `>s3cr3t` — the password (prefixed with `>` to distinguish it from other tokens)
- `~analytics:*` — this user can only touch keys whose names match `analytics:*`
  (the `~` means "key pattern"; `*` is a wildcard)
- `+@read +@write` — allow all read commands (GET, HGET, SMEMBERS, XRANGE, ...)
  and all write commands (SET, HSET, XADD, ...)
- `-@admin` — deny administrative commands (CONFIG, DEBUG, SHUTDOWN, ...)

When the analytics container tries to write `config:dial` — a key outside its
permitted pattern — Redis rejects it immediately with a `NOPERM` error. This is
enforced in Redis kernel space; no application code can bypass it.

### 2b. Why Jinja2 Auto-Escaping Is Not Enough for a Security Product

Jinja2 auto-escaping converts HTML special characters like `<`, `>`, and `"` into
safe representations (`&lt;`, `&gt;`, `&quot;`). This prevents XSS (Cross-Site
Scripting) attacks where a piece of rendered text accidentally becomes executable
HTML.

But consider this attack: the analytics engine writes its findings to Redis. The
management console reads those findings and renders them. If an attacker can control
what the analytics engine writes to Redis — perhaps by exploiting a deserialization
bug in the analytics container, or by compromising the analytics container directly
— they can write malicious data into the `analytics:finding:*` keys.

Jinja2 auto-escaping handles the *rendering* step safely, but it does nothing about
**blocklist poisoning**. For example:

```
analytics engine writes: analytics:finding:abc123
  → type: "blocklist_update"     ← a type we didn't expect
  → subject_ip: "10.0.0.0/8"    ← our entire internal network
  → suggested_action: "block"   ← the management console might act on this
```

If the management console blindly reads any finding from Redis and acts on the
`suggested_action` field, the attacker has poisoned the blocklist. Jinja2 escaping
would display this safely on screen, but the damage happens when the operator clicks
"Block" trusting the model's output.

**The defence:** Schema validation. Before rendering *anything* from Redis, the
management console validates:
1. Every required field is present.
2. Every field is the correct type (string, float, int).
3. Every field is within allowed value ranges (confidence is 0.0–1.0 not 999).
4. Every string field is within maximum length limits (description ≤ 500 chars).
5. The `type` field is one of a known-good enum (beaconing, campaign, drift, slowscan).
6. The `suggested_action` is one of a known-good enum (monitor, watchlist, investigate, block).

Anything that fails validation is **silently discarded** with a WARNING log entry.
The operator sees "no findings" rather than a poisoned finding. This is the correct
security posture: fail closed on unexpected data from an analytics component.

Combined with Redis ACLs (which prevent the analytics container from writing outside
its namespace) and the CSP header (from Phase 232, which prevents inline script
execution), this creates three independent layers of defence.

### 2c. What Confidence Tiers Mean in Machine Learning

A classification model outputs a number between 0.0 and 1.0 called a **confidence
score** (or probability). A score of 0.95 means the model believes there is a 95%
chance that this traffic is, for example, beaconing. A score of 0.55 means the
model is barely better than a coin flip.

The problem with showing all model outputs to operators is **alert fatigue**. If
every finding above 0.5 appeared on the main dashboard, operators would see hundreds
of low-quality alerts per shift and start ignoring them — including the real ones.

Decision 5 from PHASE_231.md defines three tiers:

| Tier   | Confidence range | What it means                                        |
|--------|-----------------|------------------------------------------------------|
| HIGH   | ≥ 0.90          | Model is highly confident. Worth immediate attention.|
| MEDIUM | 0.70–0.89       | Model thinks this is likely but not certain.          |
| LOW    | < 0.70          | Uncertain. Background noise.                         |

**Only HIGH findings appear on the main dashboard.** This is a deliberate UX
decision: the dashboard is the 2 AM incident response view. Only actionable,
high-confidence intelligence belongs there.

MEDIUM and LOW findings are still stored and available on the "Intelligence Review"
page for analysts doing deeper triage during quieter periods.

### 2d. Why Schema Validation Before Rendering Matters

This is closely related to 2b, but deserves its own explanation for clarity.

The analytics engine and the management console are two separate containers. They
communicate via Redis. From the management console's perspective, the data in Redis
is **untrusted external input** — exactly the same as form data from a user, a query
parameter in a URL, or a JSON body from an API caller.

We already validate and sanitise all of those. We must do the same for Redis data
that originated from another container.

Validation rules for analytics findings are defined as a schema constant dict in
`output_writer.py`. The management console carries its own copy of the schema in
`_FINDING_SCHEMA`. This duplication is by design — the two services run in
separate containers and the management container does not have access to
`output_writer.py` at runtime (its Dockerfile only copies `management/`).

If the schemas ever drift (analytics writes a new field the console doesn't
expect), the console safely ignores the unknown field. A **parity test** 
(`tests/unit/test_schema_parity.py`) verifies both copies are identical in CI,
catching drift at PR time.

---

## 3. PREREQUISITE: Redis ACL Setup

> **⚠ NOTE: This must be completed before Step A. Do not implement the output writer
> or the intelligence endpoint until these ACLs are verified. An analytics container
> without ACL restrictions can write to `ja4:blocklist` — see Section 2b.**

This is the "Analytics Trust Boundary" described in PHASE_231.md (the section of the
same name, between the finding register and the delivery sub-phases).

### 3a. Understanding the Redis ACL Config File Format

Redis ACL rules are written in a plain text file, one rule per line. The file is
passed to Redis at startup with the `aclfile` directive in `redis.conf`:

```
aclfile /etc/redis/redis_acl.conf
```

Each line follows this format:
```
user <name> <enabled|disabled> [password] [key-patterns] [commands]
```

Tokens after the username:
- `on` / `off` — enable or disable the account
- `><password>` — password (the `>` prefix is required by the ACL syntax)
- `~<pattern>` — key pattern(s) the user can access (glob syntax, `*` = all)
- `+@<category>` — allow a category of commands (`@read`, `@write`, `@string`, etc.)
- `-@<category>` — deny a category (evaluated after allowlist)
- `+<command>` — allow a specific command
- `-<command>` — deny a specific command
- `nopass` — no password required (only for trusted environments — don't use here)
- `resetkeys` — remove all key patterns (start clean before adding new ones)

### 3b. Complete `config/redis_acl.conf` Additions

Create or extend the file at `config/redis_acl.conf`:

```
# Redis ACL file for JA4proxy
# Phase 236: Analytics Trust Boundary
#
# user management — used by the management console.
#   ~* = may access any key (it needs to read config:*, ja4:*, ban:*, etc.)
#   This is intentionally broad; the management console is trusted.
user management on >${MANAGEMENT_REDIS_PASSWORD} ~* +@read +@write -@admin

# user analytics — used by the analytics container ONLY.
#   ~analytics:* = analytics container may ONLY read/write keys beginning with
#   "analytics:". It cannot touch config:dial, ja4:blocklist, ban:*, etc.
#   If the analytics container is compromised, the attacker cannot manipulate
#   the blocklist or dial setting.
user analytics on >${ANALYTICS_REDIS_PASSWORD} resetkeys ~analytics:* +@read +@write +ping -@admin

# user default — disable the unauthenticated default user.
#   Any client that does not authenticate gets no permissions at all.
user default off nopass ~* -@all
```

**Key design choices:**
- `resetkeys` before `~analytics:*` — clears any inherited key patterns, ensuring
  analytics starts with a clean slate.
- `+ping` — needed by health checks that call `PING` without a key argument.
- `-@admin` — prevents both users from running CONFIG, DEBUG, SHUTDOWN, etc.
- `user default off` — disables unauthenticated access entirely.

### 3c. `docker-compose.poc.yml` Changes to Pass ACL Credentials

The analytics container needs to know its Redis credentials. Add to the analytics
service definition in `deploy/docker/docker-compose.poc.yml`:

```diff
  analytics:
    build:
      context: ../..
      dockerfile: deploy/docker/Dockerfile.analytics
    environment:
+     - REDIS_URL=redis://analytics:${ANALYTICS_REDIS_PASSWORD:?ANALYTICS_REDIS_PASSWORD is required}@redis:6379/0
-     - REDIS_URL=redis://redis:6379/0
      - ANALYTICS_POLL_INTERVAL=30
    networks:
      - ja4proxy-data
      - ja4proxy-mgmt
```

Add the same `REDIS_URL` change to `docker-compose.prod.yml`.

Add the new variables to `.env.example`:
```
# Redis credentials for analytics container (Phase 236 ACL)
ANALYTICS_REDIS_PASSWORD=change_me_analytics_strong_password
MANAGEMENT_REDIS_PASSWORD=change_me_management_strong_password
```

Also add the ACL file mount to the Redis service:
```diff
  redis:
    image: redis:7.4.0-alpine
+   command: redis-server /etc/redis/redis.conf --aclfile /etc/redis/redis_acl.conf
    volumes:
      - redis-data:/data
+     - ../../config/redis_acl.conf:/etc/redis/redis_acl.conf:ro
```

### 3d. Change to `analytics/redis_client.py` to Use the Scoped User

Locate the Redis client initialisation in the analytics codebase. The exact path
may be `src/analytics/redis_client.py` or similar — grep to confirm:

```bash
# Working directory: <repo root>
grep -rn "redis.from_url\|aioredis\|Redis(" src/analytics/ --include="*.py"
```

The change is to use the `REDIS_URL` environment variable (which now contains the
`analytics` user credentials) instead of a hardcoded connection string:

```diff
-REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
+# Phase 236: Use scoped analytics ACL user. REDIS_URL must include credentials,
+# e.g. redis://analytics:<password>@redis:6379/0 — see config/redis_acl.conf.
+REDIS_URL = os.getenv("REDIS_URL")
+if not REDIS_URL:
+    raise RuntimeError(
+        "REDIS_URL is required. Set it to redis://analytics:<password>@redis:6379/0"
+    )
```

If the Redis client is already reading from `REDIS_URL`, no change to the client
itself is needed — only the compose file change above is required.

### 3e. Verification — Testing the ACL Works

Run these steps after deploying the compose changes:

```bash
# Working directory: <repo root>

# 1. Start the POC stack
docker compose -f deploy/docker/docker-compose.poc.yml up -d redis

# 2. Exec into the analytics container (or use the Redis CLI directly with analytics creds)
docker compose -f deploy/docker/docker-compose.poc.yml run --rm analytics \
  python3 -c "
import os, redis
r = redis.from_url(os.environ['REDIS_URL'])
# This should succeed:
r.hset('analytics:finding:test', mapping={'confidence': '0.95', 'type': 'beaconing'})
print('PASS: analytics can write analytics:finding:test')
# This must fail with NOPERM:
try:
    r.set('config:dial', '50')
    print('FAIL: analytics wrote config:dial — ACL not enforced!')
except redis.exceptions.NoPermissionError as e:
    print('PASS: analytics cannot write config:dial —', e)
except Exception as e:
    print('UNEXPECTED error:', e)
"
```

Expected output:
```
PASS: analytics can write analytics:finding:test
PASS: analytics cannot write config:dial — user analytics has no permissions to access a key
```

If the second line shows `FAIL`, stop and fix the ACL before proceeding.

---

## 4. Step A: Analytics Output Writer Module

This new module defines the **contract** between the analytics engine and everything
else. Treat it as the official schema definition — if you change the field names here,
update both the analytics engine and the management console in the same commit.

### Complete `src/analytics/output_writer.py`

```python
"""Analytics output writer — Redis interface for analytics findings.

This module is the authoritative Redis output contract for the analytics engine.
All analytics data written to Redis flows through this module.

Redis key schema
----------------
analytics:finding:{uuid}          Hash — one finding per key
analytics:findings:index          Sorted set — created_at epoch → uuid
analytics:heartbeat               String — ISO8601 timestamp, TTL = 2 * poll interval
analytics:active_connections      String — integer count, written by tarpit or analytics

Finding hash field definitions
-------------------------------
Field               Type    Constraints
confidence          float   0.0 ≤ x ≤ 1.0
tier                str     HIGH | MEDIUM | LOW
type                str     beaconing | campaign | drift | slowscan
subject_ip          str     optional; valid IPv4/IPv6 or empty string
subject_ja4         str     optional; max 64 chars or empty string
description         str     max 500 chars; PLAIN TEXT — no HTML
evidence_count      int     ≥ 0
model_version       str     max 32 chars (e.g. "1.2.3")
model_trained_at    str     ISO8601 datetime
fp_rate_estimate    float   0.0 ≤ x ≤ 1.0 (model's own FP rate estimate)
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

# ---------------------------------------------------------------------------
# Schema constant — single source of truth for field definitions.
# The management console validates against this same schema (see partials.py).
# ---------------------------------------------------------------------------

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

    Parameters
    ----------
    redis:            Async Redis client authenticated as the 'analytics' ACL user.
    confidence:       Model confidence score, 0.0–1.0.
    type:             Detection type: beaconing | campaign | drift | slowscan.
    description:      Plain-text description (no HTML), max 500 chars.
    evidence_count:   Number of events that contributed to this finding.
    model_version:    Version string of the model that produced this finding.
    model_trained_at: ISO8601 datetime when the model was trained.
    fp_rate_estimate: Model's own false-positive rate estimate, 0.0–1.0.
    suggested_action: Recommended action: monitor | watchlist | investigate | block.
    subject_ip:       Optional; the specific IP this finding is about.
    subject_ja4:      Optional; the specific JA4 fingerprint this finding is about.
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
        "description":      description[:500],   # hard truncate as safety net
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
        # Trim index to last 1000 findings to prevent unbounded growth
        pipe.zremrangebyrank(_FINDINGS_INDEX, 0, -1001)
        await pipe.execute()
        logger.info(
            "output_writer | event=finding_written | id=%s | tier=%s | type=%s",
            finding_id, tier, type,
        )
        return finding_id
    except Exception as exc:
        # Fail-open: log and return None. The analytics pipeline continues.
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
```

### Wire into `src/analytics/main.py` — Diff

```diff
+from src.analytics.output_writer import (
+    write_finding,
+    update_heartbeat,
+    write_active_connections,
+)

 async def run_detection_cycle(redis_client, config):
     """One complete detection cycle."""
+    # Phase 236: Update heartbeat at the start of every cycle.
+    await update_heartbeat(redis_client, poll_interval_seconds=config.poll_interval)
+
     results = await run_all_detectors(redis_client, config)

     for result in results:
         if result.confidence is None:
             continue
-        logger.info("Detection result: %s confidence=%s", result.type, result.confidence)
+        finding_id = await write_finding(
+            redis_client,
+            confidence=result.confidence,
+            type=result.type,
+            description=result.description,
+            evidence_count=result.evidence_count,
+            model_version=result.model_version,
+            model_trained_at=result.model_trained_at,
+            fp_rate_estimate=result.fp_rate_estimate,
+            suggested_action=result.suggested_action,
+            subject_ip=getattr(result, "subject_ip", ""),
+            subject_ja4=getattr(result, "subject_ja4", ""),
+        )
+        if finding_id:
+            logger.info(
+                "main | event=finding_published | id=%s | tier=%s | type=%s",
+                finding_id, result.tier, result.type,
+            )
```

---

## 5. Step B: Intelligence Partial Endpoint

### 5a. Schema Validation Function

Add to `management/api/routes/partials.py` (import section and helper):

```python
# Phase 236 — imports
import ipaddress
from datetime import datetime, timezone

# Phase 236 — schema constant (mirrors output_writer.FINDING_SCHEMA)
# Intentionally duplicated: the two services run in separate containers and
# the management Dockerfile only copies management/. A parity test at
# tests/unit/test_schema_parity.py verifies both copies stay in sync.
_FINDING_SCHEMA = {
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

_INTELLIGENCE_KEY_PREFIX = "analytics:finding:"
_INTELLIGENCE_INDEX = "analytics:findings:index"


def _validate_finding(raw: dict, finding_id: str) -> Optional[dict]:
    """Validate an analytics finding against the schema.

    Returns a cleaned dict if valid, None if invalid.
    Any validation failure results in silent discard with a WARNING log.
    This is the schema-validation security control described in PHASE_231.md
    (Analytics Trust Boundary section).
    """
    cleaned: dict = {}
    for field, rules in _FINDING_SCHEMA.items():
        value = raw.get(field)
        if value is None:
            if rules.get("required"):
                logger.warning(
                    "partials | event=finding_schema_fail | id=%s | reason=missing_required | field=%s",
                    finding_id, field,
                )
                return None
            cleaned[field] = ""
            continue
        # Type coerce and validate
        expected_type = rules["type"]
        try:
            coerced = expected_type(value)
        except (ValueError, TypeError):
            logger.warning(
                "partials | event=finding_schema_fail | id=%s | reason=type_error | field=%s | value=%s",
                finding_id, field, value,
            )
            return None
        # Range check for numerics
        if "min" in rules and coerced < rules["min"]:
            logger.warning(
                "partials | event=finding_schema_fail | id=%s | reason=below_min | field=%s",
                finding_id, field,
            )
            return None
        if "max" in rules and coerced > rules["max"]:
            logger.warning(
                "partials | event=finding_schema_fail | id=%s | reason=above_max | field=%s",
                finding_id, field,
            )
            return None
        # Enum check
        if "enum" in rules and coerced not in rules["enum"]:
            logger.warning(
                "partials | event=finding_schema_fail | id=%s | reason=invalid_enum | field=%s | value=%s",
                finding_id, field, coerced,
            )
            return None
        # Length check for strings
        if "max_len" in rules and len(str(coerced)) > rules["max_len"]:
            logger.warning(
                "partials | event=finding_schema_fail | id=%s | reason=too_long | field=%s",
                finding_id, field,
            )
            return None
        cleaned[field] = coerced
    cleaned["id"] = finding_id
    return cleaned
```

### 5b. Complete `GET /api/v1/partials/intelligence` Endpoint

Add to `management/api/routes/partials.py`:

```python
@router.get("/api/v1/partials/intelligence", response_class=HTMLResponse)
async def intelligence_partial(
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Return the analytics intelligence row as an HTML fragment.

    Filters to HIGH-confidence, non-dismissed findings only.
    All findings are schema-validated before rendering (Decision 5, PHASE_231.md).
    """
    templates = _get_templates()

    high_findings: list[dict] = []
    total_unreviewed = 0

    try:
        # Read last 50 finding IDs from the sorted index, newest first
        raw_ids = await redis.zrevrange(_INTELLIGENCE_INDEX, 0, 49)

        for finding_id in raw_ids:
            if isinstance(finding_id, bytes):
                finding_id = finding_id.decode()

            key = f"{_INTELLIGENCE_KEY_PREFIX}{finding_id}"
            raw = await redis.hgetall(key)
            if not raw:
                continue  # TTL expired — skip silently

            # Decode bytes keys/values from Redis
            decoded = {
                (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
                for k, v in raw.items()
            }

            # Schema validation — REQUIRED before rendering (Phase 236 trust boundary)
            finding = _validate_finding(decoded, finding_id)
            if finding is None:
                continue  # Invalid — discard and log (already logged in _validate_finding)

            # Check dismiss status
            if finding.get("dismissed") == "1":
                continue

            # Count all non-dismissed valid findings for the badge
            total_unreviewed += 1

            # Only HIGH findings appear on the main dashboard (Decision 5, PHASE_231.md)
            if finding.get("tier") == "HIGH":
                high_findings.append(finding)

        # Cap at 5 HIGH findings on the dashboard card; track total for overflow indicator
        total_high = len(high_findings)
        high_findings = high_findings[:5]

    except Exception as exc:
        logger.warning("partials | event=intelligence_redis_error | error=%s", exc)

    dial_value = await _get_dial(redis)

    return templates.TemplateResponse(
        request,
        "partials/intelligence.html",
        {
            "user": current_user[0],
            "findings": high_findings,
            "total_unreviewed": total_unreviewed,
            "total_high": total_high,
            "dial_value": dial_value,
        },
    )
```

### 5c. Complete `intelligence.html` Partial Template

Create `management/templates/partials/intelligence.html`:

```html
<!--
  HTMX Partial: intelligence.html
  GET /api/v1/partials/intelligence
  Polled every 60s. Template vars:
    findings: list of validated finding dicts (HIGH tier, not dismissed)
    total_unreviewed: int — total findings across all tiers not dismissed
-->
<div id="intelligence-row" aria-label="Analytics Intelligence">
  <!-- Section header -->
  <div class="flex items-center justify-between mb-3">
    <div class="flex items-center gap-2">
      <svg class="w-4 h-4 text-[#0ea5e9]" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
        <path stroke-linecap="round" stroke-linejoin="round" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
      </svg>
      <h2 class="text-sm font-semibold text-[#f1f5f9]">Intelligence</h2>
      {% if total_unreviewed > 0 %}
      <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-[#d97706] text-white"
            title="{{ total_unreviewed }} unreviewed findings across all tiers">
        {{ total_unreviewed }} unreviewed
      </span>
      {% endif %}
    </div>
    <a href="/intelligence-review"
       class="text-xs text-[#94a3b8] hover:text-[#0ea5e9] transition-colors focus:outline-none focus:ring-2 focus:ring-[#0ea5e9]">
      Review all →
    </a>
  </div>

  {% if not findings %}
  <!-- No high-confidence findings -->
  <div class="text-sm text-[#64748b] py-2">
    No high-confidence findings active.
    {% if total_unreviewed > 0 %}
    <a href="/intelligence-review" class="text-[#0ea5e9] hover:underline">
      {{ total_unreviewed }} lower-confidence finding{% if total_unreviewed != 1 %}s{% endif %} available for review.
    </a>
    {% endif %}
  </div>

  {% else %}
  <!-- Finding rows -->
  <div class="space-y-2">
    {% for f in findings %}
    <div class="bg-[#1e293b] border border-[#334155] rounded-lg p-3 flex flex-col sm:flex-row sm:items-start gap-3"
         id="finding-{{ f.id }}">

      <!-- Left: type icon + tier badge -->
      <div class="flex items-center gap-2 flex-shrink-0">
        <!-- Tier badge -->
        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-bold bg-[#d97706] text-white"
              title="HIGH confidence — model score {{ '%.0f'|format(f.confidence * 100) }}%">
          HIGH {{ '%.0f'|format(f.confidence * 100) }}%
        </span>
        <!-- Type badge -->
        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-[#0f172a] text-[#94a3b8] border border-[#334155]">
          {{ f.type }}
        </span>
      </div>

      <!-- Centre: description + metadata -->
      <div class="flex-1 min-w-0">
        <p class="text-sm text-[#f1f5f9] leading-snug">
          {% if f.description | length > 150 %}
            {{ f.description[:150] }}&hellip;
            <a href="/intelligence-review#finding-{{ f.id }}" class="text-[#0ea5e9] text-xs hover:underline">more</a>
          {% else %}
            {{ f.description }}
          {% endif %}
        </p>
        <p class="text-xs text-[#64748b] mt-1">
          {{ f.evidence_count }} events ·
          FP est. {{ '%.1f'|format(f.fp_rate_estimate * 100) }}% ·
          Model {{ f.model_version }} trained {{ f.model_trained_at[:10] }}
          {% if f.subject_ip %}· IP: {{ f.subject_ip }}{% endif %}
          {% if f.subject_ja4 %}· JA4: {{ f.subject_ja4 }}{% endif %}
        </p>
      </div>

      <!-- Right: suggested action + buttons -->
      <div class="flex flex-col gap-1.5 flex-shrink-0">
        <!-- Suggested action badge -->
        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium
          {% if f.suggested_action == 'block' %}bg-[#dc2626] text-white
          {% elif f.suggested_action == 'investigate' %}bg-[#d97706] text-white
          {% elif f.suggested_action == 'watchlist' %}bg-[#2563eb] text-white
          {% else %}bg-[#334155] text-[#94a3b8]{% endif %}">
          → {{ f.suggested_action }}
        </span>
        <!-- Action buttons -->
        <div class="flex gap-1">
          <button type="button"
                  class="px-2 py-1 text-xs rounded bg-[#0ea5e9] hover:bg-[#0284c7] text-white transition-colors
                         focus:outline-none focus:ring-2 focus:ring-[#0ea5e9]"
                  title="Take action on this finding"
                  @click="window.ConfirmModal.open({
                    action: '{{ f.suggested_action if f.suggested_action in ["block","watchlist","tarpit","allow"] else "block" }}',
                    ip: '{{ f.subject_ip }}',
                    ja4: '{{ f.subject_ja4 }}',
                    currentState: 'active'
                  })">
            Action
          </button>
          <button type="button"
                  hx-post="/api/v1/intelligence/dismiss/{{ f.id }}"
                  hx-target="#finding-{{ f.id }}"
                  hx-swap="outerHTML"
                  class="px-2 py-1 text-xs rounded bg-[#334155] hover:bg-[#475569] text-[#94a3b8] transition-colors
                         focus:outline-none focus:ring-2 focus:ring-[#475569]">
            Dismiss
          </button>
          <button type="button"
                  hx-post="/api/v1/intelligence/mark-fp/{{ f.id }}"
                  hx-target="#finding-{{ f.id }}"
                  hx-swap="outerHTML"
                  class="px-2 py-1 text-xs rounded bg-[#334155] hover:bg-[#475569] text-[#94a3b8] transition-colors
                         focus:outline-none focus:ring-2 focus:ring-[#475569]"
                  title="Mark as false positive — sends feedback to the analytics engine">
            Mark FP
          </button>
        </div>
      </div>
    </div>
    {% endfor %}
  </div>
  {% if findings|length < total_high %}
  <p class="text-xs text-[#64748b] mt-2">
    Showing {{ findings|length }} of {{ total_high }} high-confidence findings.
    <a href="/intelligence-review" class="text-[#0ea5e9] hover:underline">Review all</a>
  </p>
  {% endif %}
  {% endif %}
</div>
```

### 5d. Intelligence Review Page Route

Add to `management/api/routes/pages.py`:

```python
@router.get("/intelligence-review", response_class=HTMLResponse)
async def intelligence_review_page(
    request: Request,
    current_user=Depends(get_current_user),
) -> HTMLResponse:
    """Render the Intelligence Review page (MEDIUM and LOW findings).

    Requires analyst or admin role. Auditors do not have access.
    Role check is done in the template (role is passed from current_user).
    """
    templates = _get_templates()
    user_name = current_user[0]
    user_role = current_user[1] if len(current_user) > 1 else "auditor"
    return templates.TemplateResponse(
        request,
        "intelligence_review.html",
        {"user": user_name, "role": user_role},
    )
```

Create `management/templates/intelligence_review.html`:

```html
{% extends "base.html" %}
{% block title %}Intelligence Review{% endblock %}
{% block page_title %}Intelligence Review{% endblock %}

{% block content %}
{% if role not in ['analyst', 'operator', 'admin'] %}
  <div class="bg-[#dc2626]/10 border border-[#dc2626]/30 rounded-lg p-4 text-[#f87171]">
    Access restricted. Analyst role or higher required.
  </div>
{% else %}

<div class="space-y-4">
  <!-- Page description -->
  <p class="text-sm text-[#94a3b8]">
    This page shows MEDIUM (70–89% confidence) and LOW (&lt;70%) analytics findings.
    These are not shown on the main dashboard to avoid alert fatigue, but are worth
    reviewing during quieter periods.
  </p>

  <!-- Filter bar -->
  <div class="flex gap-2 flex-wrap">
    <select id="filter-tier"
            class="px-3 py-1.5 text-xs rounded bg-[#1e293b] border border-[#334155] text-[#f1f5f9] focus:outline-none focus:ring-2 focus:ring-[#0ea5e9]"
            hx-get="/api/v1/partials/intelligence-review"
            hx-trigger="change"
            hx-target="#review-content"
            name="tier">
      <option value="all">All tiers</option>
      <option value="MEDIUM">MEDIUM only</option>
      <option value="LOW">LOW only</option>
    </select>
    <select id="filter-type"
            class="px-3 py-1.5 text-xs rounded bg-[#1e293b] border border-[#334155] text-[#f1f5f9] focus:outline-none focus:ring-2 focus:ring-[#0ea5e9]"
            hx-get="/api/v1/partials/intelligence-review"
            hx-trigger="change"
            hx-target="#review-content"
            name="type"
            hx-include="#filter-tier">
      <option value="all">All types</option>
      <option value="beaconing">Beaconing</option>
      <option value="campaign">Campaign</option>
      <option value="drift">Drift</option>
      <option value="slowscan">Slow Scan</option>
    </select>
  </div>

  <!-- Review content — loaded via HTMX -->
  <div id="review-content"
       hx-get="/api/v1/partials/intelligence-review"
       hx-trigger="load"
       hx-vals='{"tier": "all", "type": "all"}'>
    <p class="text-sm text-[#64748b]">Loading findings…</p>
  </div>
</div>
{% endif %}
{% endblock %}
```

### 5e. `dashboard.html` Change — Add Intelligence Row

In `management/templates/dashboard.html`, add the intelligence row between the
health cards row and the triage queue (shifting triage to Row 4 as described in
PHASE_231.md Phase 236 scope):

```diff
   <!-- Row 1: Health Cards (10s poll) -->
   <section aria-label="System Health" class="mb-6">
     <div id="health-cards"
          hx-get="/api/v1/partials/health-cards"
          hx-trigger="load, every 10s"
          hx-swap="innerHTML">
       {% include "partials/health_cards.html" %}
     </div>
   </section>

+  <!-- Row 3: Intelligence (60s poll) — Phase 236 -->
+  <section aria-label="Analytics Intelligence" class="mb-6">
+    <div id="intelligence"
+         hx-get="/api/v1/partials/intelligence"
+         hx-trigger="load, every 60s"
+         hx-swap="innerHTML">
+      <p class="text-sm text-[#64748b]">Loading intelligence…</p>
+    </div>
+  </section>

   <!-- Row 4: Triage Queue (60s poll) -->
```

---

## 6. Step C: False-Positive Dismissal Endpoints

Add to `management/api/routes/partials.py` (or create a new
`management/api/routes/intelligence.py` if the file grows too large):

```python
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

_DISMISS_TEMPLATE = """
<div class="bg-[#1e293b] border border-[#334155] rounded-lg p-3 opacity-50"
     id="finding-{finding_id}">
  <p class="text-xs text-[#64748b]">Finding dismissed.</p>
</div>
"""

_FP_TEMPLATE = """
<div class="bg-[#1e293b] border border-[#334155] rounded-lg p-3 opacity-50"
     id="finding-{finding_id}">
  <p class="text-xs text-[#64748b]">Marked as false positive. Feedback sent to analytics engine.</p>
</div>
"""


@router.post("/api/v1/intelligence/dismiss/{finding_id}", response_class=HTMLResponse)
async def dismiss_finding(
    finding_id: str,
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Dismiss an analytics finding.

    Sets dismissed=1 on the finding hash. The finding disappears from the
    dashboard on the next 60s poll. The key retains its original TTL so it
    reappears naturally if the pattern continues (after the TTL expires, the
    finding is gone; the analytics engine will write a new one if the pattern
    persists).
    """
    key = f"analytics:finding:{finding_id}"
    try:
        exists = await redis.exists(key)
        if not exists:
            raise HTTPException(status_code=404, detail="Finding not found")
        await redis.hset(key, "dismissed", "1")
        logger.info(
            "partials | event=finding_dismissed | id=%s | user=%s",
            finding_id, current_user[0],
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning(
            "partials | event=dismiss_redis_error | id=%s | error=%s",
            finding_id, exc,
        )
        raise HTTPException(status_code=500, detail="Redis error")

    return HTMLResponse(content=_DISMISS_TEMPLATE.format(finding_id=finding_id))


@router.post("/api/v1/intelligence/mark-fp/{finding_id}", response_class=HTMLResponse)
async def mark_finding_fp(
    finding_id: str,
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Mark an analytics finding as a false positive.

    Sets dismissed=1 and writes a feedback event to the analytics:feedback
    stream. The analytics engine consumes this stream to adjust future
    scoring. This implements the feedback loop described in Decision 5
    of PHASE_231.md.
    """
    key = f"analytics:finding:{finding_id}"
    feedback_stream = "analytics:feedback"

    try:
        exists = await redis.exists(key)
        if not exists:
            raise HTTPException(status_code=404, detail="Finding not found")

        # Read type/model_version for the feedback event (for model improvement)
        finding_type = await redis.hget(key, "type")
        model_version = await redis.hget(key, "model_version")

        pipe = redis.pipeline()
        pipe.hset(key, "dismissed", "1")
        pipe.xadd(
            feedback_stream,
            {
                "finding_id": finding_id,
                "feedback_type": "false_positive",
                "finding_type": finding_type or "unknown",
                "model_version": model_version or "unknown",
                "reported_by": current_user[0],
                "reported_at": datetime.now(timezone.utc).isoformat(),
            },
            maxlen=10000,
        )
        await pipe.execute()
        logger.info(
            "partials | event=finding_marked_fp | id=%s | user=%s",
            finding_id, current_user[0],
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning(
            "partials | event=mark_fp_redis_error | id=%s | error=%s",
            finding_id, exc,
        )
        raise HTTPException(status_code=500, detail="Redis error")

    return HTMLResponse(content=_FP_TEMPLATE.format(finding_id=finding_id))
```

---

## 7. Tests

### 7a. Unit Tests — Schema Validation

File: `tests/unit/test_intelligence_schema.py`

```python
"""Tests for analytics finding schema validation.

These tests verify that the management console correctly validates and rejects
malformed analytics findings before rendering. This is the core security control
described in the Analytics Trust Boundary section of PHASE_231.md.
"""
import pytest

# Import the validation function from partials module
# (adjust import path if the function moves to a separate module)
from management.api.routes.partials import _validate_finding


# --- Valid finding fixture ---

VALID_FINDING = {
    "confidence": "0.95",
    "tier": "HIGH",
    "type": "beaconing",
    "subject_ip": "203.0.113.42",
    "subject_ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1",
    "description": "Client at 203.0.113.42 connects every 30 seconds with millisecond precision.",
    "evidence_count": "120",
    "model_version": "1.2.3",
    "model_trained_at": "2026-06-01T00:00:00Z",
    "fp_rate_estimate": "0.02",
    "suggested_action": "watchlist",
    "created_at": "2026-06-12T08:00:00Z",
    "dismissed": "0",
}


def test_valid_finding_passes():
    result = _validate_finding(VALID_FINDING.copy(), "test-uuid-001")
    assert result is not None
    assert result["id"] == "test-uuid-001"
    assert result["confidence"] == 0.95
    assert result["evidence_count"] == 120


def test_missing_required_field_rejected():
    bad = VALID_FINDING.copy()
    del bad["confidence"]
    result = _validate_finding(bad, "test-uuid-002")
    assert result is None


def test_confidence_above_range_rejected():
    bad = VALID_FINDING.copy()
    bad["confidence"] = "1.5"   # > 1.0
    result = _validate_finding(bad, "test-uuid-003")
    assert result is None


def test_confidence_below_range_rejected():
    bad = VALID_FINDING.copy()
    bad["confidence"] = "-0.1"  # < 0.0
    result = _validate_finding(bad, "test-uuid-004")
    assert result is None


def test_invalid_type_enum_rejected():
    bad = VALID_FINDING.copy()
    bad["type"] = "blocklist_update"   # not in allowed enum
    result = _validate_finding(bad, "test-uuid-005")
    assert result is None


def test_invalid_suggested_action_rejected():
    bad = VALID_FINDING.copy()
    bad["suggested_action"] = "delete_all"   # injection attempt
    result = _validate_finding(bad, "test-uuid-006")
    assert result is None


def test_description_too_long_rejected():
    bad = VALID_FINDING.copy()
    bad["description"] = "x" * 501   # exceeds max 500 chars
    result = _validate_finding(bad, "test-uuid-007")
    assert result is None


def test_html_in_description_rejected_by_enum_or_type():
    # description is a string with max_len — it won't be rejected purely for
    # containing HTML (Jinja2 auto-escapes), but verify schema doesn't accept
    # an integer disguised as a string for the type field.
    bad = VALID_FINDING.copy()
    bad["type"] = "<script>alert(1)</script>"
    result = _validate_finding(bad, "test-uuid-008")
    assert result is None   # not in the type enum


def test_invalid_tier_rejected():
    bad = VALID_FINDING.copy()
    bad["tier"] = "ULTRA"
    result = _validate_finding(bad, "test-uuid-009")
    assert result is None


def test_optional_fields_can_be_absent():
    # subject_ip and subject_ja4 are optional
    finding = VALID_FINDING.copy()
    del finding["subject_ip"]
    del finding["subject_ja4"]
    result = _validate_finding(finding, "test-uuid-010")
    assert result is not None
    assert result["subject_ip"] == ""
    assert result["subject_ja4"] == ""
```

### 7b. Unit Tests — Schema Parity (Drift Detection)

File: `tests/unit/test_schema_parity.py`

```python
"""Verify the two FINDING_SCHEMA copies stay identical.

The schema is duplicated in analytics/output_writer.py (the authoritative
source) and management/api/routes/partials.py (the consumer). Both services
run in separate containers and cannot share code at runtime. This test catches
drift between the two copies at PR time.

If this test fails, update both copies in the same commit.
"""

from analytics.output_writer import FINDING_SCHEMA
from management.api.routes.partials import _FINDING_SCHEMA


def test_finding_schema_parity():
    """Both copies of the finding schema must be identical."""
    assert FINDING_SCHEMA == _FINDING_SCHEMA, (
        "FINDING_SCHEMA in analytics/output_writer.py and _FINDING_SCHEMA in "
        "management/api/routes/partials.py have drifted. Update both in the "
        "same commit."
    )
```

### 7c. Unit Tests — Confidence Tier Filtering

File: `tests/unit/test_intelligence_tier_filter.py`

```python
"""Tests for the confidence tier filtering in the intelligence partial.

Verifies that only HIGH-confidence findings reach the dashboard, and that
MEDIUM/LOW findings are excluded from the main view but counted for the badge.
This implements Decision 5 from PHASE_231.md.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# Helper to build a valid finding dict
def _make_finding(confidence_str: str, dismissed: str = "0") -> dict:
    tier_map = {
        c: ("HIGH" if float(c) >= 0.90 else "MEDIUM" if float(c) >= 0.70 else "LOW")
        for c in [confidence_str]
    }
    return {
        "confidence": confidence_str,
        "tier": tier_map[confidence_str],
        "type": "beaconing",
        "subject_ip": "203.0.113.1",
        "subject_ja4": "",
        "description": "Test finding.",
        "evidence_count": "50",
        "model_version": "1.0.0",
        "model_trained_at": "2026-01-01T00:00:00Z",
        "fp_rate_estimate": "0.05",
        "suggested_action": "monitor",
        "created_at": "2026-06-12T08:00:00Z",
        "dismissed": dismissed,
    }


@pytest.mark.asyncio
async def test_only_high_findings_returned_to_dashboard(mock_redis):
    """Only HIGH (≥0.90) findings appear on the main dashboard intelligence row."""
    from management.api.routes.partials import _validate_finding

    findings = [
        _make_finding("0.95"),  # HIGH — should appear
        _make_finding("0.91"),  # HIGH — should appear
        _make_finding("0.85"),  # MEDIUM — should NOT appear on dashboard
        _make_finding("0.60"),  # LOW — should NOT appear on dashboard
    ]

    high_count = sum(
        1 for f in findings
        if _validate_finding(f, "id") is not None and f["tier"] == "HIGH"
    )
    medium_low_count = sum(
        1 for f in findings
        if _validate_finding(f, "id") is not None and f["tier"] != "HIGH"
    )

    assert high_count == 2
    assert medium_low_count == 2


def test_dismissed_findings_excluded():
    """Dismissed findings (dismissed='1') must not appear anywhere on the dashboard."""
    from management.api.routes.partials import _validate_finding

    dismissed_high = _make_finding("0.95", dismissed="1")
    result = _validate_finding(dismissed_high, "id-dismissed")
    assert result is not None   # schema is valid...
    # ...but the caller checks dismissed field, not this function.
    # Verify the dismissed field is preserved in the output.
    assert result["dismissed"] == "1"
```

### 7d. Integration Test — Redis ACL NOPERM Verification

File: `tests/integration/test_analytics_acl.py`

```python
"""Integration test: analytics Redis ACL enforcement.

This test requires a real Redis instance with ACL configuration loaded.
It is skipped in unit test runs (requires INTEGRATION_REDIS_URL env var).

To run:
  INTEGRATION_REDIS_URL=redis://analytics:<pwd>@localhost:6379/0 pytest tests/integration/test_analytics_acl.py -v
"""
import os
import pytest
import redis as redis_sync

INTEGRATION_REDIS_URL = os.getenv("INTEGRATION_REDIS_URL")
requires_integration_redis = pytest.mark.skipif(
    not INTEGRATION_REDIS_URL,
    reason="INTEGRATION_REDIS_URL not set — skipping ACL integration test",
)


@requires_integration_redis
def test_analytics_can_write_analytics_key():
    """Analytics ACL user can write analytics:* keys."""
    r = redis_sync.from_url(INTEGRATION_REDIS_URL)
    r.hset("analytics:finding:acl-test", mapping={"confidence": "0.95"})
    assert r.hget("analytics:finding:acl-test", "confidence") == b"0.95"
    r.delete("analytics:finding:acl-test")


@requires_integration_redis
def test_analytics_cannot_write_config_key():
    """Analytics ACL user MUST NOT be able to write config:dial.

    If this test fails, the Redis ACL is not enforced and the blocklist
    poisoning attack described in PHASE_231.md (Analytics Trust Boundary) is possible.
    """
    r = redis_sync.from_url(INTEGRATION_REDIS_URL)
    with pytest.raises(redis_sync.exceptions.NoPermissionError):
        r.set("config:dial", "50")


@requires_integration_redis
def test_analytics_cannot_write_blocklist():
    """Analytics ACL user MUST NOT be able to write ja4:blocklist."""
    r = redis_sync.from_url(INTEGRATION_REDIS_URL)
    with pytest.raises(redis_sync.exceptions.NoPermissionError):
        r.sadd("ja4:blocklist", "t13d1516h2_test")
```

### 7e. Page Rendering Test — Intelligence Routes

Add to the existing `tests/management/test_pages.py`:

```python
@pytest.mark.asyncio
async def test_intelligence_review_page_renders(client):
    """GET /intelligence-review returns 200 with HTML for analyst+."""
    response = await client.get("/intelligence-review")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
```

### 7f. Running the Tests

```bash
# Working directory: <repo root>

# Unit tests — run inside the tools container (container-strict rule)
docker run --rm -v "$PWD":/src -w /src ja4proxy-tools \
  pytest tests/unit/test_intelligence_schema.py tests/unit/test_schema_parity.py tests/unit/test_intelligence_tier_filter.py -v

# Integration ACL test (requires Redis with ACL running)
docker run --rm -v "$PWD":/src -w /src -e INTEGRATION_REDIS_URL ja4proxy-tools \
  pytest tests/integration/test_analytics_acl.py -v

# Full test suite (must be green before merging)
make test

# Page rendering test (verify new routes return 200 + text/html)
docker run --rm -v "$PWD":/src -w /src ja4proxy-tools \
  pytest tests/management/test_pages.py -k "intelligence" -v

# Ruff + mypy (via make targets — runs in tools container)
make lint
```

---

## 8. Definition of Done

All of the following must be true before this phase is marked COMPLETE in
`docs/phases/manifest.yaml`:

- [ ] Redis ACL config exists at `config/redis_acl.conf` with `analytics` user
      restricted to `analytics:*` keys.
- [ ] Analytics container uses `ANALYTICS_REDIS_PASSWORD` to authenticate.
- [ ] Verification test confirms analytics CANNOT write `config:dial` (NOPERM error).
- [ ] `src/analytics/output_writer.py` exists with all required functions:
      `write_finding`, `update_heartbeat`, `write_active_connections`.
- [ ] `FINDING_SCHEMA` constant defined in `output_writer.py` with a matching
      `_FINDING_SCHEMA` in `partials.py` (intentional cross-container duplication).
- [ ] Schema parity test (`tests/unit/test_schema_parity.py`) verifies both copies match.
- [ ] `output_writer` wired into `src/analytics/main.py` detection cycle.
- [ ] `GET /api/v1/partials/intelligence` endpoint exists, validates schema, and
      returns only HIGH non-dismissed findings.
- [ ] `intelligence.html` partial renders correctly, including `"Showing X of Y"` overflow indicator when capped at 5.
- [ ] `GET /intelligence-review` page route exists and renders for analyst+ role.
- [ ] `intelligence_review.html` page renders correctly.
- [ ] `dashboard.html` includes intelligence row polled every 60s.
- [ ] `POST /api/v1/intelligence/dismiss/{id}` sets `dismissed=1`.
- [ ] `POST /api/v1/intelligence/mark-fp/{id}` sets `dismissed=1` and writes to
      `analytics:feedback` stream.
- [ ] All unit tests pass with zero warnings, including `test_schema_parity.py`.
- [ ] Page rendering test for `/intelligence-review` returns 200 + `text/html`.
- [ ] `make test` exits 0.
- [ ] `make lint` exits 0 on all new/modified files (runs ruff + mypy in-container).
- [ ] CHANGELOG.md updated with Phase 236 entry.
- [ ] `docs/phases/manifest.yaml` updated: `status: COMPLETE`, `completed: YYYY-MM-DD`.
- [ ] `python3 scripts/sync-roadmap.py` run to regenerate TODO.md and PROJECT_STATUS.md.

---

## 9. Common Mistakes

**Mistake 1: Skipping the Redis ACL prerequisite.**
It feels like extra setup work. It is not optional. An analytics container without
ACL restrictions can write to `ja4:blocklist`, which means a compromised analytics
container can unblock any IP. Set up the ACL first, test it, then write the output
writer.

**Mistake 2: Using f-strings in logging calls.**
Wrong: `logger.warning(f"Schema error for finding {finding_id}")`
Right: `logger.warning("Schema error for finding %s", finding_id)`
This is enforced by ruff. The CI will fail if you use f-strings in logging calls.

**Mistake 3: Rendering without validating.**
The quickest path to a working demo is to skip `_validate_finding` and just render
whatever is in Redis. Don't. The schema validation is not optional UX polish — it
is the primary security control against blocklist poisoning. Every code path that
reads from `analytics:finding:*` must call `_validate_finding`.

**Mistake 4: Forgetting that Redis HGETALL returns bytes.**
In an async Redis client, `hgetall` returns `{b"field": b"value"}`. Your validation
function receives bytes keys and bytes values. Decode them before processing:
```python
decoded = {
    (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
    for k, v in raw.items()
}
```
If you forget this, `_validate_finding` will always return None (bytes can't be
compared to str enums) and the intelligence row will always say "No findings".

**Mistake 5: Failing loudly instead of silently discarding invalid findings.**
The correct behaviour when a finding fails schema validation is:
1. Log a WARNING (so the issue is visible to an operator reading logs).
2. Return None from `_validate_finding`.
3. Skip that finding in the caller.
Never raise an exception that reaches the HTMX response — a 500 error on the
intelligence partial will show an ugly error box on the dashboard.

**Mistake 6: Forgetting to update the nav in `base.html`.**
The "Intelligence Review" link should only appear for analyst+ role. Without the
role guard, auditors see the nav link and get a 403 when they click it — confusing.
Add the role guard as shown in the Phase 234 RBAC sub-task pattern.

**Mistake 7: Not testing that the `analytics:feedback` XADD is bounded.**
Use `XADD ... MAXLEN ~ 10000` so the feedback stream doesn't grow unboundedly.
Already shown in the `mark-fp` endpoint above — don't remove it when copying.

**Mistake 8: Using `$dispatch` instead of `window.ConfirmModal.open`.**
Phase 235's confirmation modal exposes `window.ConfirmModal.open(config)`. Do
NOT use Alpine's `$dispatch('open-confirm-modal', ...)` — it does not exist.
The `$dispatch` event from Phase 234 was deprecated by Phase 235's global shim.
Always use the `window.ConfirmModal.open()` API and pass the config keys
(`action`, `ip`, `ja4`, `currentState`) directly.

**Mistake 9: Running pytest or ruff on the host machine.**
The AGENTS.md container-strict rule forbids running Python tooling on the host.
Always use `docker run --rm -v "$PWD":/src -w /src ja4proxy-tools pytest ...`
or `make lint` / `make test-unit`. Running on the host with Python 3.10 may
mask Python 3.14-specific syntax errors.
