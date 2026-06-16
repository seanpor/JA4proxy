---
phase: 234
title: Dashboard — Threat Posture & Infrastructure Rows
status: IN_PROGRESS
size: LARGE
created: 2026-06-12
audience: [developer, operator, secops]
dependencies: [231, 233]
---

# Dashboard — Threat Posture & Infrastructure Rows

> **Before you touch a line of code**, read `docs/phases/PHASE_231.md`.
> Every design decision in this phase is cited by number from that document
> (e.g. "Decision 1", "Decision 4"). If you disagree with a decision, raise it
> in a PR comment — do not silently implement a different approach.

---

## 1. Plain-English Goal

**What will the dashboard look like after this phase?**

Right now, the Management Console dashboard has two things: a row of four health
cards (Redis status, active bans, dial setting, events/min) and a live connection
feed. If an analyst is paged at 2 AM with "something is attacking us", they have
to leave the dashboard, open Redis CLI, and write their own queries to find out
*what* is happening.

After this phase, the dashboard answers the most critical incident-response
questions without leaving the browser:

- **Who are the top 10 attacking IPs right now?** (Threat Posture row)
- **Which JA4 fingerprints are appearing the most?** (Threat Posture row)
- **What fraction of connections are being blocked vs allowed?** (action distribution bar)
- **Is the proxy running? Is analytics running? Is Redis running out of memory?** (Infrastructure row)
- **Are there any suspicious IPs that the system hasn't decided to block yet?** (Triage Queue)

A non-technical manager watching over your shoulder would see:
- A colour-coded strip at the top showing "NOMINAL / ELEVATED / ACTIVE"
  (Decision 1, delivered in Phase 232 — already done by the time you start this phase)
- A "Threat Posture" panel with two tables: Top 10 Source IPs and Top 10 JA4
  Fingerprints, each with action badges and a timestamp
- A row of service health indicators: Redis memory bar, analytics status,
  tarpit status, HAProxy backend status
- A "Needs Decision" triage list of IPs that are suspicious but not yet blocked,
  with one-click Block / Watchlist / Dismiss buttons

---

## 2. Background

### 2.1 What is RBAC and why does showing controls to people who can't use them matter?

RBAC stands for **Role-Based Access Control**. In this project (see `management/api/models.py`
lines 16–23 and `management/api/auth.py`), there are four roles in ascending order of
permission:

| Role | Can do |
|------|--------|
| `auditor` | Read-only access to logs and connection history |
| `analyst` | Read + query connections and fingerprints |
| `operator` | Block IPs, change the dial, manage lists |
| `admin` | Everything an operator can do + manage users and tokens |

**The problem today:** `pages.py` passes only `current_user[0]` (the username string)
to every Jinja2 template. The role is never sent. This means every authenticated
user sees every navigation item, every Block button, and every list-management form —
regardless of whether their role permits those actions.

The *API* correctly rejects unauthorised requests with a 403. But showing controls
that always fail is:
1. **Confusing** — an auditor tries to click Block, gets a cryptic error
2. **A UI security smell** — enterprise auditors note "controls visible to users
   who can't use them" as a finding in access reviews
3. **Inconsistent** — the API enforces it but the UI ignores it

**The fix (Sub-task A):** Pass `role` alongside `username` in every page template
context, then use Jinja2 conditionals to hide controls the current user cannot use.

### 2.2 What is a sorted set in Redis and why does it help answer "top 10" questions?

A Redis **sorted set** (`ZADD`, `ZRANGE`, `ZRANGEBYSCORE`) stores members (strings)
each with a floating-point **score**. Members are always kept in score order. This
makes it extremely fast to ask "give me the top 10 by score" or "give me all members
with a score between 35 and 65".

In this project, the `events:connection` key is a **stream** (not a sorted set) — it
is an append-only log. To find the top 10 IPs, we must:
1. Read recent events from the stream
2. Group them by IP, computing the max risk score per IP
3. Sort and take the top 10

This is done in Python in the endpoint, not in Redis. For Phase 234 this is
acceptable (stream depth is capped at 100,000 events by Phase 233). A future phase
can add a Redis sorted set maintained by the proxy for O(log N) lookups.

The **triage queue** (Sub-task D) does use a sorted set conceptually:
`ZRANGEBYSCORE config:triage_range` — but in practice we read the triage min/max
threshold from a plain Redis string, then do the score filtering in Python.

### 2.3 What does XREVRANGE do?

`XREVRANGE` reads a Redis stream **in reverse order** (newest first). It takes:
- The stream key (`events:connection`)
- A start ID (`+` means the most recent possible entry)
- An end ID (either `-` meaning the oldest, or a specific stream ID)
- An optional `COUNT` to limit results

When you want "the last N events" or "all events in the last 15 minutes":
```
XREVRANGE events:connection + <timestamp_15_minutes_ago> COUNT 5000
```
This is more efficient than `XRANGE` (oldest-first) because you stop as soon as
you've collected enough recent events without scanning old ones.

In the `redis-py` async client (used in this project), the call is:
```python
entries = await redis.xrevrange("events:connection", max="+", min=min_id, count=5000)
```
Each entry is a tuple `(stream_id, fields_dict)`. The stream ID is a string like
`"1749711234567-0"` — the first part is a Unix timestamp in milliseconds.

**Payload shape (important):** `fields_dict` has exactly **one** key, `"event"`,
whose value is a JSON string the Go proxy writes (`cmd/ja4pd/main.go`). That JSON
uses flat, dot-delimited ECS keys — `event.action`, `event.risk_score`,
`source.ip`, `ja4proxy.fingerprint.ja4`, `ja4proxy.sni`, `@timestamp`. You must
`json.loads(fields["event"])` and then index the literal dotted strings
(`ev["source.ip"]`) — they are **not** top-level stream fields and **not** nested
objects (`ev["source"]["ip"]` would `KeyError`).

### 2.4 Why poll with HTMX every 30 seconds instead of SSE?

The live feed (already implemented) uses **Server-Sent Events (SSE)**: the server
keeps an HTTP connection open and pushes each new event to the browser the moment
it arrives. This is ideal for the live feed because latency matters and events
arrive continuously.

The new dashboard rows (Threat Posture, Infrastructure, Triage Queue) use
**polling** instead: HTMX sends a new GET request every N seconds and replaces
the HTML fragment. Why the difference?

| | SSE | HTMX polling |
|---|---|---|
| Server load per row | Persistent open connection | Brief request every N seconds |
| Cost to compute | Cheap — just relay stream events | Expensive — full top-N aggregation |
| Latency | Sub-second | 30–60 seconds |
| Best for | High-frequency, low-compute events | Aggregated summaries (top-N, counts) |

The Threat Posture aggregation (top-N IPs, top-N JA4, action distribution) requires
reading potentially thousands of stream events and doing grouping/sorting. Doing this
computation 30–60 times per second (SSE push frequency) would make Redis and the
Python server hot. Polling every 30 seconds is a reasonable trade-off for a
"situational awareness" panel.

### 2.5 What is a triage queue and why do slow-burn attackers stay below the block threshold?

**Triage queue:** A list of IPs that are scoring in the "grey zone" — suspicious
enough to notice but not conclusively bad enough to block automatically.

**Why slow-burn attackers deliberately stay below the threshold:**
A smart attacker knows that JA4proxy (and most proxy systems) block based on a
threshold score. If the threshold is 70, they keep their score at 45 — just enough
activity to probe the target without triggering automated blocking. They may:
- Space their connections minutes apart (low frequency = lower frequency signal)
- Rotate their JA4 fingerprint occasionally
- Avoid known-bad TI feed IPs

These "grey zone" IPs accumulate over hours or days. Without the triage queue,
an analyst would only discover them by reading the raw stream — which nobody does
at 2 AM. The triage queue surfaces exactly these IPs: score 35–65, at least 50
connections in 24h, not on any list, score trending upward.

Per **Decision 5** in `PHASE_231.md`: the triage queue sits on the main dashboard
(not a separate page) because it must be in the primary incident response view.

---

## 3. Sub-task A: Fix the RBAC UI Gap (Finding M-1)

### 3.1 What pages.py does wrong today

Look at `management/api/routes/pages.py` lines 65–74:
```python
@router.get("/", response_class=HTMLResponse)
async def dashboard_page(
    request: Request,
    current_user=Depends(get_current_user),
) -> HTMLResponse:
    templates = _get_templates()
    return templates.TemplateResponse(
        request, "dashboard.html", {"user": current_user[0]}  # ← BUG: only [0]
    )
```

`get_current_user` (in `auth.py`) returns a `Tuple[str, Role]`. Index `[0]` is the
username; index `[1]` is the role. Every page route does this — so the role is
silently discarded on every page render.

### 3.2 The fix — extract_user_and_role helper + update all routes

**File:** `management/api/routes/pages.py`

```diff
+def _extract_user_and_role(current_user) -> tuple[str, str]:
+    """Extract username and role string from the auth tuple.
+
+    get_current_user() returns (username, Role). This helper unpacks the
+    tuple and returns both values, converting Role to its string value
+    so Jinja2 templates can use simple string comparisons.
+    """
+    username = current_user[0]
+    role = current_user[1].value  # Role is a str Enum; .value gives 'auditor' etc.
+    return username, role
+

 @router.get("/", response_class=HTMLResponse)
 async def dashboard_page(
     request: Request,
     current_user=Depends(get_current_user),
 ) -> HTMLResponse:
     """Render the main dashboard page."""
     templates = _get_templates()
+    user, role = _extract_user_and_role(current_user)
     return templates.TemplateResponse(
-        request, "dashboard.html", {"user": current_user[0]}
+        request, "dashboard.html", {"user": user, "role": role}
     )

 @router.get("/lists", response_class=HTMLResponse)
 async def lists_page(
     request: Request,
     current_user=Depends(get_current_user),
 ) -> HTMLResponse:
     """Render the JA4 / IP list management page."""
     templates = _get_templates()
+    user, role = _extract_user_and_role(current_user)
     return templates.TemplateResponse(
-        request, "lists.html", {"user": current_user[0]}
+        request, "lists.html", {"user": user, "role": role}
     )

 @router.get("/bans", response_class=HTMLResponse)
 async def bans_page(
     request: Request,
     current_user=Depends(get_current_user),
 ) -> HTMLResponse:
     """Render the active bans management page."""
     templates = _get_templates()
+    user, role = _extract_user_and_role(current_user)
     return templates.TemplateResponse(
-        request, "bans.html", {"user": current_user[0]}
+        request, "bans.html", {"user": user, "role": role}
     )

 @router.get("/audit", response_class=HTMLResponse)
 async def audit_page(
     request: Request,
     current_user=Depends(get_current_user),
 ) -> HTMLResponse:
     """Render the audit log page."""
     templates = _get_templates()
+    user, role = _extract_user_and_role(current_user)
     return templates.TemplateResponse(
-        request, "audit.html", {"user": current_user[0]}
+        request, "audit.html", {"user": user, "role": role}
     )

 @router.get("/threat-intel", response_class=HTMLResponse)
 async def threat_intel_page(
     request: Request,
     current_user=Depends(get_current_user),
 ) -> HTMLResponse:
     """Render the Phase 85 threat intelligence feeds page."""
     templates = _get_templates()
+    user, role = _extract_user_and_role(current_user)
     return templates.TemplateResponse(
-        request, "threat_intel.html", {"user": current_user[0]}
+        request, "threat_intel.html", {"user": user, "role": role}
     )
```

### 3.3 Jinja2 template conditionals

The Jinja2 pattern for role-gating is:

```jinja2
{# Show nav item only to operators and admins #}
{% if role in ['operator', 'admin'] %}
  <a href="/lists">Lists</a>
{% endif %}

{# Show item to analyst, operator, and admin (not auditor) #}
{% if role in ['analyst', 'operator', 'admin'] %}
  <a href="/connections">Connections</a>
{% endif %}
```

Note: `role` is a plain string in the template (e.g. `'operator'`), not a Python
enum object. That is why `_extract_user_and_role` calls `.value`.

### 3.4 Role/feature matrix

Apply the following guards to `management/templates/base.html`:

| Feature / Control | auditor | analyst | operator | admin |
|---|---|---|---|---|
| Dashboard (read) | ✅ | ✅ | ✅ | ✅ |
| Live feed (read) | ✅ | ✅ | ✅ | ✅ |
| Audit log | ✅ | ✅ | ✅ | ✅ |
| Connections / fingerprints | ❌ | ✅ | ✅ | ✅ |
| Threat Intel feeds page | ❌ | ✅ | ✅ | ✅ |
| Lists page (read) | ❌ | ✅ | ✅ | ✅ |
| Lists page (add/remove) | ❌ | ❌ | ✅ | ✅ |
| Bans page (read) | ❌ | ✅ | ✅ | ✅ |
| Block / Tarpit / Allow buttons | ❌ | ❌ | ✅ | ✅ |
| Dial change control | ❌ | ❌ | ✅ | ✅ |
| Triage queue Block/Watchlist | ❌ | ❌ | ✅ | ✅ |
| Triage queue Dismiss | ❌ | ✅ | ✅ | ✅ |
| Token management | ❌ | ❌ | ❌ | ✅ |

**Specific nav items and buttons to hide in `base.html`:**

```jinja2
{# Nav: Lists link — operator+ only #}
{% if role in ['operator', 'admin'] %}
<li><a href="/lists" ...>Lists</a></li>
{% endif %}

{# Nav: Bans link — analyst+ #}
{% if role in ['analyst', 'operator', 'admin'] %}
<li><a href="/bans" ...>Bans</a></li>
{% endif %}

{# Nav: Connections link — analyst+ #}
{% if role in ['analyst', 'operator', 'admin'] %}
<li><a href="/connections" ...>Connections</a></li>
{% endif %}

{# Nav: Token management — admin only #}
{% if role == 'admin' %}
<li><a href="/tokens" ...>Tokens</a></li>
{% endif %}

{# Dial change form submit button — operator+ only #}
{% if role in ['operator', 'admin'] %}
<button type="submit" ...>Update Dial</button>
{% else %}
<p class="text-xs text-slate-500">Read-only — operator role required to change</p>
{% endif %}
```

### 3.5 Tests for RBAC template rendering

These tests go in `tests/unit/test_pages_rbac.py`:

```python
"""
tests/unit/test_pages_rbac.py
Test that each role sees the correct nav items and action controls.
"""
import pytest
from httpx import AsyncClient
from management.api.main import create_app
from management.api.auth import _create_access_token


@pytest.mark.asyncio
@pytest.mark.parametrize("role,expect_lists_nav,expect_block_btn", [
    ("auditor",  False, False),
    ("analyst",  False, False),
    ("operator", True,  True),
    ("admin",    True,  True),
])
async def test_dashboard_role_visibility(role, expect_lists_nav, expect_block_btn):
    """Log in as each role; assert correct nav items visible."""
    app = create_app()
    token = _create_access_token("testuser", role=role)
    async with AsyncClient(app=app, base_url="http://test") as client:
        resp = await client.get("/", cookies={"token": token})
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Dashboard" in resp.text   # landmark string

    if expect_lists_nav:
        assert 'href="/lists"' in resp.text, f"role={role} should see Lists nav"
    else:
        assert 'href="/lists"' not in resp.text, f"role={role} should NOT see Lists nav"

    if expect_block_btn:
        # Operator+ see the dial update button
        assert 'Update Dial' in resp.text, f"role={role} should see dial update"
    else:
        assert 'Update Dial' not in resp.text, f"role={role} should NOT see dial update"


@pytest.mark.asyncio
async def test_unauthenticated_dashboard_never_500():
    """Unauthenticated dashboard request must not 500."""
    app = create_app()
    async with AsyncClient(app=app, base_url="http://test") as client:
        resp = await client.get("/")
    assert resp.status_code < 500


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["auditor", "analyst", "operator", "admin"])
async def test_all_pages_render_200_for_all_roles(role):
    """Every page route returns 200 + text/html for all roles."""
    app = create_app()
    token = _create_access_token("testuser", role=role)
    routes = ["/", "/audit"]
    # Lists, bans require operator+; test separately
    async with AsyncClient(app=app, base_url="http://test") as client:
        for route in routes:
            resp = await client.get(route, cookies={"token": token})
            assert resp.status_code == 200, f"route={route} role={role}"
            assert "text/html" in resp.headers["content-type"]
```

**Run the tests (from project root):**
```bash
# Working directory: <repo root>
make test-unit  # runs all unit tests in the pinned tools container (AGENTS.md § Container-Strict)
# Or for targeted feedback:
docker run --rm -v "$PWD":/src -w /src ja4proxy-tools \
  python -m pytest tests/unit/test_pages_rbac.py -v --timeout=30
```

---

## 4. Sub-task B: Threat Posture Row

### 4.1 Background — time window to Redis stream ID conversion

The stream uses IDs in the format `<milliseconds_since_epoch>-<sequence>`. To query
"all events in the last 15 minutes", compute:

```python
import time
min_ms = int((time.time() - 15 * 60) * 1000)  # 15 minutes ago in ms
min_id = f"{min_ms}-0"
# XREVRANGE events:connection + <min_id>
```

### 4.2 The complete endpoint

**File:** `management/api/routes/partials.py` — add after the existing routes.

```python
import json
import time
from collections import defaultdict

# ── Threat Posture constants ────────────────────────────────────────────────────
_STREAM_KEY = "events:connection"   # the Go proxy's per-connection event stream (cmd/ja4pd/main.go)
_JA4_LABELS_KEY = "config:ja4_labels"   # Redis hash: ja4_hash -> human label

# Each stream entry has ONE field, "event", whose value is a JSON string of
# FLAT, dot-delimited ECS keys (cmd/ja4pd/main.go builds it). Parse the JSON,
# then index the literal dotted keys — they are NOT top-level stream fields and
# NOT nested objects:
#   event.action  event.risk_score  source.ip  source.port
#   ja4proxy.fingerprint.ja4  ja4proxy.sni  ja4proxy.dial_setting  @timestamp

_WINDOW_SECONDS: dict[str, int] = {
    "5m":  5 * 60,
    "15m": 15 * 60,
    "1h":  60 * 60,
    "24h": 24 * 60 * 60,
}
_DEFAULT_WINDOW = "15m"
# Must match the proxy's event.action vocabulary (cmd/ja4pd/main.go).
_VALID_ACTIONS = {"allow", "flag", "rate_limit", "tarpit", "block", "ban"}


def _window_min_id(seconds: int) -> str:
    """Return the Redis stream ID for 'seconds ago'."""
    min_ms = int((time.time() - seconds) * 1000)
    return f"{min_ms}-0"


@router.get("/api/v1/partials/threat-posture", response_class=HTMLResponse)
async def threat_posture_partial(
    request: Request,
    window: str = Query(_DEFAULT_WINDOW, description="Time window: 5m|15m|1h|24h"),
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Return the Threat Posture row as an HTML fragment.

    Reads the event stream for the selected time window and computes:
    - Top 10 source IPs by maximum risk score
    - Top 10 JA4 fingerprints by connection count
    - Action distribution (counts and percentages)
    - Stream depth (XLEN)

    Polled every 30 seconds by the dashboard (hx-trigger="every 30s").
    """
    templates = _get_templates()

    if window not in _WINDOW_SECONDS:
        window = _DEFAULT_WINDOW
    window_secs = _WINDOW_SECONDS[window]
    min_id = _window_min_id(window_secs)

    # Accumulators
    ip_scores: dict[str, float] = {}        # ip -> max score seen
    ip_actions: dict[str, str] = {}          # ip -> most recent action
    ip_counts: dict[str, int] = defaultdict(int)
    ja4_counts: dict[str, int] = defaultdict(int)
    action_dist: dict[str, int] = defaultdict(int)
    stream_depth = 0
    total_events = 0

    try:
        # XREVRANGE reads newest-first; stop at min_id (15 min ago)
        raw = await redis.xrevrange(_STREAM_KEY, max="+", min=min_id, count=5000)

        for _entry_id, fields in raw:
            total_events += 1
            raw_event = fields.get("event")
            if not raw_event:
                continue
            try:
                ev = json.loads(raw_event)
            except (ValueError, TypeError):
                continue
            ip = ev.get("source.ip", "")
            ja4 = ev.get("ja4proxy.fingerprint.ja4", "")
            action = ev.get("event.action", "")
            risk_raw = ev.get("event.risk_score", 0)

            try:
                score = float(risk_raw)
            except (ValueError, TypeError):
                score = 0.0

            if ip:
                ip_counts[ip] += 1
                if score > ip_scores.get(ip, -1):
                    ip_scores[ip] = score
                    ip_actions[ip] = action

            if ja4:
                ja4_counts[ja4] += 1

            if action in _VALID_ACTIONS:
                action_dist[action] += 1

        stream_depth = await redis.xlen(_STREAM_KEY)

    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=threat_posture_redis_error | error=%s", exc)

    # Top 10 IPs sorted by max score descending
    top_ips = sorted(ip_scores.items(), key=lambda x: x[1], reverse=True)[:10]
    top_ip_rows = [
        {
            "ip": ip,
            "score": round(score, 1),
            "action": ip_actions.get(ip, ""),
            "count": ip_counts.get(ip, 0),
        }
        for ip, score in top_ips
    ]

    # Top 10 JA4 fingerprints by connection count
    top_ja4_raw = sorted(ja4_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # JA4 label lookup from config:ja4_labels hash
    ja4_labels: dict[str, str] = {}
    if top_ja4_raw:
        try:
            for fp, _ in top_ja4_raw:
                label = await redis.hget(_JA4_LABELS_KEY, fp)
                if label:
                    ja4_labels[fp] = label
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "partials | event=ja4_label_lookup_error | error=%s", exc
            )

    top_ja4_rows = [
        {
            "fingerprint": fp,
            "label": ja4_labels.get(fp, ""),
            "count": count,
        }
        for fp, count in top_ja4_raw
    ]

    # Action distribution as percentages
    # Proxy action vocabulary: allow, flag, rate_limit, tarpit, block, ban
    # (verified in internal/security/action_decider.go and internal/metrics/metrics.go)
    DISPLAY_ACTIONS = ["allow", "flag", "rate_limit", "tarpit", "block", "ban"]
    total_actions = sum(action_dist.values()) or 1  # avoid division by zero
    action_pct = {
        act: {
            "count": action_dist.get(act, 0),
            "pct": round(action_dist.get(act, 0) / total_actions * 100, 1),
        }
        for act in DISPLAY_ACTIONS
    }

    stream_warn = stream_depth > 80_000  # approaching 100k MAXLEN cap (Phase 233)

    return templates.TemplateResponse(
        request,
        "partials/threat_posture.html",
        {
            "user": current_user[0],
            "window": window,
            "windows": list(_WINDOW_SECONDS.keys()),
            "top_ips": top_ip_rows,
            "top_ja4": top_ja4_rows,
            "action_pct": action_pct,
            "stream_depth": stream_depth,
            "stream_warn": stream_warn,
            "total_events": total_events,
        },
    )
```

### 4.3 The complete threat_posture.html template

**File:** `management/templates/partials/threat_posture.html`

```html
<!--
  HTMX Partial: threat_posture.html
  GET /api/v1/partials/threat-posture?window=15m
  Polled every 30s.
  Template vars:
    window: str — current window key (e.g. "15m")
    windows: list[str] — ["5m","15m","1h","24h"]
    top_ips: list[{ip, score, action, count}]
    top_ja4: list[{fingerprint, label, count}]
    action_pct: dict — {action: {count, pct}} for allow/flag/rate_limit/tarpit/block/ban
    stream_depth: int
    stream_warn: bool
    total_events: int
-->

<!-- Action badge colour helper macros -->
{% macro action_badge(action) %}
  {% set colours = {
    "allow":      "bg-green-900/60 text-green-300",
    "flag":       "bg-blue-900/60 text-blue-300",
    "rate_limit": "bg-yellow-900/60 text-yellow-300",
    "tarpit":     "bg-orange-900/60 text-orange-300",
    "block":      "bg-red-900/60 text-red-300",
    "ban":        "bg-red-900/60 text-red-300",
  } %}
  <span class="px-2 py-0.5 rounded text-[10px] font-mono font-semibold
               {{ colours.get(action, 'bg-slate-700 text-slate-300') }}">
    {{ action | replace('_', ' ') | upper }}
  </span>
{% endmacro %}

<div id="threat-posture"
     hx-get="/api/v1/partials/threat-posture?window={{ window }}"
     hx-trigger="every 30s"
     hx-swap="outerHTML"
     class="space-y-4">

  <!-- ── Section header ──────────────────────────────────────────── -->
  <div class="flex items-center justify-between">
    <h2 class="text-sm font-semibold text-slate-100">
      Threat Posture
      <span class="ml-2 text-xs font-normal text-slate-400">
        {{ total_events }} events · stream depth: {{ stream_depth | filesizeformat if False else stream_depth }}
        {% if stream_warn %}
        <span class="ml-1 text-orange-400 font-semibold" title="Approaching 100k MAXLEN cap">⚠ {{ stream_depth }}</span>
        {% else %}
        <span class="text-slate-500">{{ stream_depth }}</span>
        {% endif %}
      </span>
    </h2>

    <!-- Time window selector tabs -->
    <!-- The selected window is stored in localStorage so the user's preference
         persists across page reloads. On change, a new HTMX request fires with
         the updated window parameter. -->
    <div class="flex gap-1" role="tablist" aria-label="Threat posture time window">
      {% for w in windows %}
      <button
        id="window-tab-{{ w }}"
        role="tab"
        aria-selected="{{ 'true' if w == window else 'false' }}"
        class="px-2.5 py-1 text-xs rounded
               {% if w == window %}
                 bg-sky-600 text-white font-semibold
               {% else %}
                 bg-slate-700 text-slate-300 hover:bg-slate-600
               {% endif %}"
        onclick="setThreatWindow('{{ w }}')"
        type="button">{{ w }}</button>
      {% endfor %}
    </div>
  </div>

  <!-- ── Two-column tables ────────────────────────────────────────── -->
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">

    <!-- Top 10 Source IPs -->
    <div class="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
      <div class="px-4 py-2.5 border-b border-slate-700">
        <h3 class="text-xs font-semibold text-slate-300">Top 10 Source IPs</h3>
      </div>
      {% if top_ips %}
      <table class="w-full text-xs" aria-label="Top source IPs">
        <thead>
          <tr class="border-b border-slate-700">
            <th class="px-3 py-2 text-left text-slate-400 font-medium">IP</th>
            <th class="px-3 py-2 text-right text-slate-400 font-medium">Score</th>
            <th class="px-3 py-2 text-left text-slate-400 font-medium">Action</th>
            <th class="px-3 py-2 text-right text-slate-400 font-medium">Count</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-700/50">
          {% for row in top_ips %}
          <tr class="hover:bg-slate-700/30 transition-colors">
            <td class="px-3 py-2 font-mono text-slate-200">
              <a href="/ip/{{ row.ip }}"
                 class="hover:text-sky-400 transition-colors"
                 title="View IP detail">{{ row.ip }}</a>
            </td>
            <td class="px-3 py-2 text-right font-mono
                       {% if row.score >= 80 %}text-red-400
                       {% elif row.score >= 50 %}text-orange-400
                       {% else %}text-slate-300{% endif %}">
              {{ row.score }}
            </td>
            <td class="px-3 py-2">{{ action_badge(row.action) }}</td>
            <td class="px-3 py-2 text-right text-slate-400">{{ row.count }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
      <div class="px-4 py-6 text-xs text-slate-500 text-center">
        No events in the {{ window }} window.
      </div>
      {% endif %}
    </div>

    <!-- Top 10 JA4 Fingerprints -->
    <div class="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
      <div class="px-4 py-2.5 border-b border-slate-700">
        <h3 class="text-xs font-semibold text-slate-300">Top 10 JA4 Fingerprints</h3>
      </div>
      {% if top_ja4 %}
      <table class="w-full text-xs" aria-label="Top JA4 fingerprints">
        <thead>
          <tr class="border-b border-slate-700">
            <th class="px-3 py-2 text-left text-slate-400 font-medium">Fingerprint</th>
            <th class="px-3 py-2 text-right text-slate-400 font-medium">Count</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-700/50">
          {% for row in top_ja4 %}
          <tr class="hover:bg-slate-700/30 transition-colors">
            <td class="px-3 py-2">
              <a href="/fingerprint/{{ row.fingerprint }}"
                 class="hover:text-sky-400 transition-colors font-mono"
                 title="View fingerprint detail">
                {% if row.label %}
                  <span class="text-slate-200 font-semibold">{{ row.label }}</span>
                  <span class="text-slate-500 ml-1 text-[10px]">{{ row.fingerprint[:12] }}…</span>
                {% else %}
                  <span class="text-slate-400">{{ row.fingerprint }}</span>
                {% endif %}
              </a>
            </td>
            <td class="px-3 py-2 text-right text-slate-400">{{ row.count }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
      <div class="px-4 py-6 text-xs text-slate-500 text-center">
        No events in the {{ window }} window.
      </div>
      {% endif %}
    </div>
  </div>

  <!-- ── Action distribution bar ──────────────────────────────────── -->
  <!--
    Uses colour AND pattern fills for accessibility (Decision 238 / Finding H-5 area).
    Percentages are shown as tooltips and as a legend below the bar.

    Proxy action vocabulary (internal/security/action_decider.go):
    allow:     solid green
    flag:      diagonal lines blue
    rate_limit: dotted yellow
    tarpit:    horizontal lines orange
    block:     dense cross-hatch red
    ban:       cross-hatch + horizontal lines dark red
  -->
  <div class="bg-slate-800 border border-slate-700 rounded-xl p-4">
    <h3 class="text-xs font-semibold text-slate-300 mb-3">Action Distribution</h3>
    <svg class="w-full h-0" height="0">
      <defs>
        <pattern id="pat-flag"       width="4" height="4" patternUnits="userSpaceOnUse">
          <path d="M-1,1 l2,-2 M0,4 l4,-4 M3,5 l2,-2" stroke="#3b82f6" stroke-width="1"/>
        </pattern>
        <pattern id="pat-rate_limit" width="4" height="4" patternUnits="userSpaceOnUse">
          <circle cx="2" cy="2" r="1" fill="#eab308"/>
        </pattern>
        <pattern id="pat-block"      width="4" height="4" patternUnits="userSpaceOnUse">
          <path d="M0,0 l4,4 M4,0 l-4,4" stroke="#ef4444" stroke-width="1"/>
        </pattern>
        <pattern id="pat-tarpit"     width="4" height="4" patternUnits="userSpaceOnUse">
          <path d="M0,2 h4" stroke="#f97316" stroke-width="1"/>
        </pattern>
        <pattern id="pat-ban"        width="4" height="4" patternUnits="userSpaceOnUse">
          <path d="M0,0 l4,4 M4,0 l-4,4" stroke="#dc2626" stroke-width="0.5"/>
          <path d="M0,2 h4" stroke="#dc2626" stroke-width="0.5"/>
        </pattern>
      </defs>
    </svg>

    {# Proxy action vocabulary (internal/security/action_decider.go): allow, flag, rate_limit, tarpit, block, ban #}
    <div class="flex h-6 rounded overflow-hidden w-full" role="img" aria-label="Action distribution bar">
      {% set action_meta = {
        'allow':     ('#16a34a', ''),
        'flag':      ('#3b82f6', 'url(#pat-flag)'),
        'rate_limit':('#eab308', 'url(#pat-rate_limit)'),
        'tarpit':    ('#f97316', 'url(#pat-tarpit)'),
        'block':     ('#ef4444', 'url(#pat-block)'),
        'ban':       ('#dc2626', 'url(#pat-ban)'),
      } %}
      {% for action in ['allow', 'flag', 'rate_limit', 'tarpit', 'block', 'ban'] %}
      {% set pct = action_pct[action].pct %}
      {% set colour, pattern = action_meta[action] %}
      {% if pct > 0 %}
      <div
        title="{{ action | replace('_', ' ') | title }}: {{ action_pct[action].count }} ({{ pct }}%)"
        style="width: {{ pct }}%; background-color: {{ colour }};{% if pattern %} background-image: {{ pattern }};{% endif %}"
        class="relative group">
        {% if pct > 5 %}
        <span class="absolute inset-0 flex items-center justify-center text-[10px] font-bold text-white/80">
          {{ pct }}%
        </span>
        {% endif %}
      </div>
      {% endif %}
      {% endfor %}
    </div>

    <!-- Legend -->
    <div class="flex flex-wrap gap-3 mt-2">
      {% set legend = {
        'allow':     '#16a34a',
        'flag':      '#3b82f6',
        'rate_limit':'#eab308',
        'tarpit':    '#f97316',
        'block':     '#ef4444',
        'ban':       '#dc2626',
      } %}
      {% for action, colour in legend.items() %}
      <div class="flex items-center gap-1 text-[10px] text-slate-400">
        <span class="w-2.5 h-2.5 rounded-sm inline-block" style="background:{{ colour }}"></span>
        {{ action | replace('_', ' ') | title }}: {{ action_pct[action].count }}
      </div>
      {% endfor %}
    </div>
  </div>

</div>

<script>
/**
 * setThreatWindow — change the time window and persist choice in localStorage.
 *
 * localStorage trick: The user's preference is stored under "threat_posture_window".
 * On the next page load, the page reads this key and appends ?window=<value> to the
 * hx-get URL before HTMX fires. This means the user never has to re-select their
 * preferred window after a page refresh.
 *
 * Alpine.js is not needed here — plain DOM manipulation is sufficient.
 */
function setThreatWindow(w) {
  localStorage.setItem('threat_posture_window', w);
  // Build the URL with the new window parameter
  var url = '/api/v1/partials/threat-posture?window=' + encodeURIComponent(w);
  // Update the hx-get attribute on the container so future polls use the new window
  var container = document.getElementById('threat-posture');
  if (container) {
    container.setAttribute('hx-get', url);
    htmx.trigger(container, 'refresh');  // fire an immediate poll
  }
}

// On initial load, read the stored window preference (if any)
(function () {
  var stored = localStorage.getItem('threat_posture_window');
  if (stored && stored !== '{{ window }}') {
    setThreatWindow(stored);
  }
})();
</script>
```

### 4.4 The JA4 label lookup explained

`config:ja4_labels` is a Redis **hash** (key-value map within Redis). The Go proxy
populates it with entries like:
```
HSET config:ja4_labels "t13d1516h2_8daaf6152771_b1ff8ab2d16f" "Chrome 120 / Windows"
```

When the endpoint runs, it calls:
```python
label = await redis.hget("config:ja4_labels", fingerprint_hash)
```
If the fingerprint is not in the hash, `hget` returns `None` and we fall back to
showing the raw hash. The template checks `{% if row.label %}` to decide which to
show.

### 4.5 dashboard.html change — add the Threat Posture row

Insert the new section **between** the health-cards row and the live feed row:

```diff
   </section>

+  <!-- ── Row 2: Threat Posture (30s poll, NEW) ──────────────── -->
+  <section aria-label="Threat posture">
+    <div id="threat-posture-outer"
+         hx-get="/api/v1/partials/threat-posture?window=15m"
+         hx-trigger="load"
+         hx-swap="outerHTML">
+      <!-- Loading skeleton -->
+      <div class="bg-slate-800 border border-slate-700 rounded-xl p-4 animate-pulse h-48"></div>
+    </div>
+  </section>
+
   <!-- ── Row 2: Live feed + Dial widget ─────────────────────────── -->
```

> **NOTE:** The `threat_posture.html` partial contains its own `hx-trigger="every 30s"`
> on the `#threat-posture` div. The initial load uses `hx-trigger="load"` on the
> outer wrapper. After the first load, HTMX replaces the outer wrapper with the
> partial, and the partial's own trigger takes over. This is the standard HTMX
> "load then poll" pattern.

### 4.6 Tests for threat posture endpoint

**File:** `tests/unit/test_threat_posture.py`

```python
"""
tests/unit/test_threat_posture.py
Unit tests for the /api/v1/partials/threat-posture endpoint.

These tests mock Redis so they do not require a running Redis instance.
See AGENTS.md: "Unit tests must mock every external service".
"""
import pytest
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient
from management.api.main import create_app
from management.api.auth import _create_access_token


def _make_stream_entry(ip, ja4, score, action, ts_ms=None):
    """Build a fake Redis stream entry tuple matching the Go proxy's payload shape.

    The Go proxy writes a single 'event' field whose value is a JSON string
    of flat, dot-delimited ECS keys (cmd/ja4pd/main.go):
      event.action, event.risk_score, source.ip, ja4proxy.fingerprint.ja4, @timestamp
    """
    import json, time
    ts_ms = ts_ms or int(time.time() * 1000)
    entry_id = f"{ts_ms}-0"
    payload = json.dumps({
        "event.action": action,
        "event.risk_score": score,
        "source.ip": ip,
        "ja4proxy.fingerprint.ja4": ja4,
        "@timestamp": "2026-06-12T08:00:00Z",
    })
    fields = {"event": payload}
    return (entry_id, fields)


@pytest.mark.asyncio
async def test_top_n_ip_computation():
    """Top 10 IPs are sorted by max score, highest first."""
    app = create_app()
    token = _create_access_token("analyst", role="analyst")

    # Build 15 unique IPs with different scores
    entries = []
    for i in range(15):
        entries.append(_make_stream_entry(
            ip=f"10.0.0.{i+1}",
            ja4="t13d1516h2_8daaf6152771_b1ff8ab2d16f",
            score=float(i * 5),   # scores 0, 5, 10, ... 70
            action="allow",
        ))

    with patch("management.api.routes.partials.get_redis") as mock_get_redis:
        mock_redis = AsyncMock()
        mock_redis.xrevrange = AsyncMock(return_value=list(reversed(entries)))
        mock_redis.xlen = AsyncMock(return_value=15)
        mock_redis.hget = AsyncMock(return_value=None)  # no labels
        mock_get_redis.return_value = mock_redis

        async with AsyncClient(app=app, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/partials/threat-posture?window=15m",
                cookies={"token": token},
            )

    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    # Highest score is 70 (10.0.0.15) — must appear first
    text = resp.text
    pos_highest = text.find("10.0.0.15")
    pos_second  = text.find("10.0.0.14")
    assert pos_highest < pos_second, "Highest-scoring IP must appear before second-highest"
    # Only top 10 should appear (not 10.0.0.1 through 10.0.0.5 which are lowest)
    assert "10.0.0.1\"" not in text   # 11th-lowest should be absent


@pytest.mark.asyncio
async def test_invalid_window_defaults_to_15m():
    """An invalid window parameter falls back to 15m silently."""
    app = create_app()
    token = _create_access_token("analyst", role="analyst")

    with patch("management.api.routes.partials.get_redis") as mock_get_redis:
        mock_redis = AsyncMock()
        mock_redis.xrevrange = AsyncMock(return_value=[])
        mock_redis.xlen = AsyncMock(return_value=0)
        mock_get_redis.return_value = mock_redis

        async with AsyncClient(app=app, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/partials/threat-posture?window=BOGUS",
                cookies={"token": token},
            )

    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_ja4_label_shown_when_present():
    """JA4 label from config:ja4_labels hash is shown in the rendered HTML."""
    app = create_app()
    token = _create_access_token("analyst", role="analyst")
    fp = "t13d1516h2_8daaf6152771_b1ff8ab2d16f"
    label = "Chrome 120 / Windows"

    entries = [_make_stream_entry("1.2.3.4", fp, 50, "flag")]

    with patch("management.api.routes.partials.get_redis") as mock_get_redis:
        mock_redis = AsyncMock()
        mock_redis.xrevrange = AsyncMock(return_value=entries)
        mock_redis.xlen = AsyncMock(return_value=1)
        mock_redis.hget = AsyncMock(return_value=label)
        mock_get_redis.return_value = mock_redis

        async with AsyncClient(app=app, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/partials/threat-posture?window=15m",
                cookies={"token": token},
            )

    assert label in resp.text, "Human-readable JA4 label should appear in HTML"


@pytest.mark.asyncio
async def test_stream_depth_warning_shown_above_80k():
    """Stream depth warning badge appears when stream_depth > 80000."""
    app = create_app()
    token = _create_access_token("analyst", role="analyst")

    with patch("management.api.routes.partials.get_redis") as mock_get_redis:
        mock_redis = AsyncMock()
        mock_redis.xrevrange = AsyncMock(return_value=[])
        mock_redis.xlen = AsyncMock(return_value=85000)  # above warning threshold
        mock_get_redis.return_value = mock_redis

        async with AsyncClient(app=app, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/partials/threat-posture?window=15m",
                cookies={"token": token},
            )

    # The template renders a ⚠ warning when stream_warn is True
    assert "⚠" in resp.text


@pytest.mark.asyncio
async def test_action_distribution_percentages():
    """Action distribution percentages sum to 100 (or close)."""
    app = create_app()
    token = _create_access_token("analyst", role="analyst")

    entries = (
        [_make_stream_entry("1.1.1.1", "fp1", 10, "allow")]   * 50 +
        [_make_stream_entry("2.2.2.2", "fp2", 60, "block")]   * 30 +
        [_make_stream_entry("3.3.3.3", "fp3", 40, "flag")] * 20
    )

    with patch("management.api.routes.partials.get_redis") as mock_get_redis:
        mock_redis = AsyncMock()
        mock_redis.xrevrange = AsyncMock(return_value=entries)
        mock_redis.xlen = AsyncMock(return_value=100)
        mock_redis.hget = AsyncMock(return_value=None)
        mock_get_redis.return_value = mock_redis

        async with AsyncClient(app=app, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/partials/threat-posture?window=15m",
                cookies={"token": token},
            )

    assert resp.status_code == 200
    # 50% allow, 30% block, 20% flag should appear somewhere
    assert "50.0" in resp.text
    assert "30.0" in resp.text
    assert "20.0" in resp.text
```

---

## 5. Sub-task C: Infrastructure Row

### 5.0 Heartbeat producer — DEFERRED to follow-up Phase 239

The infra row reads `proxy:heartbeat:*` to show the proxy up/down. **As of `main`
nothing writes that key** (verified: no writer in `cmd/` or `internal/`); the
producers assumed by `health.py`, `pack_builder.py`, and `nodes.py` do not exist.

**Decision: The Go heartbeat producer is deferred to Phase 239 (estimated < 1 day).**
See `PHASE_239.md` for the planned implementation:
- A heartbeat goroutine in `cmd/ja4pd/main.go` that `SET proxy:heartbeat:{instance_id} <epoch> EX 90` every ~30s.
- Standardise `proxy:heartbeat:{instance_id}` as the program's chosen convention.
- Converge the existing `mgmt:node:*` reader onto the same key, and correct `docs/REDIS_SCHEMA.md`.

Until Phase 239 ships, the infra row will show `proxy_status: "unknown"` instead of `"DOWN"`.
The endpoint handles this gracefully — no errors, just a missing-data indicator.

### 5.1 The complete endpoint

**File:** `management/api/routes/partials.py` — add after threat-posture.

```python
import aiohttp  # for Prometheus HTTP API queries

import os

_PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://prometheus:9090")  # configurable via env


@router.get("/api/v1/partials/infrastructure", response_class=HTMLResponse)
async def infrastructure_partial(
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Return the Infrastructure row as an HTML fragment.

    Data sources:
    - redis.info("memory") → memory usage
    - redis.info("stats")  → evicted_keys
    - proxy:heartbeat:*    → proxy up/down
    - analytics:heartbeat  → analytics up/down
    - tarpit:active_count  → active tarpit connections
    - Prometheus HTTP API  → HAProxy backend status (may be unavailable)

    Polled every 30 seconds.
    """
    templates = _get_templates()

    # ── Redis memory ────────────────────────────────────────────────
    redis_mem_used = "?"
    redis_mem_max = "?"
    redis_mem_pct = 0.0
    redis_evictions = 0
    redis_ok = False

    try:
        mem_info = await redis.info("memory")
        stats_info = await redis.info("stats")
        redis_ok = True

        used_bytes = int(mem_info.get("used_memory", 0))
        max_bytes  = int(mem_info.get("maxmemory", 0))
        redis_mem_used = mem_info.get("used_memory_human", "?")
        redis_mem_max  = mem_info.get("maxmemory_human", "unlimited") if max_bytes else "unlimited"

        if max_bytes > 0:
            redis_mem_pct = round(used_bytes / max_bytes * 100, 1)
        else:
            redis_mem_pct = 0.0   # no max configured → can't compute %

        redis_evictions = int(stats_info.get("evicted_keys", 0))

    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=infra_redis_error | error=%s", exc)

    # ── Proxy heartbeat ─────────────────────────────────────────────
    # NOTE: The Go heartbeat producer is DEFERRED to Phase 239.
    # Until then, no proxy:heartbeat:* key exists, and the proxy row
    # shows status="unknown" — this is intentional and graceful.
    proxy_up = False
    proxy_unknown = True
    proxy_last_seen = None
    try:
        cursor = 0
        while True:
            cursor, keys = await redis.scan(cursor=cursor, match="proxy:heartbeat:*", count=50)
            if keys:
                proxy_up = True
                proxy_unknown = False
                ttl = await redis.ttl(keys[0])
                import time as _time
                if ttl and ttl > 0:
                    secs_ago = 90 - ttl
                    proxy_last_seen = f"{secs_ago}s ago"
                break
            if cursor == 0:
                proxy_unknown = True
                break
    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=infra_proxy_hb_error | error=%s", exc)

    # ── Analytics heartbeat ─────────────────────────────────────────
    analytics_up = False
    analytics_last_seen = None
    try:
        hb = await redis.get("analytics:heartbeat")
        if hb:
            analytics_up = True
            analytics_last_seen = hb  # ISO8601 timestamp written by analytics
    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=infra_analytics_hb_error | error=%s", exc)

    # ── Tarpit active count ─────────────────────────────────────────
    tarpit_active = None
    try:
        raw = await redis.get("tarpit:active_count")
        if raw is not None:
            tarpit_active = int(raw)
    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=infra_tarpit_count_error | error=%s", exc)

    # ── HAProxy status via Prometheus ───────────────────────────────
    # Decision note: The management container may not be on the ja4proxy-monitoring
    # network. See Section 5.2 of PHASE_234.md for the three options.
    # This implementation uses option (b): query Prometheus which IS on the monitoring
    # network. If Prometheus is unreachable, we show "N/A" rather than failing.
    haproxy_status = "N/A"
    haproxy_note = "Prometheus unreachable from management container"
    try:
        prom_query = "haproxy_backend_status{backend=\"proxy\"}"
        prom_url = f"{_PROMETHEUS_URL}/api/v1/query"
        async with aiohttp.ClientSession() as session:
            async with session.get(
                prom_url,
                params={"query": prom_query},
                timeout=aiohttp.ClientTimeout(total=3),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    results = data.get("data", {}).get("result", [])
                    if results:
                        val = results[0].get("value", [None, None])[1]
                        haproxy_status = "UP" if str(val) == "1" else "DOWN"
                        haproxy_note = ""
    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=infra_haproxy_prom_error | error=%s", exc)

    # ── Compute Redis memory status colour ─────────────────────────
    if redis_mem_pct == 0:
        mem_colour = "ok"       # no max configured
    elif redis_mem_pct < 60:
        mem_colour = "ok"       # green
    elif redis_mem_pct < 85:
        mem_colour = "warn"     # amber
    else:
        mem_colour = "error"    # red

    return templates.TemplateResponse(
        request,
        "partials/infrastructure.html",
        {
            "user": current_user[0],
            "redis_ok": redis_ok,
            "redis_mem_used": redis_mem_used,
            "redis_mem_max": redis_mem_max,
            "redis_mem_pct": redis_mem_pct,
            "mem_colour": mem_colour,
            "redis_evictions": redis_evictions,
            "proxy_up": proxy_up,
            "proxy_unknown": proxy_unknown,
            "proxy_last_seen": proxy_last_seen,
            "analytics_up": analytics_up,
            "analytics_last_seen": analytics_last_seen,
            "tarpit_active": tarpit_active,
            "haproxy_status": haproxy_status,
            "haproxy_note": haproxy_note,
        },
    )
```

### 5.2 HAProxy metrics challenge — network routing options

> **NOTE (read before implementing):**
> The management container is on the `ja4proxy-mgmt` Docker network.
> The `haproxy-exporter` container is on the `ja4proxy-monitoring` network.
> These two networks are isolated by default.
>
> Three options to resolve this (discuss with the team before picking one):
>
> **Option a) Add management to the monitoring network** — simplest, but widens the
> management container's network exposure. Edit `docker-compose.poc.yml` to add
> `ja4proxy-monitoring` to the management service's `networks:` list.
>
> **Option b) Query Prometheus instead of haproxy-exporter directly** — Prometheus
> *is* on the monitoring network and *may* also be reachable from mgmt if the compose
> is configured to expose it. The implementation above uses this approach. If Prometheus
> is not reachable, the endpoint logs a WARNING and shows "N/A" — fail-open, not fail-closed.
>
> **Option c) Show N/A with a note** — simplest to implement, honest about the gap.
> Set `haproxy_status = "N/A"` and `haproxy_note = "Not available: see PHASE_234.md#5.2"`.
> This does NOT require any network changes.
>
> The implementation above defaults to option (b) with graceful fallback to "N/A".
> **Do not hard-block the PR on HAProxy metrics.** If it shows N/A in CI, that is
> acceptable for Phase 234. Phase 237 can add the network routing fix.

### 5.3 The complete infrastructure.html template

**File:** `management/templates/partials/infrastructure.html`

```html
<!--
  HTMX Partial: infrastructure.html
  GET /api/v1/partials/infrastructure
  Polled every 30s.
  Template vars: see partials.py infrastructure_partial()
-->
<div id="infrastructure"
     hx-get="/api/v1/partials/infrastructure"
     hx-trigger="every 30s"
     hx-swap="outerHTML"
     class="bg-slate-800 border border-slate-700 rounded-xl p-4 space-y-4">

  <h2 class="text-sm font-semibold text-slate-100">Infrastructure</h2>

  <div class="grid grid-cols-2 sm:grid-cols-4 gap-4">

    <!-- Redis Memory Bar -->
    <div class="col-span-2">
      <div class="flex items-center justify-between mb-1">
        <span class="text-xs text-slate-400">Redis Memory</span>
        <span class="text-xs font-mono
          {% if mem_colour == 'ok' %}text-green-400
          {% elif mem_colour == 'warn' %}text-amber-400
          {% else %}text-red-400{% endif %}">
          {{ redis_mem_used }} / {{ redis_mem_max }}
          {% if redis_mem_pct > 0 %}({{ redis_mem_pct }}%){% endif %}
        </span>
      </div>
      {% if redis_mem_pct > 0 %}
      <div class="w-full bg-slate-700 rounded-full h-2" role="progressbar"
           aria-valuenow="{{ redis_mem_pct }}" aria-valuemin="0" aria-valuemax="100"
           aria-label="Redis memory usage">
        <div class="h-2 rounded-full transition-all
          {% if mem_colour == 'ok' %}bg-green-500
          {% elif mem_colour == 'warn' %}bg-amber-500
          {% else %}bg-red-500{% endif %}"
          style="width: {{ [redis_mem_pct, 100] | min }}%">
        </div>
      </div>
      {% endif %}
      {% if redis_evictions > 0 %}
      <div class="mt-1 text-[10px] text-red-400 font-semibold">
        ⚠ {{ redis_evictions }} key{{ 's' if redis_evictions != 1 }} evicted — security state may be affected
      </div>
      {% endif %}
    </div>

    <!-- Analytics Status -->
    <div>
      <span class="text-xs text-slate-400 block mb-1">Analytics</span>
      {% if analytics_up %}
        <span class="flex items-center gap-1 text-xs text-green-400 font-semibold">
          <span class="w-2 h-2 rounded-full bg-green-400 inline-block"></span> UP
        </span>
        {% if analytics_last_seen %}
        <span class="text-[10px] text-slate-500 block mt-0.5">
          {{ analytics_last_seen[:19] | replace("T"," ") }} UTC
        </span>
        {% endif %}
      {% else %}
        <span class="flex items-center gap-1 text-xs text-red-400 font-semibold">
          <span class="w-2 h-2 rounded-full bg-red-400 animate-ping inline-block"></span> DOWN
        </span>
        <span class="text-[10px] text-slate-500 block mt-0.5">No heartbeat</span>
      {% endif %}
    </div>

    <!-- Tarpit Status -->
    <div>
      <span class="text-xs text-slate-400 block mb-1">Tarpit</span>
      {% if tarpit_active is not none %}
        <span class="text-xs text-green-400 font-semibold">{{ tarpit_active }} active</span>
      {% else %}
        <span class="text-xs text-slate-500">Unknown</span>
      {% endif %}
    </div>

    <!-- Proxy Status -->
    <div>
      <span class="text-xs text-slate-400 block mb-1">Proxy</span>
      {% if proxy_unknown %}
        <span class="flex items-center gap-1 text-xs text-slate-500 font-semibold">
          <span class="w-2 h-2 rounded-full bg-slate-500 inline-block"></span> Unknown
        </span>
        <span class="text-[10px] text-slate-600 block mt-0.5">Heartbeat producer deferred to Phase 239</span>
      {% elif proxy_up %}
        <span class="flex items-center gap-1 text-xs text-green-400 font-semibold">
          <span class="w-2 h-2 rounded-full bg-green-400 inline-block"></span> UP
        </span>
        {% if proxy_last_seen %}
        <span class="text-[10px] text-slate-500 block mt-0.5">hb {{ proxy_last_seen }}</span>
        {% endif %}
      {% else %}
        <span class="flex items-center gap-1 text-xs text-red-400 font-semibold">
          <span class="w-2 h-2 rounded-full bg-red-500 animate-ping inline-block"></span> DOWN
        </span>
      {% endif %}
    </div>

    <!-- HAProxy Backend -->
    <div>
      <span class="text-xs text-slate-400 block mb-1">HAProxy</span>
      {% if haproxy_status == 'UP' %}
        <span class="flex items-center gap-1 text-xs text-green-400 font-semibold">
          <span class="w-2 h-2 rounded-full bg-green-400 inline-block"></span> UP
        </span>
      {% elif haproxy_status == 'DOWN' %}
        <span class="flex items-center gap-1 text-xs text-red-400 font-semibold">
          <span class="w-2 h-2 rounded-full bg-red-400 animate-ping inline-block"></span> DOWN
        </span>
      {% else %}
        <span class="text-xs text-slate-500" title="{{ haproxy_note }}">N/A</span>
      {% endif %}
    </div>

  </div>
</div>
```

### 5.4 dashboard.html change — add Infrastructure row

Insert after the Threat Posture section:

```diff
+  <!-- ── Row 3: Infrastructure (30s poll, NEW) ─────────────────── -->
+  <section aria-label="Infrastructure status">
+    <div id="infrastructure-outer"
+         hx-get="/api/v1/partials/infrastructure"
+         hx-trigger="load"
+         hx-swap="outerHTML">
+      <div class="bg-slate-800 border border-slate-700 rounded-xl p-4 animate-pulse h-24"></div>
+    </div>
+  </section>
+
   <!-- ── Row 2: Live feed + Dial widget ─────────────────────────── -->
```

---

## 6. Sub-task D: Triage Queue

### 6.1 The complete endpoint

**File:** `management/api/routes/partials.py` — add after infrastructure.

```python
@router.get("/api/v1/partials/triage-queue", response_class=HTMLResponse)
async def triage_queue_partial(
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Return the Triage Queue as an HTML fragment.

    The triage queue surfaces IPs in the 'grey zone': score 35-65, at least
    50 connections in the last 24h, not on any list, score trending upward,
    and not recently dismissed.

    Per Decision 5 in PHASE_231.md: polled every 60 seconds.
    """
    templates = _get_templates()

    # ── Read configuration ──────────────────────────────────────────
    try:
        triage_range_raw = await redis.get("config:triage_range") or "35,65"
        triage_min_count_raw = await redis.get("config:triage_min_count") or "50"
        score_min, score_max = (float(x) for x in triage_range_raw.split(",", 1))
        min_count = int(triage_min_count_raw)
    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=triage_config_error | error=%s", exc)
        score_min, score_max, min_count = 35.0, 65.0, 50

    # ── Read 24h of stream events ──────────────────────────────────
    min_id_24h = _window_min_id(24 * 60 * 60)
    ip_scores: dict[str, list[float]] = {}   # ip -> list of scores (for trend)
    ip_counts: dict[str, int] = {}

    try:
        raw = await redis.xrevrange(_STREAM_KEY, max="+", min=min_id_24h, count=10000)
        for _entry_id, fields in raw:
            raw_event = fields.get("event")
            if not raw_event:
                continue
            try:
                ev = json.loads(raw_event)
            except (ValueError, TypeError):
                continue
            ip = ev.get("source.ip", "")
            if not ip:
                continue
            try:
                score = float(ev.get("event.risk_score", 0))
            except (ValueError, TypeError):
                score = 0.0
            ip_scores.setdefault(ip, []).append(score)
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=triage_stream_error | error=%s", exc)

    # ── Read all blocklists / allowlists ────────────────────────────
    listed_ips: set[str] = set()
    try:
        for key in ("static:allowlist", "static:blocklist", "static:watchlist"):
            members = await redis.smembers(key)
            listed_ips.update(members)
        # Also check active bans
        cursor = 0
        while True:
            cursor, keys = await redis.scan(cursor=cursor, match="ban:*", count=100)
            for k in keys:
                listed_ips.add(k[len("ban:"):])
            if cursor == 0:
                break
    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=triage_list_error | error=%s", exc)

    # ── Build candidate list ────────────────────────────────────────
    candidates = []
    for ip, scores in ip_scores.items():
        count = ip_counts.get(ip, 0)
        max_score = max(scores)
        if max_score < score_min or max_score > score_max:
            continue
        if count < min_count:
            continue
        if ip in listed_ips:
            continue

        # Score trend: positive if last 5 scores are higher than first 5
        # Simple linear approximation: compare first half avg to second half avg
        if len(scores) >= 4:
            mid = len(scores) // 2
            first_half_avg = sum(scores[:mid]) / mid
            second_half_avg = sum(scores[mid:]) / (len(scores) - mid)
            trend = second_half_avg - first_half_avg  # positive = trending up
        else:
            trend = 0.0

        if trend < 0:   # trending downward — skip (system is handling it)
            continue

        # Check dismiss TTL
        try:
            dismissed = await redis.get(f"dismissed:triage:{ip}")
        except Exception:
            dismissed = None
        if dismissed:
            continue

        # Trend indicator
        if trend > 2:
            trend_label = "↑"
        elif trend > -2:
            trend_label = "→"
        else:
            trend_label = "↓"

        candidates.append({
            "ip": ip,
            "score": round(max_score, 1),
            "count": count,
            "trend": trend_label,
            "trend_value": round(trend, 1),
        })

    # Sort by score descending; take top 25
    candidates.sort(key=lambda x: x["score"], reverse=True)
    candidates = candidates[:25]

    return templates.TemplateResponse(
        request,
        "partials/triage_queue.html",
        {
            "user": current_user[0],
            "role": current_user[1].value if hasattr(current_user[1], 'value') else str(current_user[1]),
            "candidates": candidates,
            "total_count": len(candidates),
        },
    )


@router.post("/api/v1/triage/dismiss/{ip}", response_class=HTMLResponse)
async def triage_dismiss(
    ip: str,
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Dismiss an IP from the triage queue for 4 hours.

    Writes dismissed:triage:{ip} with a 4h TTL. The IP will re-appear in the
    triage queue after the TTL expires if it is still in the grey zone.

    No confirmation modal needed — a 4h dismiss is low-stakes and reversible
    by waiting. Per Decision 5 in PHASE_231.md.
    """
    import re
    # Basic IP validation — reject anything that's not a valid IP
    if not re.match(r'^[\d\.]{7,15}$|^[\da-fA-F:]{3,39}$', ip):
        from fastapi.responses import HTMLResponse as _H
        return _H(
            content='<div class="text-red-400 text-xs p-2">Invalid IP format</div>',
            status_code=400,
        )

    try:
        four_hours = 4 * 3600
        await redis.set(f"dismissed:triage:{ip}", "1", ex=four_hours)
        logger.info(
            "partials | event=triage_dismiss | ip=%s | user=%s",
            ip, current_user[0]
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=triage_dismiss_error | ip=%s | error=%s", ip, exc)

    # Return a minimal fragment that replaces the row (the row hx-swaps outerHTML)
    return HTMLResponse(
        content=f'<!-- dismissed: {ip} -->',
        status_code=200,
    )
```

### 6.2 The complete triage_queue.html template

**File:** `management/templates/partials/triage_queue.html`

```html
<!--
  HTMX Partial: triage_queue.html
  GET /api/v1/partials/triage-queue
  Polled every 60 seconds.
  Template vars:
    candidates: list[{ip, score, count, trend, trend_value}]
    total_count: int
    role: str — current user role for RBAC guards
-->
<div id="triage-queue"
     hx-get="/api/v1/partials/triage-queue"
     hx-trigger="every 60s"
     hx-swap="outerHTML"
     class="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">

  <!-- Header with badge count -->
  <div class="px-4 py-3 border-b border-slate-700 flex items-center justify-between">
    <h2 class="text-sm font-semibold text-slate-100">
      Needs Decision
      {% if total_count > 0 %}
      <span class="ml-2 px-2 py-0.5 rounded-full text-xs font-bold bg-amber-600 text-white">
        {{ total_count }}
      </span>
      {% endif %}
    </h2>
    <span class="text-xs text-slate-500">Score range 35–65 · 50+ connections/24h · polled 60s</span>
  </div>

  {% if not candidates %}
  <!-- Empty state — system is acting decisively -->
  <div class="px-4 py-8 text-center">
    <span class="text-green-400 text-lg">✓</span>
    <p class="text-sm text-slate-400 mt-1">No IPs in the grey zone — system is acting decisively.</p>
  </div>

  {% else %}
  <table class="w-full text-xs" aria-label="Triage queue">
    <thead>
      <tr class="border-b border-slate-700">
        <th class="px-4 py-2 text-left text-slate-400 font-medium">IP</th>
        <th class="px-4 py-2 text-right text-slate-400 font-medium">Score</th>
        <th class="px-4 py-2 text-right text-slate-400 font-medium">24h Conn</th>
        <th class="px-4 py-2 text-center text-slate-400 font-medium">Trend</th>
        <th class="px-4 py-2 text-right text-slate-400 font-medium">Actions</th>
      </tr>
    </thead>
    <tbody class="divide-y divide-slate-700/50">
      {% for row in candidates %}
      <tr id="triage-row-{{ row.ip | replace('.', '-') }}"
          class="hover:bg-slate-700/30 transition-colors">

        <td class="px-4 py-2.5 font-mono text-slate-200">
          <a href="/ip/{{ row.ip }}"
             class="hover:text-sky-400 transition-colors"
             title="View IP detail">{{ row.ip }}</a>
        </td>

        <td class="px-4 py-2.5 text-right font-mono font-semibold
                   {% if row.score >= 55 %}text-orange-400
                   {% elif row.score >= 45 %}text-yellow-400
                   {% else %}text-slate-300{% endif %}">
          {{ row.score }}
        </td>

        <td class="px-4 py-2.5 text-right text-slate-400">{{ row.count }}</td>

        <td class="px-4 py-2.5 text-center
                   {% if row.trend == '↑' %}text-red-400
                   {% elif row.trend == '↓' %}text-green-400
                   {% else %}text-slate-400{% endif %}">
          {{ row.trend }}
          <span class="sr-only">
            {% if row.trend == '↑' %}Trending upward
            {% elif row.trend == '↓' %}Trending downward
            {% else %}Stable{% endif %}
          </span>
        </td>

        <td class="px-4 py-2.5 text-right">
          <div class="flex items-center justify-end gap-1">

            <!--
              Block and Watchlist open the confirmation modal (Decision 4, PHASE_231.md).
              The modal is implemented in Phase 235 (confirm-modal.js).
              For now these buttons are placeholders that will be wired up in Phase 235.
              If Phase 235 has been completed already, replace onclick with:
              onclick="ConfirmModal.open({action:'block', ip:'{{ row.ip }}', ...})"
            -->
            {% if role in ['operator', 'admin'] %}
            <button
              id="triage-block-{{ row.ip | replace('.', '-') }}"
              class="px-2 py-1 text-[10px] font-semibold rounded
                     bg-red-900/60 text-red-300 hover:bg-red-800 transition-colors"
              type="button"
              title="Block {{ row.ip }} — opens confirmation modal"
              data-action="block"
              data-ip="{{ row.ip }}"
              data-score="{{ row.score }}"
              onclick="if(window.ConfirmModal) ConfirmModal.open({action:'block',ip:'{{ row.ip }}',score:{{ row.score }}});">
              Block
            </button>

            <button
              id="triage-watchlist-{{ row.ip | replace('.', '-') }}"
              class="px-2 py-1 text-[10px] font-semibold rounded
                     bg-blue-900/60 text-blue-300 hover:bg-blue-800 transition-colors"
              type="button"
              title="Add {{ row.ip }} to watchlist"
              data-action="watchlist"
              data-ip="{{ row.ip }}"
              onclick="if(window.ConfirmModal) ConfirmModal.open({action:'watchlist',ip:'{{ row.ip }}',score:{{ row.score }}});">
              Watchlist
            </button>
            {% endif %}

            <!--
              Dismiss fires inline — no modal needed.
              4h dismiss is low-stakes: the IP re-appears when the TTL expires
              if it is still active. Per Decision 5 in PHASE_231.md.

              Analyst+ can dismiss (they can see the feed but can't block).
            -->
            {% if role in ['analyst', 'operator', 'admin'] %}
            <button
              id="triage-dismiss-{{ row.ip | replace('.', '-') }}"
              class="px-2 py-1 text-[10px] font-semibold rounded
                     bg-slate-700 text-slate-400 hover:bg-slate-600 transition-colors"
              type="button"
              title="Dismiss {{ row.ip }} for 4 hours"
              hx-post="/api/v1/triage/dismiss/{{ row.ip }}"
              hx-swap="outerHTML"
              hx-target="#triage-row-{{ row.ip | replace('.', '-') }}"
              hx-confirm="">
              Dismiss 4h
            </button>
            {% endif %}

          </div>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% endif %}

</div>
```

### 6.3 Why the dismiss button fires inline (no modal)

From **Decision 5** in `PHASE_231.md`:
> "Dismiss fires a lightweight POST /api/v1/triage/dismiss/{ip} endpoint
> with no confirmation required (4h dismiss is low-stakes)."

A 4-hour dismiss means: "I've looked at this IP, I'm not ready to block it, check
back in 4 hours." If the analyst mis-clicks, the consequence is that a suspicious
IP is not shown for 4 hours — the system still monitors it, just doesn't surface it
in the triage view. This is recoverable (just wait 4 hours). Contrast with Block
(irreversible for the ban duration) or Allowlist (bypasses all scoring) — those
require confirmation.

The `hx-confirm=""` attribute on the dismiss button is intentionally set to empty
string. This disables the default HTMX browser confirm dialog (which would use
`window.confirm()` — blocked by enterprise browsers per Decision 4). The action
fires immediately on click.

### 6.4 dashboard.html change — add Triage Queue row

Insert before the Live feed section:

```diff
+  <!-- ── Row 4: Triage Queue (60s poll, NEW) ─────────────────── -->
+  <section aria-label="Triage queue">
+    <div id="triage-queue-outer"
+         hx-get="/api/v1/partials/triage-queue"
+         hx-trigger="load"
+         hx-swap="outerHTML">
+      <div class="bg-slate-800 border border-slate-700 rounded-xl p-4 animate-pulse h-20"></div>
+    </div>
+  </section>
+
   <!-- ── Row 2: Live feed + Dial widget ─────────────────────────── -->
```

---

## 7. Final dashboard.html Structure

After all four sub-tasks, the complete `management/templates/dashboard.html` should
be structured as follows. This is the target state — the actual content is in the
partial templates; dashboard.html just contains the wiring:

```html
{% extends "base.html" %}

{% block title %}Dashboard{% endblock %}
{% block page_title %}Dashboard{% endblock %}

{% block content %}
<div class="space-y-6 max-w-[1200px]">

  <!--
    Situation Summary Bar — delivered in Phase 232, sits ABOVE this file's content
    (it's in base.html between the topbar and the page content block).
    See PHASE_232.md Sub-task B. Not repeated here.
  -->

  <!-- ── Row 1: System Health (10s poll) ─────────────────────────── -->
  <section aria-label="System health">
    <div id="health-cards"
         hx-get="/api/v1/partials/health-cards"
         hx-trigger="load, every 10s"
         hx-swap="innerHTML"
         hx-indicator="#htmx-indicator">
      <!-- Skeleton placeholders -->
      <div class="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {% for _ in range(4) %}
        <div class="bg-[#1e293b] border border-[#334155] rounded-xl p-4 animate-pulse">
          <div class="h-3 w-24 bg-[#334155] rounded mb-3"></div>
          <div class="h-7 w-16 bg-[#334155] rounded"></div>
        </div>
        {% endfor %}
      </div>
    </div>
  </section>

  <!-- ── Row 2: Threat Posture (30s poll, Phase 234 Sub-task B) ──── -->
  <section aria-label="Threat posture">
    <div id="threat-posture-outer"
         hx-get="/api/v1/partials/threat-posture?window=15m"
         hx-trigger="load"
         hx-swap="outerHTML">
      <div class="bg-slate-800 border border-slate-700 rounded-xl p-4 animate-pulse h-48"></div>
    </div>
  </section>

  <!-- ── Row 3: Infrastructure (30s poll, Phase 234 Sub-task C) ──── -->
  <section aria-label="Infrastructure status">
    <div id="infrastructure-outer"
         hx-get="/api/v1/partials/infrastructure"
         hx-trigger="load"
         hx-swap="outerHTML">
      <div class="bg-slate-800 border border-slate-700 rounded-xl p-4 animate-pulse h-24"></div>
    </div>
  </section>

  <!-- ── Row 4: Triage Queue (60s poll, Phase 234 Sub-task D) ────── -->
  <section aria-label="Triage queue">
    <div id="triage-queue-outer"
         hx-get="/api/v1/partials/triage-queue"
         hx-trigger="load"
         hx-swap="outerHTML">
      <div class="bg-slate-800 border border-slate-700 rounded-xl p-4 animate-pulse h-20"></div>
    </div>
  </section>

  <!-- ── Row 5: Live feed + Dial widget (SSE, existing) ─────────── -->
  <section class="grid grid-cols-1 lg:grid-cols-3 gap-6"
           aria-label="Live connections and dial">

    <!-- Live feed (2/3 width) -->
    <div class="lg:col-span-2">
      <div class="bg-[#1e293b] border border-[#334155] rounded-xl overflow-hidden">
        <div class="flex items-center justify-between px-4 py-3 border-b border-[#334155]">
          <div class="flex items-center gap-2">
            <span class="w-2 h-2 rounded-full bg-[#16a34a] animate-pulse"></span>
            <h2 class="text-sm font-semibold text-[#f1f5f9]">Live Connection Feed</h2>
          </div>
          <span class="text-xs text-[#94a3b8]">Latest 50</span>
        </div>
        <div id="live-feed-container">
          {% include "partials/live_feed.html" %}
        </div>
      </div>
    </div>

    <!-- Dial widget (1/3 width) -->
    <div class="lg:col-span-1">
      <div id="dial-widget"
           hx-get="/api/v1/partials/dial"
           hx-trigger="load"
           hx-swap="outerHTML"
           hx-indicator="#htmx-indicator">
        {% include "partials/dial_widget.html" %}
      </div>
    </div>

  </section>

</div>
{% endblock %}
```

---

## 8. Tests

### 8.1 Pytest commands

All commands run from the project root. Per AGENTS.md § Container-Strict Execution,
**never create or use a host venv**. Use the tools container:

```bash
# Run ONLY Phase 234 tests (fast feedback during development)
docker run --rm -v "$PWD":/src -w /src ja4proxy-tools \
  python -m pytest tests/unit/test_pages_rbac.py \
                    tests/unit/test_threat_posture.py \
                    tests/unit/test_infrastructure_partial.py \
                    tests/unit/test_triage_queue.py \
                    -v --timeout=30

# Full suite before merging (mandatory per AGENTS.md)
make test
```

### 8.2 Test coverage table

| Test file | Sub-task covered | Key scenarios |
|---|---|---|
| `tests/unit/test_pages_rbac.py` | A — RBAC | All 4 roles; nav items shown/hidden; 200+HTML for all |
| `tests/unit/test_threat_posture.py` | B — Threat Posture | Top-N ordering; window defaults; JA4 label lookup; stream depth warning; action pct |
| `tests/unit/test_infrastructure_partial.py` | C — Infrastructure | Redis memory colour bands; eviction alert; proxy/analytics up/down states |
| `tests/unit/test_triage_queue.py` | D — Triage Queue | Score filter 35–65; count filter ≥50; dismissed IPs excluded; trend filter; dismiss endpoint writes Redis key with 4h TTL |
| `tests/unit/test_pages.py` (existing, extend) | All | Every page route 200+HTML for all 4 roles; unauthenticated never 500 |

---

## 9. Definition of Done

All of the following must be checked off before this phase is marked COMPLETE
in `docs/phases/manifest.yaml`:

- [ ] `_extract_user_and_role()` helper added to `pages.py`; `role` passed in all
      five page route contexts
- [ ] `base.html` nav items role-gated per the matrix in Section 3.4
- [ ] `GET /api/v1/partials/threat-posture` endpoint implemented in `partials.py`
- [ ] `management/templates/partials/threat_posture.html` created
- [ ] Time window selector persists choice to `localStorage`
- [ ] JA4 label lookup from `config:ja4_labels` working
- [ ] `GET /api/v1/partials/infrastructure` endpoint implemented
- [ ] `management/templates/partials/infrastructure.html` created
- [ ] Proxy heartbeat producer deferred to Phase 239; infra row shows "Unknown" until then
- [ ] HAProxy status documented (N/A fallback acceptable per Section 5.2)
- [ ] `GET /api/v1/partials/triage-queue` endpoint implemented
- [ ] `POST /api/v1/triage/dismiss/{ip}` endpoint implemented
- [ ] `management/templates/partials/triage_queue.html` created
- [ ] `dashboard.html` updated with all four new section slots (Rows 2–4)
- [ ] **Dashboard answers all 17 questions from the Phase 230 gap table**
  (verify each question in `PHASE_230.md` is now answerable from the dashboard)
- [ ] `aiohttp` added to `management/requirements.txt`
- [ ] All unit tests pass with zero warnings: `make test` exits 0
- [ ] `ruff check management/ tests/` exits 0
- [ ] `mypy management/` exits 0 (or all errors are approved exceptions)
- [ ] Changelog fragment added to `docs/fragments/phase-234-<slug>.md`
- [ ] `docs/phases/manifest.yaml` status set to `COMPLETE`
- [ ] PR opened with `gh pr create --base main`; all four CI checks green
- [ ] Merged with `gh pr merge --auto --squash --delete-branch`

---

## 10. Common Mistakes

| Mistake | What goes wrong | How to avoid |
|---|---|---|
| Forgetting to import the new router in `main.py` | Endpoints return 404 silently | After adding a new endpoint, run `curl -s http://localhost:8000/api/v1/partials/threat-posture` and check it doesn't 404 |
| HTMX targeting wrong element ID | Poll updates the wrong part of the DOM | Use browser DevTools → Network tab; watch the HTMX swap; ensure `hx-target` matches the actual element ID |
| XREVRANGE vs XRANGE direction | XREVRANGE returns newest-first; iterating in order gives you the most recent events. XRANGE (used elsewhere in the codebase for oldest-first) would give you stale events if you read from the front | Always use `xrevrange` with `max="+"` and `min=min_id` for "recent events" |
| `current_user[1]` is a `Role` enum, not a string | Jinja2 receives `Role.operator` instead of `'operator'`; `{% if role == 'operator' %}` fails | Always call `.value` in `_extract_user_and_role()`: `role = current_user[1].value` |
| Mocking `get_redis` at the wrong module path | Test passes locally (dev Redis running) but fails in CI | Mock at the import site: `patch("management.api.routes.partials.get_redis")`, not `patch("management.api.redis_client.get_redis")` |
| `os.access` bitmask mocks use equality not `&` | Mock `if mode == os.W_OK` never matches `os.W_OK \| os.R_OK`; test silently passes against dev Redis | Always use `if mode & os.W_OK` (see AGENTS.md Unit test section) |
| Forgetting `aiohttp` import for Prometheus query | `NameError: aiohttp` at runtime, not at import time | Add `import aiohttp` at top of `partials.py`; check `aiohttp` is in `requirements.txt` |
| `hx-confirm=""` on dismiss button showing a dialog | Empty string disables the HTMX confirm behaviour (good). Non-empty string would show `window.confirm()` | Keep `hx-confirm=""` exactly as shown; do not add text |
| Redis `smembers` returns `set` of `bytes` in some drivers | `ip in listed_ips` fails because `ip` is `str` but set contains `bytes` | Check `redis-py` version; `aioredis`/`redis-py` 4.x returns str by default. If in doubt: `listed_ips = {m.decode() if isinstance(m, bytes) else m for m in members}` |
| `_window_min_id` used before `_WINDOW_SECONDS` is defined | `NameError` | Keep helper functions below the constant definitions in the file |
