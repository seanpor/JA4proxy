<!--
title: "Phase 247 — Under-Attack Live Dashboard"
audience: developer
last_reviewed: 2026-06-25
phase: 247
-->

# Phase 247 — Under-Attack Live Dashboard

## Problem Statement

The scenario: it's 2am. A website owner has just deployed JA4proxy because their
contact form is getting hammered. They can see the situation bar turning red. They
can see scores ticking up in the dashboard. But there is no single place that
answers the question they actually have right now:

> **"What is hitting me, and how do I make it stop?"**

The existing dashboard is a monitoring tool. The emergency dial lets you raise the
aggression level. The bans page lets you ban individual IPs. But none of these
surfaces are designed for someone in crisis who needs to act in the next 60 seconds.

This phase adds a dedicated **Under Attack** page — a triage surface that shows
exactly what is hitting the site right now, lets the owner act on each threat with
a single click, and provides an "Attack Mode" toggle that applies a safe, time-limited
defensive posture across the whole proxy without any manual configuration.

## Goals

1. A website owner under active attack can see the top attacking IPs, fingerprints,
   and ASNs within 5 seconds of opening the dashboard.
2. They can tarpit, block, or ban any IP with one click — no forms, no confirmation
   dialogs for the initial action.
3. A single "Attack Mode" button activates a stronger defensive posture and
   auto-reverts after 4 hours so the owner cannot accidentally lock everyone out
   permanently.
4. The page is accessible directly from the situation bar when state is ACTIVE or
   ELEVATED — no navigation required.

## What Already Exists (Do Not Rebuild)

Before writing code, read these carefully. Building on top of existing work is the
entire point of this phase:

- **Situation bar** (`management/templates/partials/situation_bar.html`): already
  shows ACTIVE/ELEVATED states. Phase 247 adds a "View Attack" link to this bar
  when state is ACTIVE or ELEVATED.
- **Emergency dial** (`management/api/routes/dial.py` → `POST /api/v1/dial/emergency`):
  already handles time-limited dial overrides with auto-revert. Attack Mode uses
  this existing endpoint — it does not create a new dial mechanism.
- **Bans API** (`management/api/routes/bans.py`): already handles IP and CIDR bans.
  The one-click ban buttons call this existing API.
- **Live feed partial** (`management/templates/partials/live_feed.html`): already
  shows recent events. The attack page uses a tighter version of this.
- **Datacenter ASN list** (`config/asn_datacenter_list.yml`): already exists with
  hundreds of ASNs for AWS, GCP, Azure, etc. Used to label rows in the attack table.
- **ACTIVE/ELEVATED state logic** (`management/api/routes/partials.py` → `situation`
  partial): already computes the state. Attack Mode reads this to decide if attack
  mode is already justified.

## Sub-phases

### 247.1 — Attack Mode API Endpoint
**Size:** SMALL | **Dependencies:** none

Add `POST /api/v1/attack-mode` — a single endpoint that activates a coordinated
defensive posture. This is distinct from the emergency dial because it does more
than just raise the dial: it also publishes a config event that enables datacenter
tarpitting (Phase 249 will add the full UI for this — here we just wire the dial
half).

**What it does:**
1. Reads the current dial value (save it as `original_dial`).
2. Writes the new dial to Redis and sets the auto-revert record — **do this by
   copying the Redis logic from `management/api/routes/dial.py`**, specifically
   the `await redis.set(_DIAL_KEY, str(75))` and the `config:dial_override` key
   write. Do NOT make an HTTP call to `/api/v1/dial/emergency` from within the
   API itself — internal self-calls are hard to test and create dependency cycles.
   Import `_DIAL_KEY` and `_get_current_dial` from `dial.py` and replicate the
   override write directly.
3. Writes `attack_mode:active` to Redis with a 4-hour TTL.
4. Writes an audit log entry: `attack_mode.activated`.

**Pydantic models:** Add `AttackModeStatus` to `management/api/models.py`:
```python
class AttackModeStatus(BaseModel):
    active: bool
    dial: Optional[int] = None
    original_dial: Optional[int] = None
    reverts_at: Optional[str] = None
    message: str = ""
```

**What "Attack Mode" does NOT do at this phase:**
- It does not change rate limit thresholds (Phase 248 will hook into this).
- It does not enable datacenter blocking (Phase 249 will hook into this).
- It is a dial-only action at this phase; the other phases extend it.

> ⚠ **Sequential implementation note:** Phases 248.5 and 249.5 both modify
> `attack_mode.py`. Implement phases 247, 248, and 249 **in order** — do not
> work on them in parallel.

**Endpoint spec:**

```python
POST /api/v1/attack-mode
Auth: Depends(require_role(Role.admin)) + Depends(require_mfa_verified)
Body: {}  # no required fields

Response 200:
{
  "active": true,
  "dial": 75,
  "original_dial": 0,       # what the dial was before — DELETE restores to this
  "reverts_at": "2026-06-25T06:00:00Z",
  "message": "Attack Mode active. Dial raised to 75. Auto-reverts in 4 hours."
}
```

```python
DELETE /api/v1/attack-mode
Auth: Depends(require_role(Role.admin)) + Depends(require_mfa_verified)

Response 200:
{
  "active": false,
  "dial": 0,           # the original_dial restored from attack_mode:active
  "message": "Attack Mode cancelled. Dial restored to 0."
}
```

The DELETE endpoint must read `original_dial` from the `attack_mode:active` Redis
key before deleting it, and restore the dial to that value — not hardcode 0.
If the owner was at dial=50 before activating Attack Mode, DELETE should restore
to 50, not 0.

```python
GET /api/v1/attack-mode
Auth: Depends(require_role(Role.auditor))
# require_role enforces a minimum role — auditor, analyst, operator, and admin
# are all allowed. See management/api/auth.py for the role hierarchy.

Response 200:
{
  "active": true|false,
  "dial": 75,           # current dial value (or null if not in attack mode)
  "reverts_at": "..."   # ISO8601 timestamp (or null)
}
```

**Redis keys introduced:**
- `attack_mode:active` — String, value is JSON
  `{"activated_at": <epoch>, "original_dial": <int>}`, TTL = 14400s (4 hours).

**File to create:**
`management/api/routes/attack_mode.py`

**Acceptance criteria:**
- [ ] `POST /api/v1/attack-mode` raises dial to 75 by writing to Redis directly
      (not via HTTP self-call to `/api/v1/dial/emergency`)
- [ ] `attack_mode:active` key stores `original_dial` and is set with ≤ 14400s TTL
- [ ] `DELETE /api/v1/attack-mode` restores dial to `original_dial`, not always 0
- [ ] `GET /api/v1/attack-mode` returns `active: true` when the Redis key is present
- [ ] Audit log entries written for activate and deactivate
- [ ] Router registered in `management/api/main.py` (follow the pattern of other
      routers — search for `app.include_router` in that file)
- [ ] Unit tests in `management/tests/test_attack_mode.py` covering all three methods

### 247.2 — Attacker Table API
**Size:** MEDIUM | **Dependencies:** none

Add `GET /api/v1/attack/top` — returns the top attacking IPs right now, enriched
with what we already know about each one.

This endpoint is what powers the live table on the attack page. It is polled every
5 seconds via HTMX.

**How to find the top attackers:**

The proxy writes events to a Redis Stream (`events:connection`). Use
`XREVRANGE events:connection + - COUNT 500` to read the 500 most recent entries.
(`+` = start from newest, `-` = go back to oldest, `COUNT 500` = limit to 500.)

Look at how `management/api/routes/connections.py` does this — search for
`XREVRANGE` in that file and use the same pattern. The `_parse_entry()` function
there shows what fields each stream entry contains. **You can only rely on fields
that `_parse_entry()` already extracts** — the stream does not contain ASN numbers
(that enrichment is added in Phase 249). For Phase 247, use only what is available:
`ip`, `ja4`, `risk_score`, `action_taken`, `timestamp`.

Create a module-level async helper that other phases can reuse:
```python
import time
from .connections import _parse_entry  # reuse existing entry parser

async def _read_attack_window(redis, window_seconds: int = 300) -> list[dict]:
    """Read recent stream events within window_seconds. Returns list of parsed entries."""
    raw = await redis.xrevrange("events:connection", "+", "-", count=500)
    cutoff = time.time() - window_seconds
    entries = []
    for entry_id, fields in raw:
        parsed = _parse_entry(entry_id, fields)
        if parsed and parsed["timestamp"] >= cutoff:
            entries.append(parsed)
    return entries
```

Note: `_parse_entry` is defined in `management/api/routes/connections.py`. Import it
at the top of `attack.py`. It takes `(entry_id, fields)` and returns a dict with
`ip`, `ja4`, `risk_score`, `action_taken`, `timestamp` (Unix float) — or `None`
for malformed entries.

Also check ban status for each top IP with `await redis.exists(f"ban:{ip}")`.

**Response shape:**

```json
{
  "generated_at": "2026-06-25T02:00:00Z",
  "window_seconds": 300,
  "attackers": [
    {
      "ip": "198.51.100.42",
      "connection_count": 847,
      "block_count": 312,
      "max_score": 94,
      "last_seen": "2026-06-25T01:59:58Z",
      "ja4": "t13d1516h2_8daaf6152771_02713d6af862",
      "current_status": "active",   // "active" | "banned"
      "ban_expires": null           // ISO8601 timestamp or null
    }
  ]
}
```

Note: `asn`, `asn_name`, and `is_datacenter` are **not** in this response — ASN
data is not in the event stream. These fields will be added in Phase 249 once
ASN enrichment is wired through. The attack table in 247.3 omits the ASN column
for now.

**Where the enrichment comes from:**
- `ip`, `ja4`, `risk_score`, `action_taken`: from stream entries via `_parse_entry()`
- `block_count`: count of entries for this IP where `action_taken` is `"block"`
- `current_status`: `"banned"` if `ban:{ip}` key exists in Redis, else `"active"`
- `ban_expires`: read the TTL via `await redis.ttl(f"ban:{ip}")` (returns seconds
  remaining, or -2 if key doesn't exist, -1 if key has no TTL). Convert to ISO8601:
  ```python
  from datetime import datetime, timedelta, timezone
  ttl_secs = await redis.ttl(f"ban:{ip}")
  ban_expires = (
      (datetime.now(timezone.utc) + timedelta(seconds=ttl_secs)).isoformat()
      if ttl_secs > 0 else None
  )
  ```
  Note: `redis.ttl()` is available on the management API's aioredis client directly
  (it is NOT on the Go `RedisReader` interface — that interface is Go-only).

**File to create:** `management/api/routes/attack.py`

**Acceptance criteria:**
- [ ] `GET /api/v1/attack/top` returns JSON matching the shape above
- [ ] Response is sorted by `connection_count` descending
- [ ] Only returns IPs with events in the last 300 seconds
- [ ] `current_status: "banned"` for IPs with an active `ban:{ip}` key
- [ ] `current_status: "active"` for all others (there is no separate tarpit state)
- [ ] Request completes in < 200ms (use `XREVRANGE COUNT 500`, not `XLEN`)
- [ ] Redis unavailable → endpoint returns 200 with empty `attackers` list, not 500
- [ ] Unit tests with a mocked Redis client covering: empty stream, mixed traffic,
      banned IP status, events outside the 300s window excluded

### 247.3 — Under-Attack Page (HTML)
**Size:** MEDIUM | **Dependencies:** 247.1, 247.2

Create the `/under-attack` page — the triage surface the owner sees when they click
"View Attack" from the situation bar.

**Layout (top to bottom):**

```
┌─────────────────────────────────────────────────────────────────┐
│  UNDER ATTACK — 847 connections/5min                            │
│  Dial: 75  |  Attack Mode active — reverts in 3h 52m           │
│  [Cancel Attack Mode]  [Raise to 100]                           │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ ATTACK MODE  ❌ inactive                                        │
│                                                                 │
│ [Activate Attack Mode]  ← big, obvious, one-click              │
│                                                                 │
│ Raises protection level. Auto-reverts in 4 hours so you        │
│ cannot accidentally block everyone permanently.                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ TOP ATTACKERS  (last 5 min) — refreshes every 5s               │
├─────┬──────────────┬───────┬──────────┬────────────────────────┤
│ Cnx │ IP           │ Score │ Status   │ Actions                │
├─────┼──────────────┼───────┼──────────┼────────────────────────┤
│ 847 │ 198.51.100.x │  94   │ active   │ [1h Ban]  [24h Ban]    │
│ 423 │ 203.0.113.x  │  87   │ active   │ [1h Ban]  [24h Ban]    │
│ 201 │ 192.0.2.x    │  71   │ banned   │           [Lift Ban]   │
└─────┴──────────────┴───────┴──────────┴────────────────────────┘
```

> **Note on "Ban" vs "Tarpit":** The action buttons create IP bans via the
> existing `POST /api/v1/bans/{ip}` API. A "1h Ban" (`duration_hours=1`) is a
> short hard-block that stops reconnecting bots immediately. A "24h Ban" is a
> longer block for persistent attackers. There is no "tarpit" button because
> tarpitting a specific IP requires the Go proxy to slow its connection — this
> cannot be done from the management API. Do not label any button "Tarpit"
> or the owner will expect different behaviour than they get.

**Implementation notes for the junior engineer:**

The page uses **HTMX** (already used throughout the management UI). The key
HTMX pattern to follow is in `management/templates/dashboard.html` — search for
`hx-trigger="load, every 10s"` to see how the health cards auto-refresh. The
attack table uses the same pattern but with `every 5s` and a different URL.

The "Activate Attack Mode" button sends a POST to the new `/api/v1/attack-mode`
endpoint. After the response, HTMX swaps the attack-mode card to show the active
state and countdown.

Do not use JavaScript for the core functionality. HTMX + the existing Jinja2
template system is sufficient and consistent with the rest of the UI.

**Files to create:**
- `management/templates/under_attack.html` — the page template
- `management/templates/partials/attack_table.html` — the attacker table partial
  (polled separately so only the table refreshes, not the whole page)

**Files to modify:**
- `management/api/routes/pages.py` — add the `/under-attack` route (follow the
  existing pattern for other page routes)
- `management/templates/partials/situation_bar.html` — add "View Attack" link
  when state is ACTIVE or ELEVATED:
  ```html
  {% if state in ("ACTIVE", "ELEVATED") %}
    <a href="/under-attack" class="ml-auto text-xs font-semibold text-red-300 hover:text-red-100 underline">
      View Attack →
    </a>
  {% endif %}
  ```

**Acceptance criteria:**
- [ ] `/under-attack` renders without a 500 error (test with `test_pages.py` pattern)
- [ ] Situation bar shows "View Attack →" link when state is ACTIVE or ELEVATED
- [ ] Situation bar shows no such link when state is NOMINAL
- [ ] Attack mode card shows "inactive" state with Activate button when not in attack mode
- [ ] Attack mode card shows countdown when active (read from `GET /api/v1/attack-mode`)
- [ ] Table auto-refreshes every 5 seconds via HTMX (`hx-trigger="every 5s"`)
- [ ] "1h Ban" button calls `POST /api/v1/bans/{ip}` with `duration_hours=1` and
      `reason="1h ban from attack dashboard"`
- [ ] "24h Ban" button calls `POST /api/v1/bans/{ip}` with `duration_hours=24` and
      `reason="24h ban from attack dashboard"`
- [ ] Banned IPs show "Lift Ban" button that calls `DELETE /api/v1/bans/{ip}`
- [ ] After any action, the table row updates to show the new status

### 247.4 — Sidebar Navigation Link
**Size:** SMALL | **Dependencies:** 247.3

Add "Under Attack" to the sidebar navigation so it is always accessible.

Open `management/templates/base.html` and find where the other sidebar nav links
are defined (search for `href="/dashboard"`). Add an entry in the same format.

To show a live red dot when attack mode is active, add a small HTMX-polled
element inside the nav entry:

```html
<a href="/under-attack" class="nav-link ...">
  Under Attack
  <span id="attack-indicator"
        hx-get="/api/v1/attack-mode"
        hx-trigger="load, every 10s"
        hx-target="#attack-indicator"
        hx-swap="outerHTML">
  </span>
</a>
```

Then add a partial endpoint to `management/api/routes/partials.py` (or
`attack_mode.py`) that returns an empty string when inactive, or
`<span class="w-2 h-2 rounded-full bg-red-500 ml-1 inline-block"></span>`
when active. This is the same polling pattern used elsewhere in the UI.

**Acceptance criteria:**
- [ ] "Under Attack" appears in sidebar nav
- [ ] Nav link shows a red dot when `GET /api/v1/attack-mode` returns `active: true`
- [ ] Red dot disappears within 10 seconds of attack mode deactivating
- [ ] Link goes to `/under-attack`

### 247.5 — Tests
**Size:** MEDIUM | **Dependencies:** 247.1, 247.2, 247.3

**`management/tests/test_attack_mode.py`** (unit + integration):
- POST activates: GET returns `active: true`, dial is 75
- DELETE deactivates: GET returns `active: false`, dial restored to `original_dial`
- POST when already active: returns 200 with existing state (idempotent — does not reset TTL)
- DELETE when not active: returns 200 gracefully (no error)
- `attack_mode:active` key TTL is ≤ 14400 seconds (4 hours)
- `original_dial` stored correctly (e.g. if dial was 50, DELETE restores to 50 not 0)
- Audit log entry written on POST and DELETE
- Redis unavailable: POST returns 500 (this is a write path — fail closed is correct here)

**`management/tests/test_attack.py`** (unit):
- `GET /api/v1/attack/top` with empty stream returns `{"attackers": []}`
- IPs with events in last 300s appear in results
- IPs with only events older than 300s do NOT appear
- Banned IP gets `current_status: "banned"` and non-null `ban_expires`
- Active IP gets `current_status: "active"` and null `ban_expires`
- Results sorted by `connection_count` descending
- Redis unavailable → returns 200 with empty list (fail open)

**`management/tests/test_pages.py`** (extend existing file):
- `GET /under-attack` → 200 + HTML + "Under Attack" string
- `GET /under-attack` without auth → status < 500 (redirect is fine, 500 is not)
- Situation bar rendered with `state="ACTIVE"` contains `href="/under-attack"`
- Situation bar rendered with `state="NOMINAL"` does NOT contain `href="/under-attack"`

## Out of Scope

- Mobile notifications / push alerts (separate phase)
- WebSocket real-time streaming (HTMX polling is sufficient and simpler)
- Country-based blocking UI (separate phase — Phase 249 covers ASN blocking)
- Automatic attack detection (the owner decides when to activate attack mode)
- Changes to the Go proxy binary (this phase is management UI only)

## Architecture Notes for Junior Engineers

**Why HTMX polling instead of WebSockets?**

WebSockets are stateful connections — each needs to be managed, and they add
complexity to the server. HTMX polling (`hx-trigger="every 5s"`) is a simple
HTTP GET every 5 seconds. At the scale this proxy runs (one website owner, not
a CDN), polling is perfectly adequate and much simpler to debug. Look at how
`dashboard.html` uses `hx-trigger="every 10s"` on the health cards for the pattern.

**Why does Attack Mode auto-revert?**

The most common failure mode for a desperate operator is "I raised the dial to
100 at 2am and forgot, and at 9am my site was blocking real users." Auto-revert
after 4 hours means the worst case is "it reverts to the previous level at 6am"
— the owner wakes up, traffic is back, and they can decide whether to re-activate
during business hours.

**Why dial=75 and not dial=100?**

Dial=100 applies configured thresholds exactly. At default thresholds, a score
of 70+ triggers a block. Dial=75 interpolates those thresholds upward, meaning
more traffic gets through. This is intentional — the goal is to block the obvious
bots while keeping real browsers working. Legitimate browsers will have low risk
scores regardless of dial setting.

## Redis Keys Introduced

| Key | Type | TTL | Purpose |
|-----|------|-----|---------|
| `attack_mode:active` | String (JSON) | 14400s | Tracks active attack mode state |

## CHANGELOG Fragment

Add `docs/fragments/phase-247-attack-dashboard.md`:

```markdown
### Added
- Under Attack dashboard page: live table of top attackers, one-click tarpit/block/ban actions
- Attack Mode toggle: raises dial to 75 with 4-hour auto-revert
- Situation bar now links to Under Attack page when state is ACTIVE or ELEVATED
```
