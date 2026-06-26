<!--
title: "Phase 250 — Botnet Fingerprint Detection & One-Click Block"
audience: developer
last_reviewed: 2026-06-25
phase: 250
-->

# Phase 250 — Botnet Fingerprint Detection & One-Click Block

## The Scenario This Phase Solves

The attacker has a residential botnet — hundreds of compromised home machines,
each with a different IP address. Phases 247 (attack dashboard) and 249
(datacenter block) do not help: the IPs are residential, not datacenter, and
there are too many of them to ban one by one.

But there is a weakness. Every machine in the botnet runs the **same bot software**
— the same Python library, the same Node.js scraper, the same exploit kit. That
software produces an **identical JA4 TLS fingerprint** on every connection, from
every IP, regardless of which machine is making the request.

Blocking a single IP does nothing. Blocking the **JA4 fingerprint** blocks every
machine in the botnet simultaneously — including new machines added to the botnet
after the block is placed — because the block applies to the software, not the IP.

This phase adds:
1. A fingerprint-centric attack view showing which JA4s are driving the current
   attack, grouped across all IPs using them.
2. A botnet detection signal: "this fingerprint appeared on 10 different residential
   IPs in the last 5 minutes, all scoring above 70, and it is not a known browser."
3. A one-click block that adds the fingerprint to the JA4 blacklist — stopping the
   entire botnet in a single action.
4. A safety gate that prevents accidentally blocking a real browser fingerprint.

## What Already Exists (Do Not Rebuild)

This phase is almost entirely UI and API wiring. The detection and blocking
infrastructure already exists:

- **`fixtures/ti_feeds/ja4_fp_corpus.txt`**: Known-good browser JA4 fingerprints
  (Chrome 119/120, Firefox 115/121, Safari 17, Edge 120, Mobile Safari). Used by
  `src/analytics/ti_feeds/ja4_safety.py::is_known_browser_ja4()` to prevent TI
  feeds from blocking browsers. Phase 250 uses this same corpus as the safety gate
  in the attack UI.

- **`src/analytics/ti_feeds/ja4_safety.py`**: `is_known_browser_ja4(ja4: str) -> bool`
  — cached LRU check against the corpus. Already works in the `src/` package.
  **Do NOT import this from `management/`** — `src/` and `management/` are separate
  packages. See 250.2 for the in-package wrapper (`management/api/ja4_corpus.py`).

- **`management/api/routes/lists.py`**: `POST /api/v1/lists/ja4/blacklist/{entry}` —
  already adds a fingerprint to the JA4 blacklist. The block button calls this.
  Already audited, already authenticated.

- **`management/templates/fingerprint.html`**: Already has a per-fingerprint detail
  page with Block and Allowlist buttons and an "Associated IPs" panel. The attack
  tab links to these pages for drill-down.

- **`management/api/routes/partials.py`**: Already computes `top_ja4` (top 10 JA4s
  by connection count) from the event stream over a 5-minute window, and looks up
  human labels from `config:ja4_labels`. Phase 250 extends this aggregation with
  unique-IP count, average score, and botnet signal.

- **`management/api/routes/connections.py`**: Already has per-fingerprint profile
  aggregation from the event stream. Phase 250's new endpoint uses the same
  `XREVRANGE events:connection + - COUNT 500` pattern.

- **`internal/logging/ecs_formatter.go`**: Already writes both `ja4proxy.fingerprint.ja4`
  and `ja4proxy.fingerprint.ja4t` to stream events. JA4T is present when the
  passive TAP sidecar has captured it. Both fields are available in the management
  API without any Go changes.

- **`management/templates/under_attack.html`** (created in Phase 247.3): The
  Fingerprint tab created in this phase is added to that page as a second tab.

## Goals

1. An owner under bot attack can switch from the IP tab to the Fingerprint tab
   on the Under Attack page and see immediately: "fingerprint X is driving 847
   connections from 23 different residential IPs — not a known browser."
2. They can block that fingerprint with one click, stopping all 23 IPs plus any
   new botnet machines added later.
3. If they try to block a known-browser fingerprint, the UI stops them with a
   clear warning — this would affect all real users with that browser.
4. After blocking, the table confirms the fingerprint is now blacklisted.

## Sub-phases

### 250.1 — Expand and Version the Known-Browser Corpus
**Size:** SMALL | **Dependencies:** none

The existing corpus (`fixtures/ti_feeds/ja4_fp_corpus.txt`) has ~8 entries and
no version metadata. This is the safety gate — if it is incomplete, the UI might
let the owner block Chrome accidentally.

Expand it with all major browser fingerprints that are currently in use, and add
metadata so the UI can show a human-readable browser name next to the fingerprint.

**What to add to the corpus file:**

The existing corpus already contains verified entries (see the file header for
their provenance). Add additional entries by checking the public JA4 database.
Rather than leaving this as unspecified research, here are the fingerprints
already in the corpus file that you can use as your starting point — the task
is to **verify these are still current and add any missing major browsers**:

```
# Already in fixtures/ti_feeds/ja4_fp_corpus.txt:
t13d1516h2_8daaf6152771_02713d6af862   # Chrome 120 (desktop)
t13d1517h2_8daaf6152771_e5627efa2ab1   # Chrome 120 (desktop variant)
t13d1516h2_8daaf6152771_b1ff8ab2d16f   # Chrome 119 (desktop)
t13d1715h2_5b57614c22b0_3d5424432f57   # Firefox 121 (desktop)
t13d1714h2_5b57614c22b0_eeeeabababab   # Firefox 115 ESR
t13d1517h2_e8f1e7e78f70_b0da82dd1658   # Safari 17 / Mobile Safari iOS 17
```

To find fingerprints for browsers not yet in the corpus (Chrome on Android,
Edge, Samsung Internet, Brave, Firefox 122/123): open a browser in a network
capture tool (e.g. Wireshark or mitmproxy) and connect to a test server. The
JA4 fingerprint will be in the proxy logs. Alternatively, check
https://ja4db.com/ and search by browser name — it is a public read-only
lookup. Add verified entries only; do not guess.

**The corpus is the safety gate.** Only add fingerprints you have verified.
An incorrect entry that lists a bot fingerprint as a browser will prevent the
owner from blocking it. If you are unsure about an entry, leave it out.

**Important distinction:**
- **Known-browser corpus** (safe list): only fingerprints that real users produce.
  Chrome, Firefox, Safari, Edge, Samsung, Brave. These may NEVER be blocked from
  the attack UI.
- **Known-tool labels** (informational): curl, wget, Python requests, Go net/http.
  These get labels in the UI ("curl/libcurl") but are NOT in the safe corpus —
  the owner can choose to block them.

**New file: `fixtures/ti_feeds/ja4_browser_labels.json`**

Alongside the corpus text file, add a JSON file that maps JA4 fingerprint to
a human-readable browser name. The attack UI uses this for display.

```json
{
  "t13d1516h2_8daaf6152771_02713d6af862": "Chrome 120 (desktop)",
  "t13d1517h2_8daaf6152771_e5627efa2ab1": "Chrome 120 (desktop, variant)",
  "t13d1715h2_5b57614c22b0_3d5424432f57": "Firefox 121 (desktop)",
  "t13d1517h2_e8f1e7e78f70_b0da82dd1658": "Safari 17 / Mobile Safari (iOS 17)",
  ...
}
```

**Also add known-tool labels (these are NOT in the corpus — just labels):**
```json
{
  "t13d190900_9dc949149365_97f8aa674fd9": "curl 8.x",
  "t13d190900_9dc949149365_e7c285222651": "Python requests 2.x",
  "t13d190900_9dc949149365_a56c0480a5c1": "Go net/http"
}
```

**Modify `management/api/routes/partials.py`:**

Where it does `label = await redis.hget(_JA4_LABELS_KEY, fp)`, add a fallback:
if no Redis label exists, check `ja4_browser_labels.json` (loaded at startup
into a module-level dict). Load the JSON file once at module import time, not
per-request.

**Acceptance criteria:**
- [ ] Corpus has ≥ 10 verified entries covering Chrome, Firefox, Safari.
      Note: Edge and Brave share Chrome's JA4 fingerprint (Chromium-based) — document
      this in a comment rather than adding duplicate entries.
- [ ] `ja4_browser_labels.json` exists with labels for corpus fingerprints + common tools
- [ ] `management/api/ja4_corpus.py::is_known_browser()` returns `True` for all corpus fingerprints
- [ ] `is_known_browser()` returns `False` for `curl` and `Python requests` fingerprints
- [ ] Management UI partials fall back to `ja4_browser_labels.json` for label lookup
- [ ] Existing `test_ja4_safety.py` tests still pass (they test the `src/` version, not the management one)

### 250.2 — Attack Fingerprint Aggregation API
**Size:** MEDIUM | **Dependencies:** 250.1

Add `GET /api/v1/attack/top-fingerprints` — the fingerprint-centric equivalent
of Phase 247's `GET /api/v1/attack/top` (IP-centric).

This endpoint reads the recent event stream, aggregates by JA4 fingerprint, and
returns the fingerprints that are most active during the attack window.

**Algorithm:**

```
1. XREVRANGE events:connection + - COUNT 500
   (same as Phase 247's top-IP endpoint — reuse the helper)

2. Filter to events in the last 300 seconds.

3. Group by ja4proxy.fingerprint.ja4:
   - total connection count
   - set of unique client IPs seen with this fingerprint
   - list of scores (for avg and max)
   - set of actions taken (allow/flag/tarpit/block/ban)
   - set of JA4T values seen with this fingerprint (if present in events)
   - set of countries seen
   - set of ASNs seen

4. For each fingerprint, compute:
   - unique_ip_count = len(unique IPs)
   - avg_score = mean of scores
   - max_score = max of scores
   - is_known_browser = check against corpus (see below)
   - browser_label = label from ja4_browser_labels.json (or "" if unknown)
   - is_blacklisted, is_whitelisted = batch check (see below)
   - botnet_signal = detect_botnet_signal(unique_ip_count, avg_score, is_known_browser)

5. Sort by (unique_ip_count DESC, total_connections DESC).
   Return top 20.
```

**`detect_botnet_signal(unique_ip_count, avg_score, is_known_browser)` logic:**

```python
def detect_botnet_signal(unique_ip_count: int, avg_score: float, is_known_browser: bool) -> str:
    """
    Returns:
      "botnet"   — strong indicator: many IPs, high score, not a browser
      "suspect"  — moderate indicator: several IPs, elevated score, not a browser
      "tool"     — automated tool (e.g. curl) but not necessarily malicious
      "browser"  — known browser fingerprint
      "unknown"  — not enough data to classify
    """
    if is_known_browser:
        return "browser"
    if unique_ip_count >= 5 and avg_score >= 60:
        return "botnet"
    if unique_ip_count >= 3 and avg_score >= 40:
        return "suspect"
    if unique_ip_count >= 2:
        return "tool"
    return "unknown"
```

These thresholds are intentionally conservative. A fingerprint needs both spread
(multiple IPs) AND elevated scores to be called a botnet. A single high-scoring
IP does not qualify.

**Response shape:**

```json
{
  "generated_at": "2026-06-25T02:00:00Z",
  "window_seconds": 300,
  "fingerprints": [
    {
      "ja4": "t13d190900_9dc949149365_e7c285222651",
      "browser_label": "",
      "total_connections": 847,
      "unique_ip_count": 23,
      "avg_score": 82.4,
      "max_score": 97,
      "is_known_browser": false,
      "is_blacklisted": false,
      "is_whitelisted": false,
      "botnet_signal": "botnet",
      "ja4t_values": ["1460_2_1_8192_7"],
      "countries": ["US", "DE", "BR", "IN"],
      "asn_count": 19,
      "sample_ips": ["198.51.100.1", "198.51.100.2", "203.0.113.5"]
    },
    {
      "ja4": "t13d1516h2_8daaf6152771_02713d6af862",
      "browser_label": "Chrome 120 (desktop)",
      "total_connections": 412,
      "unique_ip_count": 389,
      "avg_score": 12.3,
      "max_score": 31,
      "is_known_browser": true,
      "is_blacklisted": false,
      "is_whitelisted": false,
      "botnet_signal": "browser",
      "ja4t_values": [],
      "countries": ["US", "GB", "DE", "FR", "AU"],
      "asn_count": 201,
      "sample_ips": []
    }
  ]
}
```

Note: `sample_ips` is only populated for non-browser fingerprints (up to 5 IPs
for drill-down links). Browser fingerprints omit it — listing IPs for Chrome
users is not useful and could be misleading.

**`is_known_browser` check — do NOT import from `src/`:**

`src/analytics/ti_feeds/ja4_safety.py` contains `is_known_browser_ja4()` but
`src/` and `management/` are separate packages on potentially different
`PYTHONPATH`s. Do not import across packages. Instead, create a small helper
in the management package:

```python
# management/api/ja4_corpus.py
import json
from functools import lru_cache
from pathlib import Path

# Use __file__-relative paths so this works regardless of where the process starts.
# management/api/ja4_corpus.py → .parents[3] = repo root.
_CORPUS_PATH = Path(__file__).parents[3] / "fixtures" / "ti_feeds" / "ja4_fp_corpus.txt"
_LABELS_PATH = Path(__file__).parents[3] / "fixtures" / "ti_feeds" / "ja4_browser_labels.json"

def _load_corpus() -> frozenset[str]:
    try:
        lines = _CORPUS_PATH.read_text().splitlines()
        return frozenset(l.strip() for l in lines if l.strip() and not l.startswith("#"))
    except Exception:
        return frozenset()

def _load_labels() -> dict[str, str]:
    try:
        return json.loads(_LABELS_PATH.read_text())
    except Exception:
        return {}

_CORPUS: frozenset[str] = _load_corpus()
_LABELS: dict[str, str] = _load_labels()

@lru_cache(maxsize=10000)
def is_known_browser(ja4: str) -> bool:
    return ja4 in _CORPUS

def browser_label(ja4: str) -> str:
    return _LABELS.get(ja4, "")
```

Import from `management.api.ja4_corpus` in `attack.py`.

**Batch blacklist/whitelist check:**

For up to 20 fingerprints, checking `SISMEMBER ja4:blacklist` 20 times is 20
round-trips. Use `SMISMEMBER` (available in Redis 6.2+, which this deployment
requires) to batch the checks:

```python
fingerprints = list(fp_data.keys())
blacklisted = await redis.smismember("ja4:blacklist", fingerprints)
whitelisted = await redis.smismember("ja4:whitelist", fingerprints)
# blacklisted and whitelisted are lists of booleans in the same order as fingerprints
```

Check whether `redis.smismember` is available on the redis client wrapper. If
not (older redis-py), fall back to `asyncio.gather()` with individual `sismember`
calls: `await asyncio.gather(*[redis.sismember("ja4:blacklist", fp) for fp in fingerprints])`.

**Reuse the event window helper from Phase 247.2:**

Phase 247.2 defines `_read_attack_window(redis, window_seconds)` in `attack.py`.
Call that function here — do not re-read the stream independently.

**File to create:** add to `management/api/routes/attack.py` (created in Phase 247.2)

**Auth:** `Depends(require_role(Role.auditor))` — same as the IP attack endpoint.

**Acceptance criteria:**
- [ ] Endpoint returns fingerprints sorted by unique_ip_count DESC
- [ ] Only fingerprints with events in the last 300 seconds appear
- [ ] `botnet_signal: "botnet"` for fingerprints with ≥ 5 IPs and avg_score ≥ 60
- [ ] `botnet_signal: "browser"` for all corpus fingerprints
- [ ] `is_blacklisted: true` for fingerprints in `ja4:blacklist`
- [ ] `is_whitelisted: true` for fingerprints in `ja4:whitelist`
- [ ] Blacklist/whitelist check uses batch SMISMEMBER (not N individual calls)
- [ ] `is_known_browser` uses `management/api/ja4_corpus.py`, not `src/` import
- [ ] `ja4t_values` populated when `ja4proxy.fingerprint.ja4t` is present in events
- [ ] Response in < 300ms
- [ ] Redis unavailable → returns 200 with empty fingerprints list (fail open)
- [ ] Unit tests covering all `botnet_signal` classification paths

### 250.3 — Fingerprint Tab on Under Attack Page
**Size:** MEDIUM | **Dependencies:** 247.3, 250.2

Add a "Fingerprints" tab to the `/under-attack` page created in Phase 247.3.
The page currently has an IP table. This phase adds a second tab that shows
the fingerprint view.

**Tab layout:**

```
┌─────────────────────────────────────────────────────────────────┐
│  [● IPs]  [ Fingerprints]                                      │
└─────────────────────────────────────────────────────────────────┘
```

**Fingerprint tab content:**

```
┌─────────────────────────────────────────────────────────────────┐
│ TOP FINGERPRINTS (last 5 min) — refreshes every 5s             │
│                                                                 │
│ ⚠ 1 botnet fingerprint detected                                │
│   Blocking it will stop all 23 attacking IPs at once.          │
└─────────────────────────────────────────────────────────────────┘

┌──────┬──────────────────────────────────┬──────┬──────┬───────────────────┬──────────────┐
│ IPs  │ Fingerprint                      │Score │Signal│ Label             │ Action       │
├──────┼──────────────────────────────────┼──────┼──────┼───────────────────┼──────────────┤
│  23  │ t13d190900_9dc9...e7c2  [detail] │ 82   │🔴 BOTNET│ —             │ [Block]      │
│   4  │ t13d190900_9dc9...a56c  [detail] │ 61   │🟡 SUSPECT│ —            │ [Block]      │
│ 389  │ t13d1516h2_8daa...6af8  [detail] │ 12   │🟢 BROWSER│ Chrome 120   │ —            │
└──────┴──────────────────────────────────┴──────┴──────┴───────────────────┴──────────────┘
```

**Columns:**
- **IPs**: unique IP count using this fingerprint (the key signal — click to expand list)
- **Fingerprint**: truncated (show first 18 + last 4 chars), link to `/fingerprint/{ja4}`
- **Score**: average risk score across all connections with this fingerprint
- **Signal**: coloured badge — 🔴 BOTNET, 🟡 SUSPECT, 🔵 TOOL, 🟢 BROWSER, ⚪ UNKNOWN
- **Label**: browser name or tool name from `ja4_browser_labels.json` (empty if unknown)
- **Action**: Block button (see 250.4 for safety gate rules)

**JA4T column (shown only when data is available):**
If any fingerprint in the response has `ja4t_values` populated, show a JA4T column:
```
│ JA4T           │
│ 1460_2_1_8192  │   ← single consistent TCP fingerprint = all same OS/device
│ (3 variants)   │   ← multiple TCP fingerprints = different machines
```

A botnet where all machines share the same JA4T is even more clearly a single
campaign — the attacker is using identical images or the same OS version across
all compromised machines. Show this as additional context in the detail popover.

**Summary banner:**
Above the table, show a one-line summary when a botnet signal is detected:
```html
{% if botnet_count > 0 %}
<div class="bg-red-900/30 border border-red-700 rounded p-3 mb-4">
  <p class="text-sm text-red-200 font-semibold">
    ⚠ {{ botnet_count }} botnet fingerprint{{ 's' if botnet_count != 1 }}
    detected across {{ total_botnet_ips }} IPs.
    Blocking {{ 'it' if botnet_count == 1 else 'them' }} will stop all
    {{ total_botnet_ips }} attacking IPs at once.
  </p>
</div>
{% endif %}
```

**IP detail popover:**
When the owner clicks the IP count number, show a small popover listing the
sample IPs (from `sample_ips` in the API response), each linking to the IP
detail page. This helps them verify these are legitimately attacking IPs before
blocking the fingerprint.

**Tab-switching with Alpine.js:**

The existing `under_attack.html` already uses Alpine.js for other interactions.
Add `x-data` to the tab container and use `x-show` to hide/show panels:

```html
<!-- Tab container — wrap both the tabs and both panels in this div -->
<div x-data="{ tab: 'ips' }">

  <!-- Tab buttons -->
  <div class="flex gap-2 mb-4">
    <button @click="tab = 'ips'"
            :class="tab === 'ips' ? 'bg-slate-700 text-white' : 'text-slate-400'"
            class="px-4 py-2 text-sm font-semibold rounded">
      IPs
    </button>
    <button @click="tab = 'fingerprints'"
            :class="tab === 'fingerprints' ? 'bg-slate-700 text-white' : 'text-slate-400'"
            class="px-4 py-2 text-sm font-semibold rounded">
      Fingerprints
    </button>
  </div>

  <!-- IPs panel (existing content, wrap in x-show) -->
  <div x-show="tab === 'ips'">
    <!-- existing IP table with HTMX polling -->
  </div>

  <!-- Fingerprints panel (new) -->
  <div x-show="tab === 'fingerprints'">
    <div hx-get="/api/v1/partials/attack-fingerprint-table{% if attack_mode_active %}?attack_mode=true{% endif %}"
         hx-trigger="load, every 5s"
         hx-swap="innerHTML">
      <p class="text-slate-400 text-sm">Loading fingerprints...</p>
    </div>
  </div>

</div>
```

Note `{% if attack_mode_active %}?attack_mode=true{% endif %}` — the page route
must pass `attack_mode_active` as a template variable. Read it from Redis:

```python
# In the /under-attack page route in pages.py:
attack_raw = await redis.get("attack_mode:active")
attack_mode_active = attack_raw is not None  # key exists = attack mode is on
return templates.TemplateResponse("under_attack.html", {
    ...,
    "attack_mode_active": attack_mode_active,
})
```

**Also add a partial route to `management/api/routes/partials.py`:**

The HTMX polls `/api/v1/partials/attack-fingerprint-table` — this route must
exist or HTMX will get a 404. Add it following the same pattern as
`threat_posture_partial` in `partials.py`:

```python
@router.get("/api/v1/partials/attack-fingerprint-table",
            response_class=HTMLResponse)
async def attack_fingerprint_table_partial(
    request: Request,
    attack_mode: bool = Query(False),
    current_user=Depends(require_role(Role.auditor)),
    redis=Depends(get_redis),
):
    from .attack import top_fingerprints  # reuse JSON endpoint logic
    data = await top_fingerprints(attack_mode=attack_mode, redis=redis)
    return templates.TemplateResponse(
        "partials/attack_fingerprint_table.html",
        {"request": request, "data": data, "attack_mode": attack_mode}
    )
```

Note: the JSON endpoint `GET /api/v1/attack/top-fingerprints` (from 250.2) is
for programmatic consumers (API clients, tests). The partial route is what HTMX
calls — it renders the HTML table. Both call the same underlying logic.

**Files to modify:**
- `management/templates/under_attack.html` — add tab switcher and fingerprint tab content
- `management/templates/partials/attack_fingerprint_table.html` — new HTML partial
- `management/api/routes/partials.py` — add the partial route (above)
- `management/api/routes/pages.py` — pass `attack_mode_active` to template

**Acceptance criteria:**
- [ ] Tab switcher shows "IPs" and "Fingerprints" tabs; clicking switches content
- [ ] `GET /api/v1/partials/attack-fingerprint-table` returns HTML (not 404)
- [ ] Fingerprint table auto-refreshes every 5 seconds via HTMX
- [ ] `GET /api/v1/attack/top-fingerprints` returns JSON for programmatic use
- [ ] BOTNET rows have red badge; BROWSER rows have green badge
- [ ] Summary banner shows when ≥ 1 BOTNET fingerprint detected
- [ ] IP count links to a popover showing sample IPs
- [ ] Fingerprint text links to `/fingerprint/{ja4}` detail page
- [ ] JA4T column appears when any fingerprint has JA4T data
- [ ] Chrome/Firefox/Safari rows show their browser label
- [ ] `attack_mode=true` passed to partial route when Attack Mode is active

### 250.4 — Block Safety Gate
**Size:** SMALL | **Dependencies:** 250.2, 250.3

The most catastrophic mistake possible in this UI is blocking Chrome 120 or
Firefox 121. It would shut out the majority of real users. The safety gate
prevents this.

**Rules:**

| Fingerprint status | Block button behaviour |
|----|-----|
| `botnet_signal: "botnet"` or `"suspect"` or `"tool"` | Button shown normally, no extra confirmation |
| `botnet_signal: "unknown"` | Button shown with a warning tooltip |
| `botnet_signal: "browser"` | Button is **disabled** with a clear explanation |
| Already blacklisted | Button replaced with "Blocked ✓" (static text) |
| Already whitelisted | Button replaced with "Allowlisted" (whitelisted fingerprints are bypassed before the blacklist is checked — explain this) |

**Implementation for browser fingerprints:**

```html
<!-- When botnet_signal == "browser" -->
<button disabled
  class="px-3 py-1 text-xs font-semibold rounded bg-slate-700 text-slate-500 cursor-not-allowed"
  title="Cannot block: this is a {{ browser_label or 'known browser' }} fingerprint.
         Blocking it would affect all your real visitors using this browser.
         If you believe this is wrong, go to the fingerprint detail page to override.">
  Protected
</button>
```

The "go to fingerprint detail page to override" link in the tooltip provides an
escape hatch: the existing `/fingerprint/{ja4}` page already has a Block button
with no safety gate (it is assumed the user knows what they are doing on the
detail page). The attack UI is the place for the protective guardrail, not the
detail page.

**Also add safety gate to the `POST /api/v1/lists/ja4/blacklist/{entry}` API
when called via the attack UI:**

> **This is a UX guardrail, not a security gate.** It prevents accidental blocking
> via the attack UI dashboard. It does not prevent a determined admin from
> blocking a browser fingerprint — they can always go to the fingerprint detail
> page, or call the API directly without the `source` parameter. Do not treat
> this as a security control.

The existing lists API has no safety gate at the API level. Add an **optional**
query parameter `source`:

```python
# In lists.py, on the blacklist POST endpoint:
from typing import Optional
from fastapi import Query

@router.post("/api/v1/lists/ja4/blacklist/{entry}", ...)
async def blacklist_ja4(
    entry: str,
    source: Optional[str] = Query(None),  # ← add this
    ...
):
    if source == "attack_ui":
        from ..ja4_corpus import is_known_browser
        if is_known_browser(entry):
            raise HTTPException(
                status_code=422,
                detail=f"Safety gate: '{entry}' is in the known-browser corpus. "
                       f"Blocking it would affect real users. "
                       f"Use the fingerprint detail page to override."
            )
    # ... existing logic unchanged ...
```

When `source=attack_ui` is present AND the fingerprint is in the known-browser
corpus, return HTTP 422. No other behaviour changes.

The attack UI's Block button includes `?source=attack_ui` in the HTMX request.
The fingerprint detail page's Block button does not — so the detail page retains
the ability to block any fingerprint for advanced users who know what they are doing.

**File to modify:**
- `management/api/routes/lists.py` — add optional `source` query param and corpus check
- `management/templates/under_attack.html` / `partials/attack_fingerprint_table.html` —
  implement disabled state for browser fingerprints

**Acceptance criteria:**
- [ ] Browser fingerprints have a disabled "Protected" button in the attack table
- [ ] `POST /api/v1/lists/ja4/blacklist/{entry}?source=attack_ui` returns 422 for corpus fingerprints
- [ ] Same endpoint without `?source=attack_ui` still works (fingerprint detail page)
- [ ] Blocked fingerprints show "Blocked ✓" static text in the table (no re-block option)
- [ ] Tooltip on "Protected" button explains why and links to detail page
- [ ] Unit test: `source=attack_ui` + corpus fingerprint → 422
- [ ] Unit test: `source=attack_ui` + non-corpus fingerprint → 200

### 250.5 — Attack Mode Integration
**Size:** SMALL | **Dependencies:** 247.1, 250.2

When Attack Mode (Phase 247) is active, the Fingerprint tab should switch to
a more aggressive botnet detection threshold — lower the `unique_ip_count` and
`avg_score` thresholds for `"botnet"` signal to catch emerging campaigns faster:

```python
# Normal mode:   5 unique IPs, avg_score >= 60
# Attack Mode:   3 unique IPs, avg_score >= 50

if attack_mode_active:
    thresholds = {"botnet_ips": 3, "botnet_score": 50, "suspect_ips": 2, "suspect_score": 30}
else:
    thresholds = {"botnet_ips": 5, "botnet_score": 60, "suspect_ips": 3, "suspect_score": 40}
```

Pass `attack_mode_active` from `GET /api/v1/attack-mode` to `detect_botnet_signal()`.

Also: when the owner blocks a BOTNET-signal fingerprint during Attack Mode, write
an audit entry with `"context": "attack_mode"` so it is distinguishable from
routine fingerprint management.

**Acceptance criteria:**
- [ ] `GET /api/v1/attack/top-fingerprints` accepts `?attack_mode=true` query param
- [ ] When `attack_mode=true`, thresholds lower as documented
- [ ] Fingerprint tab in the attack page passes `attack_mode=true` when Attack Mode is active
- [ ] Audit log entry includes `"context": "attack_mode"` for blocks during attack mode

### 250.6 — Tests
**Size:** MEDIUM | **Dependencies:** 250.1–250.5

**`management/tests/test_attack_fingerprints.py`:**

```python
# Botnet detection
- 1 fingerprint, 23 IPs, avg_score=82 → botnet_signal="botnet"
- 1 fingerprint, 4 IPs, avg_score=61 → botnet_signal="suspect"
- Chrome 120 fingerprint → botnet_signal="browser" regardless of IP count or score
- 1 fingerprint, 1 IP → botnet_signal="unknown"
- attack_mode=true lowers thresholds (3 IPs + score 50 → "botnet")

# API response
- Returns fingerprints sorted by unique_ip_count DESC
- Only last-300s events included
- Blacklisted fingerprint shows is_blacklisted=true
- sample_ips omitted for browser fingerprints
- JA4T column populated when ja4proxy.fingerprint.ja4t present in events
- Redis unavailable → returns 200 with empty list (fail open, not 500)

# Safety gate
- POST /api/v1/lists/ja4/blacklist/{chrome_fp}?source=attack_ui → 422
- POST /api/v1/lists/ja4/blacklist/{bot_fp}?source=attack_ui → 200
- POST /api/v1/lists/ja4/blacklist/{chrome_fp} (no source param) → 200

# Corpus (tests call management/api/ja4_corpus.py::is_known_browser(), not the src/ version)
- All corpus fingerprints return is_known_browser()=True
- Python requests fingerprint returns is_known_browser()=False
```

**`management/tests/test_pages.py`** (extend):
- Under attack page with fingerprint tab renders → 200 + HTML + "Fingerprints" string

**`src/tests/test_ja4_safety.py`** (extend if it exists, or create):
- Corpus loads successfully from `fixtures/ti_feeds/ja4_fp_corpus.txt`
- All expanded corpus entries return `is_known_browser_ja4=True`
- `ja4_browser_labels.json` loads and contains labels for all corpus entries

## Out of Scope

- JA4H (HTTP header fingerprinting) — JA4proxy is TLS-passthrough and does not
  see HTTP headers. This would require a different architecture.
- JA4X (TLS certificate fingerprinting) — already exists in the proxy and scoring
  but is a separate signal; adding it to this view is future work.
- Automatic fingerprint blocking (no automation — the owner makes the decision).
- Fingerprint sharing / threat intel feeds (separate phase).
- Historical fingerprint trends beyond the 5-minute attack window (the full
  fingerprint detail page covers 24h history).

## Architecture Notes for Junior Engineers

**Why does blocking a JA4 fingerprint stop a residential botnet?**

The Go proxy's first bypass check is: "Is this JA4 fingerprint in the blacklist?
BLOCK immediately." This check runs before IP checks, before scoring, before
anything else. It is a Redis SET membership check (`SISMEMBER ja4:blacklist fp`)
— O(1), essentially free.

When a bot connects, the proxy reads the ClientHello, extracts the JA4
fingerprint, and checks it against the blacklist. If the fingerprint is there,
the connection is reset. This happens before the bot has sent any application
data. The IP address is irrelevant.

This is why JA4 blacklisting is more powerful than IP banning for botnets: you
ban the *software*, not the machine. A new machine added to the botnet tomorrow
will be running the same software and will be blocked immediately.

**Why is the safety gate only on the attack UI, not the fingerprint detail page?**

The attack UI is designed for a panicked operator under time pressure. It should
be impossible to make a catastrophic mistake — blocking Chrome affects everyone.
The "Protected" button prevents this.

The fingerprint detail page (`/fingerprint/{ja4}`) is a deliberate, investigative
tool. An operator who navigates there has already looked at the fingerprint in
detail. The assumption is they know what they are doing. The safety gate would
be patronising in that context — if they want to block Chrome 120 for some
operational reason, that is their choice.

The API-level gate (`?source=attack_ui`) formalises this: the attack UI marks
its requests so the API can enforce the gate. Direct API calls (via the detail
page, via CLI, via API clients) bypass it.

**What is JA4T and why does it matter here?**

JA4T is a fingerprint of the TCP SYN packet — specifically, the TCP window size,
scaling factor, options, and MSS. Unlike JA4 (TLS-layer), JA4T is computed from
the TCP handshake. A botnet where every machine shows the same JA4T means they
are all running the same OS version with the same kernel TCP defaults — strong
evidence of a coordinated deployment (cloned VMs, same container image, same
botnet kit).

The Go proxy cannot compute JA4T from an accepted socket (the kernel has already
completed the TCP handshake). It comes from the passive TAP sidecar that captures
raw SYNs and writes `fp:ja4t:ip:{ip}` to Redis. Not all deployments have the
TAP running — that is why the JA4T column is conditional on data being present.

## Redis Keys Used (Read-Only in This Phase)

| Key | Type | Read by |
|-----|------|---------|
| `events:connection` | Stream | Attack fingerprint aggregation |
| `ja4:blacklist` | SET | `is_blacklisted` status |
| `ja4:whitelist` | SET | `is_whitelisted` status |
| `fp:ja4t:ip:{ip}` | String | JA4T lookup (if TAP running) |
| `attack_mode:active` | String | Attack mode threshold adjustment |

This phase writes only to `ja4:blacklist` (via existing lists API) and `management:audit_log`.

## CHANGELOG Fragment

Add `docs/fragments/phase-250-botnet-fingerprint.md`:

```markdown
### Added
- Fingerprint tab on Under Attack page: groups attack traffic by JA4 TLS fingerprint
  showing unique IP count — the key indicator of a residential botnet
- Botnet detection signal: fingerprints seen on 5+ IPs with avg score ≥ 60 and
  not matching a known browser are flagged as "BOTNET"
- One-click fingerprint block stops all botnet IPs simultaneously, including
  future IPs added to the botnet
- Safety gate prevents blocking known-browser fingerprints (Chrome, Firefox,
  Safari, Edge) from the attack UI — the fingerprint detail page retains override
- JA4T TCP fingerprint correlation shown when passive TAP data is available
- Expanded known-browser corpus with Chrome 120-122, Firefox 121-123, Safari 17,
  Edge, Samsung Internet, and browser label lookup file
```
