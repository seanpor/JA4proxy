# Security Foundations & Quick Wins

---

## Plain-English Goal

When this phase is complete, five things will be true that are not true today:

1. **No JavaScript loads from the internet.** Every script the dashboard needs
   (htmx, Alpine.js, Chart.js, htmx-sse) will come from your own server, stored
   in `management/static/vendor/`. If the internet goes down, the dashboard still
   works. If an attacker compromises `unpkg.com`, they cannot inject code into
   your security console.

2. **The dashboard tells you immediately if the proxy has stopped working.**
   A sticky bar at the top of every page shows the current security posture
   (NOMINAL / ELEVATED / ACTIVE) and flips to a red banner the moment the
   proxy heartbeat goes silent.

3. **The analytics engine can actually talk to Redis in development.** Right now
   it cannot — it is on the wrong Docker network. After this fix, the analytics
   pipeline can be developed and tested locally.

4. **The `admin-api` back-door is gone.** There is currently a container on
   port 8091 that lets anyone on the network change blocklists and configurations
   with zero authentication. This phase removes it permanently.

5. **Production ports are not world-reachable.** Internal ports (proxy metrics,
   tarpit, analytics) will be bound to `127.0.0.1` so only software running on
   the same host can reach them.

---

## Background: Why Each Problem Matters

### Why serving JavaScript from a CDN is a security risk

When `base.html` says `<script src="https://unpkg.com/htmx.org@1.9.12">`, your
operators' browsers go out to `unpkg.com` every time they load the page and
download a JavaScript file. Two problems arise:

**Problem 1 — Supply-chain attack.** If an attacker ever compromises `unpkg.com`
or the npm package that htmx is published from, they can replace the file with
malicious code. Your operators would then be running attacker code inside your
security management console — the most sensitive interface in the system. This
class of attack (typosquatting, account takeover of a package maintainer) is not
theoretical; it happens several times per year across the npm ecosystem.

**Problem 2 — Fake SRI hashes (per Finding H-5 in PHASE_231.md).** The current
`base.html` has this on three different libraries:

```
integrity="sha384-Y8N6e7v5p4v3i2o1n0m9l8k7j6h5g4f3d2s1a0"
```

This hash is **identical across all three libraries and is fake**. SRI
(Subresource Integrity) is the browser's mechanism for verifying a downloaded
file matches a known good hash. With a fake hash, the browser either rejects the
file (breaking the page) or the attribute is silently ignored. Either way you
get zero protection.

**The fix:** Vendor all JS. Store it in `management/static/vendor/`. The browser
fetches it from your own server over an already-authenticated session. No CDN
trust needed, no SRI hash validation needed for files you serve yourself.

### Why the admin-api is dangerous (Finding C-1 in PHASE_231.md)

The `admin-api` container runs `src.management.app:app` — this is the **legacy
application** from before Phase 13. It has:

- No RBAC (any request from any client can change any setting)
- No CSRF protection (a malicious web page can trigger state changes)
- No MFA gate
- No audit logging (changes leave no trace in the audit log)

The `management` container (port 8090) runs `management.api.main:app` — the
**current application** with 4-tier RBAC, CSRF tokens, MFA, and a full audit
log. But `admin-api` on port 8091 **bypasses all of that**. Anyone who can reach
port 8091 on your network — with no username or password — can:

- Modify blocklists mid-incident
- Change the enforcement dial
- Delete active bans

This is a security **regression**, not an inconvenience. The backdoor must be
permanently removed.

### Why port `0.0.0.0` binding is dangerous (Findings M-5/M-6/M-7 in PHASE_231.md)

When Docker binds a container port with just `"9090:9090"` (no host IP prefix),
it binds to `0.0.0.0` — meaning every network interface on the host. On a server
with a public IP and a private management IP, the proxy metrics port becomes
reachable from the public internet.

Metrics endpoints reveal internal state: active connections, block counts, score
distributions. An attacker can use this information to measure the effectiveness
of their attack and tune their evasion strategy. Binding to `"127.0.0.1:9090:9090"`
restricts access to the loopback interface only — only processes on the same host
can connect.

### Why the analytics container can't talk to Redis in the POC (Finding C-2 in PHASE_231.md)

Docker containers on different bridge networks cannot communicate directly. Think
of each bridge network as a separate physical LAN switch — containers connected
to one switch cannot talk to containers on a different switch unless a container
has a virtual cable in both.

The current `docker-compose.poc.yml` network layout — the problem is visible:

```
  ja4proxy-data network (internal=true, no internet access)
  ┌─────────────────────────────────┐
  │  [redis]  [proxy]               │
  └─────────────────────────────────┘

  ja4proxy-mgmt network
  ┌────────────────────────────────────────────┐
  │  [management]  [analytics]  [admin-api]    │
  └────────────────────────────────────────────┘

  Problem: [analytics] has REDIS_HOST=redis in its environment,
           but [redis] is ONLY on ja4proxy-data.
           [analytics] is ONLY on ja4proxy-mgmt.
           The hostname "redis" cannot be resolved from analytics.
           Every Redis call from analytics silently fails.
```

In production the compose file correctly places both on `ja4proxy-backend`, so
production works — but developers can never test the analytics pipeline locally.
The fix is a single line: add `ja4proxy-data` to the analytics `networks:` list.

### What the situation summary bar gives the operator

Operators currently have no ambient awareness of the security posture. They must
actively navigate to the dashboard and read the live feed or ban count. At 2 AM
during an active attack, this is too slow.

The situation bar (per Decision 1 and Decision 2 in PHASE_231.md) is a strip
always visible between the topbar and the dashboard content:

```
🟢 NOMINAL   0 blocks  ·  142 conn/min  ·  Dial: 0 — Monitor
🟠 ELEVATED  12 blocks  ·  892 conn/min  ·  Dial: 45 — Moderate
🔴 ACTIVE   47 blocks/5m  ·  Top: 203.0.113.42 (score 94)  ·  Dial: 75
```

It uses both colour **and** shape indicator (emoji) so it is accessible to
colour-blind operators. When the proxy goes down, the bar is replaced by a red
banner showing how long the proxy has been unreachable. This gives the operator a
30-second situational read without clicking anything.

---

## Prerequisites

Before starting this phase:

**1. Phase 231 approved.** The master plan must exist with `status: APPROVED` in
`docs/phases/manifest.yaml`. Verify:

```bash
cd /home/sean/LLM/JA4proxy2
grep -A2 "phase: 231" docs/phases/manifest.yaml
# Expected: status: APPROVED (or COMPLETE)
```

**2. Python 3.14 virtual environment.**

```bash
cd /home/sean/LLM/JA4proxy2
ls .venv314/bin/python3   # should exist
# If missing:
uv venv --python 3.14 --seed .venv314
.venv314/bin/python3 -m pip install -r requirements.txt
```

**3. Go toolchain (required for any Go parity tests).**

```bash
GOROOT=/snap/go/current /snap/go/current/bin/go version
# Expected: go version go1.23.x linux/amd64
```

**4. Docker and Docker Compose.**

```bash
docker compose version
# Expected: Docker Compose version v2.x
```

**5. Node.js (for Tailwind CSS CLI build).**

```bash
node --version    # expected: v18 or higher
npm --version
```

**6. Baseline tests pass before you touch anything.**

```bash
cd /home/sean/LLM/JA4proxy2
make test 2>&1 | tail -10
# Expected: ✓ mypy, ✓ bandit, ✓ ruff, ✓ pip-audit, 0 failed
```

**7. Create a feature branch.**

```bash
cd /home/sean/LLM/JA4proxy2
git checkout -b phase-232-security-foundations
```

---

## Step A: Vendor All JavaScript Dependencies

### Why first?

Every page rendering test (which you must run after each step) will fail if the
browser cannot load JavaScript. By vendoring JS first, all subsequent tests run
against a stable, offline-capable frontend.

### A-1: Create the vendor directory

```bash
mkdir -p /home/sean/LLM/JA4proxy2/management/static/vendor
```

### A-2: Download each library

Run each command from `/home/sean/LLM/JA4proxy2`:

```bash
cd /home/sean/LLM/JA4proxy2

# htmx 1.9.12
curl -fsSL https://unpkg.com/htmx.org@1.9.12/dist/htmx.min.js \
  -o management/static/vendor/htmx.min.js

# htmx-ext-sse 2.2.1
curl -fsSL https://unpkg.com/htmx-ext-sse@2.2.1/sse.js \
  -o management/static/vendor/htmx-sse.js

# Alpine.js 3.14.0
curl -fsSL https://unpkg.com/alpinejs@3.14.0/dist/cdn.min.js \
  -o management/static/vendor/alpinejs.min.js

# Chart.js 4.4.2
curl -fsSL https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.min.js \
  -o management/static/vendor/chart.umd.min.js
```

### A-3: Verify downloads with sha256sum

```bash
cd /home/sean/LLM/JA4proxy2/management/static/vendor

# Print actual hashes (save these in a CHECKSUMS.txt file for the repo):
sha256sum htmx.min.js htmx-sse.js alpinejs.min.js chart.umd.min.js \
  | tee CHECKSUMS.txt
```

**How to independently verify each hash:** For each file, download it directly
from the CDN URL in a separate terminal and compare:

```bash
# Example for htmx:
curl -fsSL https://unpkg.com/htmx.org@1.9.12/dist/htmx.min.js | sha256sum
# Must match the hash of your downloaded management/static/vendor/htmx.min.js
```

If any hash does not match, delete the file and re-download. **Do not commit a
vendor file whose hash you have not independently verified.**

### A-4: Build Tailwind CSS

The Tailwind CDN in `base.html` (line 9) uses the runtime JIT compiler — it
generates CSS on the fly in the browser. This cannot be simply downloaded. Instead,
run the Tailwind CLI to build a static CSS file from your templates.

**Check for an existing `input.css`:**

```bash
ls /home/sean/LLM/JA4proxy2/management/static/input.css 2>/dev/null \
  || echo "MISSING — will create"
```

If missing, create it:

```bash
cat > /home/sean/LLM/JA4proxy2/management/static/input.css << 'EOF'
@tailwind base;
@tailwind components;
@tailwind utilities;
EOF
```

**Check for `tailwind.config.js` at repo root:**

```bash
ls /home/sean/LLM/JA4proxy2/tailwind.config.js 2>/dev/null || echo "MISSING"
```

If missing, create it:

```bash
cat > /home/sean/LLM/JA4proxy2/tailwind.config.js << 'EOF'
/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './management/templates/**/*.html',
    './management/static/**/*.js',
  ],
  theme: {
    extend: {
      colors: {
        'slate-950': '#0f172a',
        'slate-800': '#1e293b',
        'slate-700': '#334155',
        'sky-500':   '#0ea5e9',
      }
    }
  },
  plugins: [],
}
EOF
```

**Run the CLI build:**

```bash
cd /home/sean/LLM/JA4proxy2
npx tailwindcss \
  -i ./management/static/input.css \
  -o ./management/static/vendor/tailwind.css \
  --minify \
  --config ./tailwind.config.js
```

Expected output: `Done in Xms.`

Verify the output is non-empty:

```bash
wc -c /home/sean/LLM/JA4proxy2/management/static/vendor/tailwind.css
# Expected: > 100000 bytes (full Tailwind is typically 150-300KB before purging)
```

> [!NOTE]
> After adding new HTML templates in later steps, re-run the Tailwind CLI so
> any new CSS classes used in those templates are included in `tailwind.css`.
> The purging scan is controlled by the `content:` array in `tailwind.config.js`.

### A-5: Update base.html to use vendored paths

> [!CAUTION]
> This step changes the HTML loaded by every page. Apply only after A-3 and A-4
> are confirmed complete. Applying this change with missing vendor files breaks
> all pages immediately.

Edit `/home/sean/LLM/JA4proxy2/management/templates/base.html`.

**Replace lines 8–22** (the CDN script/link block) with:

```diff
-  <!-- Tailwind CSS -->
-  <script src="https://cdn.tailwindcss.com" crossorigin="anonymous"></script> <!-- nosemgrep -->
-
-  <!-- HTMX -->
-  <script src="https://unpkg.com/htmx.org@1.9.12" integrity="sha384-FhXw7b6AlE/jyjlZH5iHa/tTenQXQJnaNPdfCe6RYgiW/Wm8tf/+8QOt6v/BeE6i" crossorigin="anonymous"></script>
-  <script src="https://unpkg.com/htmx-ext-sse@2.2.1/sse.js" integrity="sha384-Y8N6e7v5p4v3i2o1n0m9l8k7j6h5g4f3d2s1a0" crossorigin="anonymous"></script>
-
-  <!-- Alpine.js -->
-  <script src="https://unpkg.com/alpinejs@3.14.0/dist/cdn.min.js" integrity="sha384-6Xh8u3p1iZ6e8q6u5p4v3i2o1n0m9l8k7j6h5g4f3d2s1a0" crossorigin="anonymous" defer></script>
-
-  <!-- Chart.js -->
-  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.min.js" integrity="sha384-Y8N6e7v5p4v3i2o1n0m9l8k7j6h5g4f3d2s1a0" crossorigin="anonymous"></script>
+  <!-- Vendored CSS — Phase 232, eliminates CDN dependency (Finding H-5) -->
+  <link rel="stylesheet" href="/static/vendor/tailwind.css" />
+
+  <!-- Content-Security-Policy: scripts only from self; style-src unsafe-inline
+       is a pragmatic concession while Tailwind class-purging is configured.
+       Revisit in Phase 238 per PHASE_231.md notes. -->
+  <meta http-equiv="Content-Security-Policy"
+        content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self';" />
+
+  <!-- Vendored JS — Phase 232, eliminates CDN dependency (Finding H-5) -->
+  <script src="/static/vendor/htmx.min.js"></script>
+  <script src="/static/vendor/htmx-sse.js"></script>
+  <script defer src="/static/vendor/alpinejs.min.js"></script>
+  <script src="/static/vendor/chart.umd.min.js"></script>
```

**Also remove lines 24–38** (the inline `tailwind.config = {...}` script block).
The runtime Tailwind JIT used this; with a static CSS file it is dead code:

```diff
-  <script>
-    tailwind.config = {
-      darkMode: 'class',
-      theme: {
-        extend: {
-          colors: {
-            'slate-950': '#0f172a',
-            'slate-800': '#1e293b',
-            'slate-700': '#334155',
-            'sky-500':   '#0ea5e9',
-          }
-        }
-      }
-    }
-  </script>
```

### A-6: How to verify it works

Start the management service locally (assumes Redis is running on localhost):

```bash
cd /home/sean/LLM/JA4proxy2
MANAGEMENT_TEST_MODE=1 \
REDIS_URL=redis://localhost:6379/0 \
MANAGEMENT_JWT_SECRET=dev-secret \
MANAGEMENT_ADMIN_USER=admin \
MANAGEMENT_ADMIN_PASSWORD=adminpass \
.venv314/bin/python3 -m uvicorn management.api.main:app \
  --host 127.0.0.1 --port 8090 --reload
```

Open `http://localhost:8090` in Chrome or Firefox. Open **DevTools → Network tab**.
Reload the page. Filter by **Type → Script** and **Type → Stylesheet**.

You must see:
- `tailwind.css` from `localhost:8090` ✓
- `htmx.min.js` from `localhost:8090` ✓
- `htmx-sse.js` from `localhost:8090` ✓
- `alpinejs.min.js` from `localhost:8090` ✓
- `chart.umd.min.js` from `localhost:8090` ✓

**No requests to `unpkg.com`, `cdn.tailwindcss.com`, or `cdn.jsdelivr.net`.**

Command-line verification (no browser needed):

```bash
curl -s http://localhost:8090/login | grep -E "unpkg|tailwindcss\.com|jsdelivr"
# Expected: no output (zero CDN references)
```

---

## Step B: Situation Summary Bar + Proxy-Down Banner

### What HTMX partials are and how they work in this project

HTMX is a library that adds behaviour to HTML attributes. In this project:

1. A `<div>` in a page template has `hx-get="/api/v1/partials/health-cards"` and
   `hx-trigger="load, every 10s"`.
2. On page load — and every 10 seconds — HTMX makes a GET request to that URL.
3. The FastAPI route in `partials.py` reads from Redis and returns a **rendered
   HTML fragment** (not a full page — just the inner HTML of the card grid).
4. HTMX replaces the `<div>`'s content with the returned fragment in place.

The situation bar works the same way: one endpoint, one template fragment, polled
every 10 seconds. `hx-swap="outerHTML"` means the entire `<div>` wrapper is
replaced, not just its inner content. This is important because the bar uses an
`id="situation-bar"` on the fragment itself for screen reader labels.

### B-1: Add the situation endpoint to partials.py

Add the following block to the **end** of
`/home/sean/LLM/JA4proxy2/management/api/routes/partials.py` (before the final
blank line). The `time` import is already present in the file (line 20).

```python
# ── Situation bar (Phase 232 — Decision 1 & 2, PHASE_231.md) ──────────────────

_EVENTS_STREAM_KEY = "ja4proxy:events"
_HEARTBEAT_KEY_PATTERN = "proxy:heartbeat:*"
_PROXY_DOWN_THRESHOLD_SECONDS = 60


@router.get("/api/v1/partials/situation", response_class=HTMLResponse)
async def situation_partial(
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Return the situation summary bar (or proxy-down banner) as an HTML fragment.

    Reads the last 5 minutes of the ja4proxy:events stream and counts blocking
    actions. Also checks proxy:heartbeat:* key presence to detect proxy outage.

    State machine (per Decision 1, PHASE_231.md):
        PROXY_DOWN  — no proxy:heartbeat:* key found
        NOMINAL     — 0 block/tarpit actions in last 5m
        ELEVATED    — 1–9 block/tarpit actions in last 5m
        ACTIVE      — 10+ block/tarpit actions in last 5m

    Per Decision 2 (PHASE_231.md), PROXY_DOWN replaces the bar entirely with
    a full-width red banner.
    """
    templates = _get_templates()

    block_count_5m: int = 0
    top_ip: str | None = None
    top_score: int = 0
    conn_per_min: int = 0
    proxy_down_seconds: int = 0

    try:
        # ── 1. Proxy heartbeat check ───────────────────────────────────────────
        # The proxy writes proxy:heartbeat:<instance_id> with a TTL.
        # Absence of any such key means the proxy has been unreachable for
        # longer than the key's TTL (typically 60–120s).
        cursor = 0
        heartbeat_keys: list = []
        while True:
            cursor, batch = await redis.scan(
                cursor=cursor, match=_HEARTBEAT_KEY_PATTERN, count=100
            )
            heartbeat_keys.extend(batch)
            if cursor == 0:
                break

        if not heartbeat_keys:
            proxy_down_seconds = _PROXY_DOWN_THRESHOLD_SECONDS + 1
        else:
            proxy_down_seconds = 0

        # ── 2. Event stream: last 5 minutes ───────────────────────────────────
        # XREVRANGE reads newest-first. Build a millisecond timestamp for the
        # lower bound (5 minutes ago). Upper bound "+" means "now".
        now_ms = int(time.time() * 1000)
        five_min_ago_ms = now_ms - (5 * 60 * 1000)
        min_id = f"{five_min_ago_ms}-0"

        entries = await redis.xrevrange(
            _EVENTS_STREAM_KEY,
            max="+",
            min=min_id,
            count=2000,
        )

        ip_scores: dict[str, int] = {}
        for _entry_id, fields in entries:
            action = fields.get("action_taken", fields.get("action", ""))
            if action in ("block", "tarpit"):
                block_count_5m += 1
            try:
                score = int(fields.get("score", 0))
            except (ValueError, TypeError):
                score = 0
            ip = fields.get("client_ip", fields.get("ip", ""))
            if ip:
                ip_scores[ip] = max(ip_scores.get(ip, 0), score)

        if ip_scores:
            top_ip = max(ip_scores, key=lambda k: ip_scores[k])
            top_score = ip_scores[top_ip]

        # ── 3. Connection rate ─────────────────────────────────────────────────
        raw_cpm = await redis.get("stats:events_per_min")
        if raw_cpm:
            try:
                conn_per_min = int(raw_cpm)
            except ValueError:
                conn_per_min = 0

    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=situation_error | error=%s", exc)

    dial_value = await _get_dial(redis)

    # ── State classification ───────────────────────────────────────────────────
    if proxy_down_seconds > 0:
        state = "PROXY_DOWN"
    elif block_count_5m == 0:
        state = "NOMINAL"
    elif block_count_5m < 10:
        state = "ELEVATED"
    else:
        state = "ACTIVE"

    return templates.TemplateResponse(
        request,
        "partials/situation_bar.html",
        {
            "user": current_user[0],
            "state": state,
            "block_count_5m": block_count_5m,
            "conn_per_min": conn_per_min,
            "top_ip": top_ip,
            "top_score": top_score,
            "dial_value": dial_value,
            "proxy_down_seconds": proxy_down_seconds,
        },
    )
```

After adding this code, run ruff immediately:

```bash
cd /home/sean/LLM/JA4proxy2
.venv314/bin/python3 -m ruff check --select I001 --fix \
  management/api/routes/partials.py
.venv314/bin/python3 -m ruff check management/api/routes/partials.py
# Expected: All checks passed.
```

### B-2: Create the situation_bar.html template

Create the file
`/home/sean/LLM/JA4proxy2/management/templates/partials/situation_bar.html`:

```html
{#
  situation_bar.html — Situation summary bar / proxy-down banner

  Context variables provided by situation_partial() in partials.py:
    state             str   — NOMINAL | ELEVATED | ACTIVE | PROXY_DOWN
    block_count_5m    int   — blocks + tarpits in last 5 minutes
    conn_per_min      int   — connection rate from stats:events_per_min
    top_ip            str|None  — highest-scoring IP in last 5m
    top_score         int   — score of top_ip
    dial_value        int   — current enforcement dial (0–100)
    proxy_down_seconds int  — seconds since last heartbeat (0 = up)

  Per Decision 1 and Decision 2 in PHASE_231.md:
    - Shape indicator (emoji) AND colour for accessibility.
    - PROXY_DOWN replaces bar with full-width red alert banner.
    - hx-swap="outerHTML" on the wrapper means THIS element (id=situation-bar)
      is what gets swapped on each 10s poll.
#}

{% if state == "PROXY_DOWN" %}
{# ── Proxy-down banner (Decision 2, PHASE_231.md) ─────────────────────────── #}
<div id="situation-bar"
     class="w-full bg-[#991b1b] border-b border-[#7f1d1d] px-6 py-2.5
            flex items-center justify-between gap-4"
     role="alert"
     aria-live="assertive"
     aria-label="Proxy unreachable — security scoring offline">
  <div class="flex items-center gap-3 min-w-0">
    <span class="text-white text-lg flex-shrink-0" aria-hidden="true">⚠</span>
    <span class="text-white font-semibold text-sm tracking-wide flex-shrink-0">
      PROXY UNREACHABLE
    </span>
    <span class="text-[#fca5a5] text-sm truncate">
      — No JA4 fingerprinting active. All traffic passing through unscored.
      Last heartbeat: {{ proxy_down_seconds }}s+ ago.
    </span>
  </div>
  <div class="flex items-center gap-3 flex-shrink-0">
    <a href="#"
       class="text-[#fca5a5] hover:text-white text-xs underline transition-colors">
      Runbook ↗
    </a>
    <span class="text-[#fca5a5] text-xs px-2 py-0.5 rounded border border-[#7f1d1d]
                 bg-[#7f1d1d]">
      Dial: {{ dial_value }} — DISABLED
    </span>
  </div>
</div>

{% elif state == "NOMINAL" %}
{# ── Nominal bar — green ───────────────────────────────────────────────────── #}
<div id="situation-bar"
     class="w-full bg-[#14532d] border-b border-[#166534] px-6 py-2
            flex items-center justify-between gap-4"
     role="status"
     aria-label="Security posture: nominal — no active blocks">
  <div class="flex items-center gap-3">
    <span aria-hidden="true" class="text-base leading-none">🟢</span>
    <span class="text-[#86efac] font-semibold text-sm tracking-widest">NOMINAL</span>
    <span class="text-[#4ade80] text-sm">0 blocks</span>
    <span class="text-[#166534] text-sm mx-1">·</span>
    <span class="text-[#4ade80] text-sm">{{ conn_per_min }} conn/min</span>
    <span class="text-[#166534] text-sm mx-1">·</span>
    <span class="text-[#4ade80] text-sm">
      Dial: {{ dial_value }} —
      {% if dial_value == 0 %}Monitor
      {% elif dial_value <= 49 %}Moderate
      {% else %}Active
      {% endif %}
    </span>
  </div>
  <span class="text-[#4ade80] text-xs opacity-50">Updated every 10s</span>
</div>

{% elif state == "ELEVATED" %}
{# ── Elevated bar — amber ──────────────────────────────────────────────────── #}
<div id="situation-bar"
     class="w-full bg-[#78350f] border-b border-[#92400e] px-6 py-2
            flex items-center justify-between gap-4"
     role="status"
     aria-label="Security posture: elevated — active blocks detected">
  <div class="flex items-center gap-3">
    <span aria-hidden="true" class="text-base leading-none">🟠</span>
    <span class="text-[#fde68a] font-semibold text-sm tracking-widest">ELEVATED</span>
    <span class="text-[#fcd34d] text-sm">{{ block_count_5m }} blocks/5m</span>
    <span class="text-[#92400e] text-sm mx-1">·</span>
    <span class="text-[#fcd34d] text-sm">{{ conn_per_min }} conn/min</span>
    <span class="text-[#92400e] text-sm mx-1">·</span>
    <span class="text-[#fcd34d] text-sm">
      Dial: {{ dial_value }} —
      {% if dial_value == 0 %}Monitor
      {% elif dial_value <= 49 %}Moderate
      {% else %}Active
      {% endif %}
    </span>
  </div>
  <span class="text-[#fcd34d] text-xs opacity-50">Updated every 10s</span>
</div>

{% else %}
{# ── Active bar — red (state == "ACTIVE") ─────────────────────────────────── #}
<div id="situation-bar"
     class="w-full bg-[#7f1d1d] border-b border-[#991b1b] px-6 py-2
            flex items-center justify-between gap-4"
     role="alert"
     aria-live="polite"
     aria-label="Security posture: active — high block rate">
  <div class="flex items-center gap-3">
    <span aria-hidden="true" class="text-base leading-none">🔴</span>
    <span class="text-[#fecaca] font-semibold text-sm tracking-widest">ACTIVE</span>
    <span class="text-[#f87171] text-sm">{{ block_count_5m }} blocks/5m</span>
    {% if top_ip %}
    <span class="text-[#991b1b] text-sm mx-1">·</span>
    <span class="text-[#f87171] text-sm">
      Top: {{ top_ip }} (score {{ top_score }})
    </span>
    {% endif %}
    <span class="text-[#991b1b] text-sm mx-1">·</span>
    <span class="text-[#f87171] text-sm">
      Dial: {{ dial_value }} —
      {% if dial_value == 0 %}Monitor
      {% elif dial_value <= 49 %}Moderate
      {% else %}Active
      {% endif %}
    </span>
  </div>
  <span class="text-[#f87171] text-xs opacity-50">Updated every 10s</span>
</div>
{% endif %}
```

### B-3: Wire the partial into dashboard.html

Edit `/home/sean/LLM/JA4proxy2/management/templates/dashboard.html`.

Insert the situation bar slot **immediately after** `{% block content %}` and
**before** the `<!-- Row 1 -->` comment (current line 8):

```diff
 {% block content %}
 <div class="space-y-6 max-w-[1200px]">
 
+  <!-- ── Situation Summary Bar ──────────────────────────────────────────
+       Polls every 10s. hx-swap="outerHTML" replaces the entire wrapper
+       div with the returned situation_bar.html fragment.
+       -mx-6 -mt-6 cancels the <main class="p-6"> padding so the bar
+       stretches edge-to-edge (per Decision 1, PHASE_231.md).
+  ─────────────────────────────────────────────────────────────────────── -->
+  <div hx-get="/api/v1/partials/situation"
+       hx-trigger="load, every 10s"
+       hx-swap="outerHTML"
+       hx-indicator="#htmx-indicator"
+       class="-mx-6 -mt-6 mb-2">
+    <!-- Skeleton shown while first request is in flight -->
+    <div class="w-full h-9 bg-[#1e293b] animate-pulse"></div>
+  </div>
+
   <!-- ── Row 1: Health cards (polled every 10s via HTMX) ──────────── -->
   <section aria-label="System health">
```

### B-4: How to test the situation bar manually

**State 1 — NOMINAL (no events in stream):**
Load the dashboard. The bar should be green.

**State 2 — ELEVATED (2–9 block events in the last 5 minutes):**
```bash
# Connect to Redis:
redis-cli -a "$REDIS_PASSWORD"

# Add 3 fake block events. "*" auto-generates the stream entry ID:
127.0.0.1:6379> XADD ja4proxy:events "*" client_ip 1.2.3.4 action_taken block score 72
127.0.0.1:6379> XADD ja4proxy:events "*" client_ip 1.2.3.5 action_taken block score 65
127.0.0.1:6379> XADD ja4proxy:events "*" client_ip 1.2.3.6 action_taken tarpit score 81
# Wait up to 10s. Bar should become amber ELEVATED with "3 blocks/5m".
```

**State 3 — PROXY_DOWN:**
```bash
# List all heartbeat keys:
redis-cli -a "$REDIS_PASSWORD" KEYS "proxy:heartbeat:*"
# Delete each one. For example:
redis-cli -a "$REDIS_PASSWORD" DEL "proxy:heartbeat:instance-1"
# Wait up to 10s. Bar should become red PROXY UNREACHABLE.
```

---

## Step C: Fix the Analytics Network Gap

### C-1: Apply the compose change

Edit `/home/sean/LLM/JA4proxy2/deploy/docker/docker-compose.poc.yml`.

Find the `analytics:` service block. The current `networks:` section (around
line 267) reads:

```yaml
    networks:
      - ja4proxy-mgmt
```

Change it to:

```diff
     networks:
       - ja4proxy-mgmt
+      - ja4proxy-data
```

The full analytics `networks:` block after the change:

```yaml
    networks:
      - ja4proxy-mgmt
      - ja4proxy-data
```

No other changes to the analytics service are needed.

### C-2: Verify the fix

> [!NOTE]
> Requires the compose stack to be running. Use the POC environment, not production.

```bash
cd /home/sean/LLM/JA4proxy2

# Re-create the analytics container to pick up the new network attachment:
docker compose -f deploy/docker/docker-compose.poc.yml up -d --force-recreate analytics

# Wait for it to be healthy (up to 30s):
docker compose -f deploy/docker/docker-compose.poc.yml ps analytics

# Exec into analytics and test Redis connectivity:
docker compose -f deploy/docker/docker-compose.poc.yml exec analytics \
  python3 -c "
import redis, os
r = redis.Redis(
    host=os.environ.get('REDIS_HOST', 'redis'),
    port=int(os.environ.get('REDIS_PORT', 6379)),
    password=os.environ.get('REDIS_PASSWORD', ''),
    socket_timeout=5,
)
r.ping()
print('SUCCESS: analytics can reach Redis')
"
# Expected: SUCCESS: analytics can reach Redis
# If you see ConnectionRefusedError, the container was not re-created — run
# 'docker compose down analytics' first, then 'up -d analytics'.
```

---

## Step D: Eliminate the admin-api

> [!CAUTION]
> Removing the `admin-api` will permanently disable any automation scripts or
> Ansible playbooks that call port 8091. You **must** complete D-1 (the audit)
> and D-2 (migrate consumers) BEFORE D-3 (removing the service). This step is
> irreversible without a git revert.

### D-1: Audit — find every reference to admin-api

```bash
cd /home/sean/LLM/JA4proxy2
grep -rn "8091\|admin-api\|admin_api\|Dockerfile\.admin\|src\.management\.app" \
  --include="*.yml" \
  --include="*.yaml" \
  --include="*.py" \
  --include="*.go" \
  --include="*.md" \
  --include="*.sh" \
  . 2>/dev/null | grep -v "\.git/" | grep -v "PHASE_231\|PHASE_232"
```

**Document every result.** Create a table in your notes:

| File | What it references | Action needed |
|------|--------------------|---------------|
| `deploy/docker/docker-compose.poc.yml` | `admin-api` service | Remove (D-3) |
| `deploy/docker/Dockerfile.admin` | Dockerfile itself | Delete (D-4) |
| Any script in `scripts/` or `ansible/` | Port 8091 | Migrate to API token (D-2) |

### D-2: Migrate automation scripts to management API tokens

If you found scripts calling `http://host:8091/...`, replace them with calls to
the management service at port 8090 using a scoped token.

**Create an automation token (management must be running):**

```bash
# Step 1: Log in to get a session cookie:
curl -X POST http://localhost:8090/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "YOUR_ADMIN_PASSWORD"}' \
  -c /tmp/ja4proxy-cookie.txt \
  -s | python3 -m json.tool

# Step 2: Create a scoped operator token valid for 90 days:
curl -X POST http://localhost:8090/api/v1/tokens \
  -H "Content-Type: application/json" \
  -b /tmp/ja4proxy-cookie.txt \
  -d '{"name": "ci-automation", "role": "operator", "expires_days": 90}' \
  -s | python3 -m json.tool
# Save the returned token value securely.
```

**Replace old admin-api calls** (example pattern):

```bash
# Old (bypasses all security controls — remove this):
# curl -X POST http://host:8091/api/block -d '{"ip":"1.2.3.4"}'

# New (uses management API with proper RBAC and audit trail):
curl -X POST http://localhost:8090/api/v1/bans \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "1.2.3.4",
    "reason": "Automated block via CI pipeline",
    "duration": 86400
  }'
```

### D-3: Remove admin-api from docker-compose.poc.yml

Edit `/home/sean/LLM/JA4proxy2/deploy/docker/docker-compose.poc.yml`.

Remove the entire `admin-api:` service block (lines 290–330 in the current file).
Here is the exact block to delete:

```diff
-  admin-api:
-    build:
-      context: ../..
-      dockerfile: deploy/docker/Dockerfile.admin
-    image: ja4proxy-admin-api:1.0.0
-    restart: unless-stopped
-    ports:
-      - "${AGENT_BIND_IP:-127.0.0.1}:${HOST_PORT_ADMIN_API:-8091}:8090"
-    depends_on:
-      - redis
-    environment:
-      - REDIS_HOST=redis
-      - REDIS_PORT=6379
-      - REDIS_PASSWORD=${REDIS_PASSWORD:?REDIS_PASSWORD is required}
-      - REDIS_SIGNING_KEY=${REDIS_SIGNING_KEY:-}
-      - ENVIRONMENT=${ENVIRONMENT:-development}
-      - JA4PROXY_TRACE=${JA4PROXY_TRACE:-false}
-      - PYTHONUNBUFFERED=1
-      - PYTHONDONTWRITEBYTECODE=1
-    networks:
-      - ja4proxy-mgmt
-      - ja4proxy-data
-    security_opt:
-      - no-new-privileges:true
-    read_only: true
-    tmpfs:
-      - /tmp:noexec,nosuid,nodev,size=50m
-    cap_drop:
-      - ALL
-    deploy:
-      resources:
-        limits:
-          memory: 256M
-          cpus: '0.5'
-        reservations:
-          memory: 64M
-    logging:
-      driver: "json-file"
-      options:
-        max-size: "100m"
-        max-file: "3"
```

### D-4: Delete Dockerfile.admin

```bash
cd /home/sean/LLM/JA4proxy2
git rm deploy/docker/Dockerfile.admin
# Verify:
ls deploy/docker/Dockerfile.admin 2>&1
# Expected: ls: cannot access '...Dockerfile.admin': No such file or directory
```

### D-5: Add CI assertion to prevent re-introduction

Create `tests/unit/test_container_config.py` if it does not exist, then add:

```python
"""Container configuration parity and security regression tests.

Per the AGENTS.md test_container_config.py pattern.
Phase 232 additions: admin-api removal and port binding checks.
"""
import re


def test_admin_api_absent_from_all_compose_files():
    """admin-api backdoor must not appear in any compose file.

    admin-api runs src.management.app:app — the legacy application with no
    RBAC, no CSRF protection, no MFA gate, and no audit logging. Its removal
    is permanent (Phase 232, Finding C-1 in PHASE_231.md). If this test
    fails, someone has re-introduced the security backdoor.
    """
    compose_files = [
        "deploy/docker/docker-compose.poc.yml",
    ]
    for path in compose_files:
        try:
            with open(path) as f:
                content = f.read()
        except FileNotFoundError:
            continue
        assert "admin-api" not in content, (
            f"admin-api service found in {path}. "
            "This backdoor bypasses all RBAC/CSRF/MFA controls. "
            "It was removed in Phase 232 and must not be re-introduced. "
            "See Finding C-1 in PHASE_231.md."
        )
        assert "8091" not in content, (
            f"Port 8091 (admin-api port) found in {path}. "
            "Remove this reference — the admin-api service no longer exists."
        )


def test_no_wildcard_port_bindings_in_prod_compose():
    """All host-exposed ports in prod compose must use 127.0.0.1 binding.

    Binding to 0.0.0.0 (Docker default when no host IP is specified) exposes
    internal ports on all network interfaces, including public ones.
    Per Findings M-5, M-6, M-7 in PHASE_231.md.
    """
    prod_compose_path = "deploy/docker/docker-compose.prod.yml"
    try:
        with open(prod_compose_path) as f:
            content = f.read()
    except FileNotFoundError:
        # prod compose may not exist in all CI environments
        return

    # Match port strings that are bare HOST:CONTAINER or just CONTAINER
    # without a 127.0.0.1: or ${VAR:- prefix.
    # Examples of BAD:  "9090:9090"   "8888:8888"   "8082:8080"
    # Examples of OK:   "127.0.0.1:9090:9090"   "${AGENT_BIND_IP:-127.0.0.1}:9090:9090"
    bad_ports = re.findall(
        r'- "(\d{2,5}:\d{2,5}(?::\d{2,5})?)"',
        content,
    )
    assert not bad_ports, (
        f"Wildcard port bindings found in {prod_compose_path}: {bad_ports}. "
        "All host-exposed ports must use '127.0.0.1:HOST:CONTAINER' format "
        "to prevent public exposure of internal services. "
        "See Findings M-5/M-6/M-7 in PHASE_231.md."
    )
```

Run immediately to confirm the test passes:

```bash
cd /home/sean/LLM/JA4proxy2
.venv314/bin/python3 -m pytest tests/unit/test_container_config.py -v
# Expected: 2 passed
```

---

## Step E: Fix Production Port Bindings

> [!NOTE]
> This step modifies `docker-compose.prod.yml`. It does not affect the running
> development environment. The changes take effect on the next production
> deployment. Confirm with your ops team before merging to main.

### What to change

In `/home/sean/LLM/JA4proxy2/deploy/docker/docker-compose.prod.yml`, find and
update the following port mappings. Use `grep -n "9090\|8888\|9099\|8082"` to
locate the exact line numbers in your file.

```diff
 # proxy metrics — was world-reachable (Finding M-5)
-      - "9090:9090"
+      - "127.0.0.1:9090:9090"

 # tarpit service and tarpit metrics — were world-reachable (Finding M-6)
-      - "8888:8888"
-      - "9099:9099"
+      - "127.0.0.1:8888:8888"
+      - "127.0.0.1:9099:9099"

 # analytics — was world-reachable (Finding M-7)
-      - "8082:8080"
+      - "127.0.0.1:8082:8080"
```

After applying, verify the prod compose file has no bare port mappings:

```bash
grep -n "ports:" -A3 /home/sean/LLM/JA4proxy2/deploy/docker/docker-compose.prod.yml \
  | grep '"' | grep -v "127\.0\.0\.1\|AGENT_BIND_IP"
# Expected: no output (zero unguarded port bindings)
```

---

## Tests to Run

Run these in order. Each must be green before you proceed to the next.

### 1. Linting and type checking (run after any Python change)

```bash
cd /home/sean/LLM/JA4proxy2

# ruff — zero violations required
.venv314/bin/python3 -m ruff check management/api/routes/partials.py
# Expected: All checks passed.

# mypy
.venv314/bin/python3 -m mypy management/api/routes/partials.py \
  --ignore-missing-imports
# Expected: Success: no issues found in 1 source file
```

### 2. Container configuration tests

```bash
cd /home/sean/LLM/JA4proxy2
.venv314/bin/python3 -m pytest tests/unit/test_container_config.py -v
# Expected: 2 passed, 0 failed
```

### 3. Situation endpoint unit tests

Write `tests/unit/test_situation_partial.py` testing all four states. The test
must mock Redis (no live Redis connection). Example skeleton — fill in the full
assertions:

```bash
cd /home/sean/LLM/JA4proxy2
.venv314/bin/python3 -m pytest tests/unit/test_situation_partial.py -v
# Expected: 4 passed (NOMINAL / ELEVATED / ACTIVE / PROXY_DOWN)
```

### 4. Page rendering tests (mandatory per AGENTS.md)

```bash
cd /home/sean/LLM/JA4proxy2
.venv314/bin/python3 -m pytest tests/management/ -k "render" -v
# Expected: all routes return 200 + text/html + landmark string
```

### 5. No CDN references in rendered HTML

```bash
cd /home/sean/LLM/JA4proxy2
# Start the service in test mode, then check the login page:
MANAGEMENT_TEST_MODE=1 \
.venv314/bin/python3 -m uvicorn management.api.main:app \
  --host 127.0.0.1 --port 8090 &
sleep 2
curl -s http://localhost:8090/login | grep -c "unpkg\|tailwindcss\|jsdelivr"
# Expected: 0
kill %1
```

### 6. Full test suite — must be green before any merge

```bash
cd /home/sean/LLM/JA4proxy2
make test 2>&1 | tail -20
# Required output:
#   ✓ mypy: OK
#   ✓ bandit: OK
#   ✓ ruff: OK
#   ✓ pip-audit: OK
#   N passed, 0 failed, 0 errors
```

### 7. Final admin-api assertion

```bash
cd /home/sean/LLM/JA4proxy2
grep -r "admin-api\|8091" deploy/ --include="*.yml"
# Expected: no output
```

---

## Definition of Done

Tick each box before running `/close-phase`:

- [ ] `management/static/vendor/htmx.min.js` — downloaded, sha256 verified, committed
- [ ] `management/static/vendor/htmx-sse.js` — downloaded, sha256 verified, committed
- [ ] `management/static/vendor/alpinejs.min.js` — downloaded, sha256 verified, committed
- [ ] `management/static/vendor/chart.umd.min.js` — downloaded, sha256 verified, committed
- [ ] `management/static/vendor/tailwind.css` — built from templates via CLI, > 100KB
- [ ] `management/static/vendor/CHECKSUMS.txt` — sha256 of all four JS files committed
- [ ] `base.html` — zero CDN `<script>` or `<link>` tags remain
- [ ] `base.html` — CSP meta tag present with `script-src 'self'`
- [ ] `base.html` — inline `tailwind.config = {...}` script block removed
- [ ] `partials.py` — `GET /api/v1/partials/situation` endpoint added
- [ ] `management/templates/partials/situation_bar.html` — all 4 states (NOMINAL/ELEVATED/ACTIVE/PROXY_DOWN)
- [ ] `dashboard.html` — HTMX slot for situation bar, `hx-trigger="load, every 10s"`, `hx-swap="outerHTML"`
- [ ] `docker-compose.poc.yml` — analytics `networks:` includes `ja4proxy-data`
- [ ] `docker-compose.poc.yml` — `admin-api` service block removed entirely
- [ ] `deploy/docker/Dockerfile.admin` — deleted from filesystem and `git rm`
- [ ] `docker-compose.prod.yml` — ports 9090, 8888, 9099, 8082 all use `127.0.0.1:` prefix
- [ ] `tests/unit/test_container_config.py` — admin-api absence and port binding tests
- [ ] `tests/unit/test_situation_partial.py` — 4 state tests, all with mocked Redis
- [ ] `grep -r "admin-api\|8091" deploy/` — returns empty
- [ ] Browser DevTools confirms zero external JS/CSS requests on dashboard load
- [ ] `make test` exits 0 — zero failures, zero warnings
- [ ] `CHANGELOG.md` — Phase 232 entry added
- [ ] `docs/phases/manifest.yaml` — `status: COMPLETE`, `completed: YYYY-MM-DD`
- [ ] `python3 scripts/sync-roadmap.py` run after manifest update

---

## Common Mistakes

**1. Forgetting to rebuild Tailwind after adding new HTML templates.**
The `npx tailwindcss` build scans template files for CSS class names and includes
only the classes it finds. If you create `situation_bar.html` after building
`tailwind.css`, the bar's colour classes may not be in the CSS. Re-run the CLI.

**2. Committing vendor files without verifying their hash.**
The point of vendoring is supply-chain safety. An unverified file is no safer
than a CDN reference. Always run the sha256 comparison before committing.

**3. Leaving the `tailwind.config = {...}` inline script in base.html.**
The runtime Tailwind JIT reads this config block. After switching to a static
CSS build, this block is dead code. Leaving it causes confusion for future
engineers and is caught by careful code review.

**4. Not mocking Redis in situation endpoint tests.**
The `situation_partial()` function calls `redis.scan()`, `redis.xrevrange()`,
and `redis.get()`. Unit tests in `tests/unit/` must mock all three. Use
`unittest.mock.AsyncMock` or `fakeredis.aioredis`. If a test hits a real Redis
on your dev box, it will pass locally but fail in CI (no Redis there).

**5. Using `os.access` equality checks in mock patches.**
If you write mocks that check `if mode == os.W_OK:`, they will not fire when
production code uses `mode & (os.R_OK | os.W_OK)`. Always use bitwise AND:
`if mode & os.W_OK:`. This is a documented AGENTS.md failure pattern.

**6. Testing analytics network with a restarted (not re-created) container.**
`docker compose restart analytics` does **not** update network attachments.
The container must be stopped and re-created: `docker compose up -d --force-recreate analytics`.

**7. Forgetting the `-mx-6 -mt-6` CSS on the situation bar wrapper.**
The `<main>` in `base.html` has `class="flex-1 p-6 overflow-auto"`. Without
negative margin cancellation on the situation bar, it will have padding on all
sides and will not stretch edge-to-edge.

**8. Not running `git rm` when deleting Dockerfile.admin.**
A plain `rm` leaves the file staged as a deletion in the working tree. If you
then `git add .`, the deletion is committed. But `git rm` is explicit and
correct. Always use it when removing tracked files.
