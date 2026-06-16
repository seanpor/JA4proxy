---
phase: 235
title: Fingerprint & IP Drill-Down Pages
status: PROPOSED
size: LARGE
created: 2026-06-12
audience: [developer, operator, secops]
dependencies: [231, 234]
---

# Fingerprint & IP Drill-Down Pages

> **Before you touch a line of code**, read `docs/phases/complete/PHASE_231.md`.
> Every design decision in this phase is cited by number from that document
> (e.g. "Decision 4"). If you disagree with a decision, raise it
> in a PR comment — do not silently implement a different approach.

---

## 1. Plain-English Goal

When this phase is complete, security analysts and operators will be able to perform deep forensics on suspicious clients with a single click:

1.  **Clickable Elements in the Live Feed:** Clicking any Client IP or JA4 Fingerprint in the dashboard's live feed will open a dedicated detail page.
2.  **Dedicated Forensics Pages:**
    *   `/ip/{ip}`: Shows the client's current block status, geo/network info (ASN, Country), risk score history over the last 24 hours (via Chart.js), list of all JA4 fingerprints used by this IP (to detect fingerprint rotation), and recent activity logs.
    *   `/fingerprint/{ja4}`: Shows the fingerprint's frequency chart, list of associated source IPs, breakdown of proxy actions (allow, monitor, block, tarpit), and current list memberships.
3.  **Safe, Audited Actions:** Operators can block or allowlist IPs/fingerprints from these pages using a rich confirmation modal that forces a reason (minimum 10 characters) and audit log tracking (Decision 4).
4.  **Mistake Recovery (Undo Safety Net):** Any blocking action displays a temporary undo toast (30-second countdown) allowing the operator to immediately revert a mistaken ban.

---

## 2. Background: Why Each Problem Matters

### 2.1 Time-Series Charts with Chart.js
SOC analysts are visual. A list of raw numbers is hard to digest. Chart.js allows us to render a responsive time-series chart directly inside a standard HTML `<canvas>` element. Using a bar chart with hourly buckets, an analyst can instantly spot whether an IP is performing low-and-slow beaconing or a high-volume burst attack.

### 2.2 Alpine.js Components for UI State
Instead of writing complex vanilla Javascript query selectors or loading heavy frameworks like React, we use **Alpine.js**. Alpine binds a Javascript object to a DOM element (using `x-data`).
*   **The Benefit:** Modals, dropdowns, and alert toasts can be animated, validated, and state-controlled in less than 50 lines of clear, maintainable code.

### 2.3 Why `window.confirm()` is Bad for Enterprise
The default browser `confirm()` dialog is a security and operational anti-pattern:
1.  **Blockable:** Enterprise browsers or extensions can block dialog boxes permanently if clicked twice.
2.  **No Audit Trail:** It does not capture the analyst's intent. In a secure environment, every block or unblock must have a recorded justification (reason) for compliance audits (NIST/SOC2).
3.  **Prone to Mis-clicks:** It offers no visual distinction between low-stakes and high-stakes actions (e.g., allowlisting a global IP).

### 2.4 The Safety Net: Undo Toast
Under incident stress at 2 AM, analysts make mistakes. An "Undo" toast provides a temporary, single-click mechanism to delete the newly created ban. This reduces operational friction and prevents prolonged accidental self-blocking.

---

## 3. Prerequisites

*   Phase 234 must be fully complete and merged.
*   Run all verification targets inside the pinned `ja4proxy-tools` container. **Never run Python directly on the host.**
*   Verify the Redis stream key configuration:
    ```bash
    grep stream_key config/proxy.yml
    # Output: stream_key: "events:connection"
    ```
*   Confirm the Go proxy writes ECS-flat events to that stream:
    ```bash
    # Inside the running stack:
    docker compose exec redis redis-cli XREAD COUNT 1 STREAMS events:connection 0
    ```
    Each entry has a single `event` field whose value is a JSON string of flat dot-delimited ECS keys
    (e.g. `"source.ip"`, `"ja4proxy.fingerprint.ja4"`, `"event.action"`, `"event.risk_score"`).

---

## 4. Step A: The Confirmation Modal & Undo Toast Components

We will create two reusable Alpine.js components in `management/static/`. These components implement **Decision 4** from Phase 231 exactly — the modal API must also be compatible with the calls from Phase 234's triage queue (`window.ConfirmModal.open({action, ip, score})`).

### 4.1 Confirmation Modal — `management/static/confirm-modal.js`

**Phase 231 Decision 4 modal requirements:**
- Show target IP/fingerprint and its current state in the modal
- Show proposed action and TTL
- Require a `reason` field (minimum 10 characters) for block/tarpit/allow actions
- Optional ticket/incident ID field
- Confirm button **disabled until reason field is filled**
- For allowlist actions: show danger warning ("This IP will bypass ALL JA4 scoring")
- Expose `window.ConfirmModal.open(config)` for backward compatibility with Phase 234 triage queue

```javascript
document.addEventListener('alpine:init', () => {
    // Decision 4 — confirmation modal standard component.
    // Called externally via window.ConfirmModal.open(config).
    Alpine.data('confirmModal', () => ({
        isOpen: false,
        title: '',
        message: '',
        confirmText: 'Confirm',
        actionUrl: '',         // POST URL (e.g. /api/v1/bans/{ip})
        undoUrl: '',           // DELETE URL (may differ from actionUrl)
        actionMethod: 'POST',
        action: '',            // 'block' | 'tarpit' | 'allow' | 'watchlist'
        target: '',            // IP or JA4 value
        currentState: '',      // 'active' | 'banned' | 'watched' | 'allowlisted'
        reason: '',
        ticketId: '',
        ttl: 3600,
        ttlOptions: [3600, 14400, 43200, 86400, 604800],
        isDanger: false,
        confirmDisabled: true,

        open(config) {
            this.action = config.action || 'block';
            this.target = config.ip || config.ja4 || config.target || '';
            this.currentState = config.currentState || 'active';

            // Determine modal content based on action
            const labels = {
                'block':     {title: 'Block IP',         url: `/api/v1/bans/${this.target}`},
                'tarpit':    {title: 'Tarpit IP',        url: `/api/v1/actions/${this.target}/tarpit`},
                'allow':     {title: 'Allowlist IP',     url: `/api/v1/allowlist/${this.target}`},
                'watchlist': {title: 'Add to Watchlist', url: `/api/v1/watchlist/${this.target}`},
            };
            const label = labels[this.action] || labels.block;
            this.title = label.title;
            this.actionUrl = label.url;
            // Undo URL: most actions are undone via DELETE to the same resource
            this.undoUrl = this.actionUrl;
            this.confirmText = this.title;
            this.isDanger = (this.action === 'block' || this.action === 'allow');
            this.reason = '';
            this.ticketId = '';
            this.ttl = config.ttl || 3600;
            this.confirmDisabled = true;
            this.isOpen = true;
        },

        close() {
            this.isOpen = false;
        },

        onReasonInput() {
            this.confirmDisabled = this.reason.trim().length < 10;
        },

        async submit() {
            if (this.reason.trim().length < 10) {
                return;
            }

            const body = {
                reason: this.reason.trim(),
                ttl: this.ttl,
            };
            if (this.ticketId.trim()) {
                body.ticket_id = this.ticketId.trim();
            }

            try {
                const response = await fetch(this.actionUrl, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(body),
                });

                if (response.ok) {
                    this.close();
                    window.dispatchEvent(new CustomEvent('action-completed', {
                        detail: {
                            message: `${this.title} applied to ${this.target}`,
                            undoUrl: this.undoUrl,
                            method: 'DELETE',
                        },
                    }));
                } else {
                    const err = await response.json();
                    window.dispatchEvent(new CustomEvent('action-error', {
                        detail: {message: err.detail || 'Action failed'},
                    }));
                }
            } catch (e) {
                console.error('confirmModal submit error:', e);
                window.dispatchEvent(new CustomEvent('action-error', {
                    detail: {message: 'Network error executing request.'},
                }));
            }
        },
    }));
});

// Decision 4 — expose window.ConfirmModal for Phase 234 triage queue compatibility.
window.ConfirmModal = {
    open(config) {
        const modalEl = document.querySelector('[x-data="confirmModal"]');
        if (modalEl && modalEl.__x) {
            modalEl.__x.$data.open(config);
        }
    },
};
```

**Usage in drill-down templates (Phase 235):**
```html
<button @click="$store.confirmModal.open({action:'block', ip:'1.2.3.4'})">
  Block IP
</button>
```

**Backward-compatible call from Phase 234 triage queue (already in triage_queue.html):**
```javascript
ConfirmModal.open({action:'block', ip:'{{ row.ip }}', score:{{ row.score }}})
```

### 4.2 Undo Toast — `management/static/undo-toast.js`

Decision 4 requires:
- Toast appears after any successful block/tarpit/ban with an Undo link
- 30-second countdown
- Undo fires DELETE and confirms reversal

```javascript
document.addEventListener('alpine:init', () => {
    Alpine.data('undoToast', () => ({
        visible: false,
        message: '',
        undoUrl: '',
        undoMethod: 'DELETE',
        countdown: 30,
        timer: null,

        init() {
            window.addEventListener('action-completed', (e) => {
                this.show(e.detail.message, e.detail.undoUrl, e.detail.method || 'DELETE');
            });

            window.addEventListener('action-error', (e) => {
                // Surface errors via a brief message instead of alert()
                const notifications = document.getElementById('notification-area');
                if (notifications) {
                    const div = document.createElement('div');
                    div.className = 'bg-red-900/80 text-red-200 px-4 py-2 rounded text-sm';
                    div.textContent = e.detail.message;
                    notifications.appendChild(div);
                    setTimeout(() => div.remove(), 5000);
                }
            });
        },

        show(msg, url, method) {
            this.message = msg;
            this.undoUrl = url;
            this.undoMethod = method || 'DELETE';
            this.countdown = 30;
            this.visible = true;

            if (this.timer) clearInterval(this.timer);
            this.timer = setInterval(() => {
                this.countdown--;
                if (this.countdown <= 0) this.hide();
            }, 1000);
        },

        hide() {
            this.visible = false;
            if (this.timer) {
                clearInterval(this.timer);
                this.timer = null;
            }
        },

        async undo() {
            try {
                const response = await fetch(this.undoUrl, {method: this.undoMethod});
                if (response.ok) {
                    this.hide();
                    // Surface confirmation via notification area
                    const notifications = document.getElementById('notification-area');
                    if (notifications) {
                        const div = document.createElement('div');
                        div.className = 'bg-green-900/80 text-green-200 px-4 py-2 rounded text-sm';
                        div.textContent = 'Action reverted successfully.';
                        notifications.appendChild(div);
                        setTimeout(() => div.remove(), 5000);
                    }
                    // Trigger HTMX refresh of ban status
                    document.body.dispatchEvent(new CustomEvent('ban-updated'));
                } else {
                    const notifications = document.getElementById('notification-area');
                    if (notifications) {
                        const div = document.createElement('div');
                        div.className = 'bg-red-900/80 text-red-200 px-4 py-2 rounded text-sm';
                        div.textContent = 'Failed to undo action.';
                        notifications.appendChild(div);
                        setTimeout(() => div.remove(), 5000);
                    }
                }
            } catch (e) {
                console.error('undo error:', e);
            }
        },
    }));
});
```

### 4.3 Add Scripts to Base Layout

Add the script tags to `management/templates/base.html`:

```diff
     <link rel="stylesheet" href="/static/custom.css">
     <script src="/static/vendor/alpine.min.js" defer></script>
     <script src="/static/vendor/htmx.min.js"></script>
+    <script src="/static/confirm-modal.js"></script>
+    <script src="/static/undo-toast.js"></script>
 </head>
```

### 4.4 Template for the Modal Itself

Create `management/templates/partials/confirm_modal.html`:

```html
<div
  x-data="confirmModal"
  x-show="isOpen"
  x-cloak
  class="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
  @keydown.escape.window="close()"
>
  <div class="bg-slate-800 rounded-lg shadow-xl w-full max-w-md mx-4 border border-slate-600">
    <div class="px-6 py-4 border-b border-slate-600">
      <h3 class="text-lg font-semibold text-slate-100" x-text="title"></h3>
    </div>

    <div class="px-6 py-4 space-y-4">
      <!-- Target & current state display (Decision 4) -->
      <div class="flex justify-between text-sm">
        <span class="text-slate-400">Target:</span>
        <span class="text-slate-100 font-mono" x-text="target"></span>
      </div>
      <div class="flex justify-between text-sm">
        <span class="text-slate-400">Current state:</span>
        <span class="text-slate-100" x-text="currentState"></span>
      </div>

      <!-- Danger warning for allowlist (Decision 4) -->
      <div x-show="action === 'allow'" class="bg-red-900/40 border border-red-700/50 rounded px-3 py-2 text-sm text-red-300">
        ⚠ This IP will bypass ALL JA4 scoring.
      </div>

      <!-- Reason field (Decision 4) -->
      <div>
        <label class="block text-sm text-slate-400 mb-1">Reason (minimum 10 characters)</label>
        <textarea
          x-model="reason"
          @input="onReasonInput()"
          class="w-full bg-slate-700 border border-slate-500 rounded px-3 py-2 text-slate-100 text-sm"
          rows="2"
          placeholder="Why is this action being taken?"
        ></textarea>
        <p class="text-xs text-slate-500 mt-1" x-show="reason.length > 0 && reason.length < 10">
          Need <span x-text="10 - reason.length"></span> more characters
        </p>
      </div>

      <!-- Optional ticket ID (Decision 4) -->
      <div>
        <label class="block text-sm text-slate-400 mb-1">Ticket / Incident ID (optional)</label>
        <input
          x-model="ticketId"
          type="text"
          class="w-full bg-slate-700 border border-slate-500 rounded px-3 py-2 text-slate-100 text-sm"
          placeholder="e.g. INC-12345"
        />
      </div>

      <!-- TTL selector -->
      <div>
        <label class="block text-sm text-slate-400 mb-1">Duration</label>
        <select
          x-model="ttl"
          class="w-full bg-slate-700 border border-slate-500 rounded px-3 py-2 text-slate-100 text-sm"
        >
          <option value="3600">1 hour</option>
          <option value="14400">4 hours</option>
          <option value="43200">12 hours</option>
          <option value="86400">1 day</option>
          <option value="604800">7 days</option>
          <option value="2592000">30 days</option>
        </select>
      </div>
    </div>

    <!-- Footer buttons (Decision 4: confirm disabled until reason filled) -->
    <div class="px-6 py-4 border-t border-slate-600 flex justify-end gap-3">
      <button
        @click="close()"
        class="px-4 py-2 text-sm text-slate-300 hover:text-slate-100 transition-colors"
      >
        Cancel
      </button>
      <button
        @click="submit()"
        :disabled="confirmDisabled"
        :class="confirmDisabled
          ? 'bg-slate-600 text-slate-500 cursor-not-allowed'
          : (isDanger ? 'bg-red-700 hover:bg-red-600 text-white' : 'bg-blue-700 hover:bg-blue-600 text-white')"
        class="px-4 py-2 text-sm font-semibold rounded transition-colors"
        x-text="confirmText"
      ></button>
    </div>
  </div>
</div>
```

---

## 5. Step B: JA4 Fingerprint Detail Page

### 5.1 API Endpoint — `GET /api/v1/fingerprints/{ja4}/profile`

Add to `management/api/routes/connections.py` (or a new `management/api/routes/fingerprints.py` if it grows). This reads from the **correct** stream key `events:connection` and parses the JSON-in-`event`-field payload that the Go proxy writes.

```python
from datetime import datetime, timedelta, timezone

_STREAM_KEY = "events:connection"  # Go proxy writes here


@router.get("/api/v1/fingerprints/{ja4}/profile")
async def get_fingerprint_profile(
    ja4: str,
    request: Request,
    current_user=Depends(require_role(Role.analyst)),
    redis=Depends(get_redis),
):
    """Aggregate profile for a JA4 fingerprint from the live event stream.

    Parses the event field (a JSON string of flat ECS keys) written by the
    Go proxy to ``events:connection``.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    cutoff_ms = int(cutoff.timestamp() * 1000)

    ips: set[str] = set()
    action_counts: dict[str, int] = {}
    hourly_buckets: dict[int, float] = {}
    total_events = 0

    # Read last 5000 events (capped 24h window)
    events = await redis.xrevrange(_STREAM_KEY, max="+", min="-", count=5000)
    for _msg_id, fields in events:
        raw = fields.get("event", "{}")
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue

        event_ts = parsed.get("@timestamp", "")
        if event_ts:
            try:
                ts = datetime.fromisoformat(event_ts)
                if ts.timestamp() * 1000 < cutoff_ms:
                    break  # xrevrange is newest-first; once past cutoff, stop
            except (ValueError, TypeError):
                pass

        evt_ja4 = parsed.get("ja4proxy.fingerprint.ja4", "")
        if evt_ja4 != ja4:
            continue

        total_events += 1
        src_ip = parsed.get("source.ip", "")
        if src_ip:
            ips.add(src_ip)

        action = parsed.get("event.action", "allow")
        action_counts[action] = action_counts.get(action, 0) + 1

        # Hourly bucket for time-series chart
        if event_ts:
            try:
                ts = datetime.fromisoformat(event_ts)
                hour_key = int(ts.replace(minute=0, second=0, microsecond=0).timestamp())
                score = parsed.get("event.risk_score", 0)
                if isinstance(score, (int, float)):
                    hourly_buckets[hour_key] = max(hourly_buckets.get(hour_key, 0), float(score))
            except (ValueError, TypeError):
                pass

    # Check list membership
    is_banned = await redis.exists(f"ban:{ja4}")
    is_allowlisted = await redis.sismember("allowlist", ja4)

    return {
        "ja4": ja4,
        "total_events": total_events,
        "unique_ips": len(ips),
        "ips_sample": sorted(ips)[:20],
        "action_counts": action_counts,
        "is_banned": bool(is_banned),
        "is_allowlisted": bool(is_allowlisted),
        "hourly_scores": [
            {"timestamp": k, "max_score": v}
            for k, v in sorted(hourly_buckets.items())
        ],
    }
```

**Route registration:** Add `include_router(fingerprints_router)` to `management/api/main.py`.

### 5.2 Page Route — `GET /fingerprint/{ja4}`

Add to `management/api/routes/pages.py`:

```python
@router.get("/fingerprint/{ja4}", response_class=HTMLResponse)
async def fingerprint_detail_page(
    request: Request,
    ja4: str,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Render the forensics page for a JA4 fingerprint."""
    templates = _get_templates()
    return templates.TemplateResponse(
        request,
        "fingerprint.html",
        {
            "user": current_user[0],
            "role": current_user[1],
            "ja4": ja4,
        },
    )
```

### 5.3 Template — `management/templates/fingerprint.html`

Extends `base.html`, includes `partials/confirm_modal.html`, uses Chart.js for the hourly score chart, Alpine.js for data binding.

```html
{% extends "base.html" %}
{% block title %}JA4 Fingerprint: {{ ja4 }}{% endblock %}
{% block content %}
<div class="max-w-6xl mx-auto px-4 py-6" x-data="fingerprintPage()">
  <!-- Breadcrumb -->
  <nav class="text-sm text-slate-400 mb-4">
    <a href="/dashboard" class="hover:text-blue-400">Dashboard</a>
    <span class="mx-2">/</span>
    <span class="text-slate-100">{{ ja4 }}</span>
  </nav>

  <!-- Header with actions -->
  <div class="flex items-center justify-between mb-6">
    <h1 class="text-2xl font-bold text-slate-100 font-mono">{{ ja4 }}</h1>
    <div class="flex gap-2">
      <button
        @click="ConfirmModal.open({action:'block', target:'{{ ja4 }}', currentState:'active'})"
        class="px-3 py-1.5 text-sm font-semibold rounded bg-red-800 hover:bg-red-700 text-red-200 transition-colors">
        Block
      </button>
      <button
        @click="ConfirmModal.open({action:'allow', target:'{{ ja4 }}', currentState:'active'})"
        class="px-3 py-1.5 text-sm font-semibold rounded bg-amber-800 hover:bg-amber-700 text-amber-200 transition-colors">
        Allowlist
      </button>
    </div>
  </div>

  <!-- Stats cards -->
  <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
    <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
      <p class="text-xs text-slate-400 uppercase tracking-wider">Total Events (24h)</p>
      <p class="text-2xl font-bold text-slate-100" x-text="profile.total_events">0</p>
    </div>
    <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
      <p class="text-xs text-slate-400 uppercase tracking-wider">Unique IPs</p>
      <p class="text-2xl font-bold text-slate-100" x-text="profile.unique_ips">0</p>
    </div>
    <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
      <p class="text-xs text-slate-400 uppercase tracking-wider">Banned</p>
      <p class="text-2xl font-bold" :class="profile.is_banned ? 'text-red-400' : 'text-green-400'" x-text="profile.is_banned ? 'Yes' : 'No'">No</p>
    </div>
    <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
      <p class="text-xs text-slate-400 uppercase tracking-wider">Allowlisted</p>
      <p class="text-2xl font-bold" :class="profile.is_allowlisted ? 'text-amber-400' : 'text-green-400'" x-text="profile.is_allowlisted ? 'Yes' : 'No'">No</p>
    </div>
  </div>

  <!-- Hourly score chart -->
  <div class="bg-slate-800 rounded-lg p-4 border border-slate-700 mb-6">
    <h2 class="text-sm font-semibold text-slate-300 mb-3">Risk Score Timeline (24h)</h2>
    <div class="relative" style="height: 200px;">
      <canvas x-ref="scoreChart"></canvas>
    </div>
  </div>

  <!-- Associated IPs -->
  <div class="bg-slate-800 rounded-lg p-4 border border-slate-700 mb-6">
    <h2 class="text-sm font-semibold text-slate-300 mb-3">Associated IPs</h2>
    <div class="space-y-1">
      <template x-for="ip in profile.ips_sample" :key="ip">
        <a :href="'/ip/' + ip" class="block text-sm text-blue-400 hover:underline font-mono" x-text="ip"></a>
      </template>
      <p x-show="!profile.ips_sample || profile.ips_sample.length === 0" class="text-sm text-slate-500">No IPs found</p>
    </div>
  </div>

  <!-- Action breakdown -->
  <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
    <h2 class="text-sm font-semibold text-slate-300 mb-3">Action Breakdown</h2>
    <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
      <div class="bg-slate-700/50 rounded p-3 text-center">
        <p class="text-xs text-slate-400">Allow</p>
        <p class="text-lg font-bold text-green-400" x-text="profile.action_counts.allow || 0">0</p>
      </div>
      <div class="bg-slate-700/50 rounded p-3 text-center">
        <p class="text-xs text-slate-400">Flag</p>
        <p class="text-lg font-bold text-yellow-400" x-text="profile.action_counts.flag || 0">0</p>
      </div>
      <div class="bg-slate-700/50 rounded p-3 text-center">
        <p class="text-xs text-slate-400">Block</p>
        <p class="text-lg font-bold text-red-400" x-text="profile.action_counts.block || 0">0</p>
      </div>
      <div class="bg-slate-700/50 rounded p-3 text-center">
        <p class="text-xs text-slate-400">Tarpit</p>
        <p class="text-lg font-bold text-purple-400" x-text="profile.action_counts.tarpit || 0">0</p>
      </div>
    </div>
  </div>
</div>

{% include "partials/confirm_modal.html" %}
{% endblock %}

{% block scripts %}
<script>
function fingerprintPage() {
    return {
        profile: {
            total_events: 0,
            unique_ips: 0,
            ips_sample: [],
            action_counts: {},
            is_banned: false,
            is_allowlisted: false,
            hourly_scores: [],
        },
        chart: null,

        async init() {
            await this.fetchProfile();
            this.$nextTick(() => this.renderChart());
        },

        async fetchProfile() {
            try {
                const resp = await fetch('/api/v1/fingerprints/{{ ja4 }}/profile');
                if (resp.ok) {
                    this.profile = await resp.json();
                }
            } catch (e) {
                console.error('Failed to load fingerprint profile:', e);
            }
        },

        renderChart() {
            const canvas = this.$refs.scoreChart;
            if (!canvas) return;
            const scores = this.profile.hourly_scores || [];
            const labels = scores.map(s => {
                const d = new Date(s.timestamp * 1000);
                return d.getHours().toString().padStart(2, '0') + ':00';
            });
            const data = scores.map(s => s.max_score);

            if (this.chart) this.chart.destroy();
            this.chart = new Chart(canvas, {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Max Risk Score',
                        data: data,
                        backgroundColor: 'rgba(59, 130, 246, 0.5)',
                        borderColor: 'rgba(59, 130, 246, 1)',
                        borderWidth: 1,
                    }],
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {beginAtZero: true, max: 100, grid: {color: 'rgba(148, 163, 184, 0.1)'}},
                        x: {grid: {display: false}},
                    },
                    plugins: {legend: {display: false}},
                },
            });
        },
    };
}
</script>
{% endblock %}
```

### 5.4 Tailwind Class Note
The `font-mono` class is already covered by the Tailwind purge safelist (`src/tailwind.config.js`). If the config does not include it, add it to the safelist array.

---

## 6. Step C: IP Detail Page

### 6.1 API Endpoint — `GET /api/v1/ip/{ip:path}/profile`

Add to `management/api/routes/connections.py` (or new `management/api/routes/ip_profile.py`). Uses the **`:path`** converter so IPv4 dotted decimals and IPv6 addresses work without truncation.

```python
@router.get("/api/v1/ip/{ip:path}/profile")
async def get_ip_profile(
    ip: str,
    request: Request,
    current_user=Depends(require_role(Role.analyst)),
    redis=Depends(get_redis),
):
    """Aggregate profile for a source IP from the live event stream.

    The ``:path`` converter preserves dots and colons so IPv4 and IPv6
    addresses are not truncated by FastAPI's default string converter.
    """
    ip = urllib.parse.unquote(ip)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    cutoff_ms = int(cutoff.timestamp() * 1000)

    ja4_set: set[str] = set()
    history: list[dict] = []
    hourly_buckets: dict[int, list[float]] = {}
    total_events = 0

    events = await redis.xrevrange(_STREAM_KEY, max="+", min="-", count=5000)
    for _msg_id, fields in events:
        raw = fields.get("event", "{}")
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue

        event_ts = parsed.get("@timestamp", "")
        if event_ts:
            try:
                ts = datetime.fromisoformat(event_ts)
                if ts.timestamp() * 1000 < cutoff_ms:
                    break
            except (ValueError, TypeError):
                pass

        src_ip = parsed.get("source.ip", "")
        if src_ip != ip:
            continue

        total_events += 1
        ja4 = parsed.get("ja4proxy.fingerprint.ja4", "")
        if ja4:
            ja4_set.add(ja4)

        action = parsed.get("event.action", "allow")
        score = parsed.get("event.risk_score", 0)
        try:
            score = float(score)
        except (ValueError, TypeError):
            score = 0.0

        history.append({
            "timestamp": event_ts,
            "action": action,
            "score": score,
            "ja4": ja4,
        })

        # Hourly buckets for time-series chart
        if event_ts:
            try:
                ts = datetime.fromisoformat(event_ts)
                hour_key = int(ts.replace(minute=0, second=0, microsecond=0).timestamp())
                if hour_key not in hourly_buckets:
                    hourly_buckets[hour_key] = []
                hourly_buckets[hour_key].append(score)
            except (ValueError, TypeError):
                pass

    # Compute hourly averages
    hourly_scores = [
        {"timestamp": k, "avg_score": round(sum(v) / len(v), 1), "max_score": max(v)}
        for k, v in sorted(hourly_buckets.items())
    ]

    # Check ban status
    is_banned = await redis.exists(f"ban:{ip}")

    return {
        "ip": ip,
        "total_events": total_events,
        "unique_ja4": len(ja4_set),
        "fingerprints": sorted(ja4_set),
        "is_banned": bool(is_banned),
        "geo": {"country": "Unknown", "asn": "Unknown"},
        "history": history[-50:],
        "hourly_scores": hourly_scores,
    }
```

### 6.2 Page Route — `GET /ip/{ip:path}`

Add to `management/api/routes/pages.py`:

```python
@router.get("/ip/{ip:path}", response_class=HTMLResponse)
async def ip_detail_page(
    request: Request,
    ip: str,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Render the forensics page for an IP address."""
    templates = _get_templates()
    return templates.TemplateResponse(
        request,
        "ip_detail.html",
        {
            "user": current_user[0],
            "role": current_user[1],
            "ip": urllib.parse.unquote(ip),
        },
    )
```

### 6.3 Template — `management/templates/ip_detail.html`

```html
{% extends "base.html" %}
{% block title %}IP: {{ ip }}{% endblock %}
{% block content %}
<div class="max-w-6xl mx-auto px-4 py-6" x-data="ipPage()">
  <!-- Breadcrumb -->
  <nav class="text-sm text-slate-400 mb-4">
    <a href="/dashboard" class="hover:text-blue-400">Dashboard</a>
    <span class="mx-2">/</span>
    <span class="text-slate-100">{{ ip }}</span>
  </nav>

  <!-- Header with actions -->
  <div class="flex items-center justify-between mb-6">
    <h1 class="text-2xl font-bold text-slate-100 font-mono">{{ ip }}</h1>
    <div class="flex gap-2">
      <button
        @click="ConfirmModal.open({action:'block', ip:'{{ ip }}', currentState: profile.is_banned ? 'banned' : 'active'})"
        class="px-3 py-1.5 text-sm font-semibold rounded bg-red-800 hover:bg-red-700 text-red-200 transition-colors">
        Block
      </button>
      <button
        @click="ConfirmModal.open({action:'allow', ip:'{{ ip }}', currentState: 'active'})"
        class="px-3 py-1.5 text-sm font-semibold rounded bg-amber-800 hover:bg-amber-700 text-amber-200 transition-colors">
        Allowlist
      </button>
    </div>
  </div>

  <!-- Stats cards -->
  <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
    <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
      <p class="text-xs text-slate-400 uppercase tracking-wider">Total Events (24h)</p>
      <p class="text-2xl font-bold text-slate-100" x-text="profile.total_events">0</p>
    </div>
    <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
      <p class="text-xs text-slate-400 uppercase tracking-wider">Unique JA4s</p>
      <p class="text-2xl font-bold text-slate-100" x-text="profile.unique_ja4">0</p>
    </div>
    <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
      <p class="text-xs text-slate-400 uppercase tracking-wider">Banned</p>
      <p class="text-2xl font-bold" :class="profile.is_banned ? 'text-red-400' : 'text-green-400'" x-text="profile.is_banned ? 'Yes' : 'No'">No</p>
    </div>
    <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
      <p class="text-xs text-slate-400 uppercase tracking-wider">Country / ASN</p>
      <p class="text-lg font-bold text-slate-100" x-text="profile.geo.country + ' / ' + profile.geo.asn">Unknown</p>
    </div>
  </div>

  <!-- Risk score chart -->
  <div class="bg-slate-800 rounded-lg p-4 border border-slate-700 mb-6">
    <h2 class="text-sm font-semibold text-slate-300 mb-3">Risk Score Timeline (24h)</h2>
    <div class="relative" style="height: 200px;">
      <canvas x-ref="scoreChart"></canvas>
    </div>
  </div>

  <!-- Fingerprints -->
  <div class="bg-slate-800 rounded-lg p-4 border border-slate-700 mb-6">
    <h2 class="text-sm font-semibold text-slate-300 mb-3">JA4 Fingerprints</h2>
    <div class="space-y-1">
      <template x-for="ja4 in profile.fingerprints" :key="ja4">
        <a :href="'/fingerprint/' + ja4" class="block text-sm text-blue-400 hover:underline font-mono truncate" x-text="ja4"></a>
      </template>
      <p x-show="!profile.fingerprints || profile.fingerprints.length === 0" class="text-sm text-slate-500">No fingerprints found</p>
    </div>
  </div>

  <!-- Recent history -->
  <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
    <h2 class="text-sm font-semibold text-slate-300 mb-3">Recent Activity</h2>
    <div class="overflow-x-auto">
      <table class="w-full text-sm">
        <thead>
          <tr class="text-slate-400 text-left">
            <th class="pb-2 pr-4">Timestamp</th>
            <th class="pb-2 pr-4">Action</th>
            <th class="pb-2 pr-4">Score</th>
            <th class="pb-2">JA4</th>
          </tr>
        </thead>
        <tbody>
          <template x-for="(event, idx) in profile.history" :key="idx">
            <tr class="border-t border-slate-700/50">
              <td class="py-1.5 pr-4 text-slate-300 text-xs" x-text="event.timestamp"></td>
              <td class="py-1.5 pr-4">
                <span
                  class="px-1.5 py-0.5 rounded text-xs font-medium"
                  :class="{
                    'bg-green-900/50 text-green-300': event.action === 'allow',
                    'bg-yellow-900/50 text-yellow-300': event.action === 'flag' || event.action === 'rate_limit',
                    'bg-red-900/50 text-red-300': event.action === 'block' || event.action === 'ban',
                    'bg-purple-900/50 text-purple-300': event.action === 'tarpit',
                  }"
                  x-text="event.action"
                ></span>
              </td>
              <td class="py-1.5 pr-4 text-slate-300" x-text="event.score"></td>
              <td class="py-1.5 text-blue-400 hover:underline font-mono text-xs">
                <a :href="'/fingerprint/' + event.ja4" x-text="event.ja4"></a>
              </td>
            </tr>
          </template>
          <tr x-show="!profile.history || profile.history.length === 0">
            <td colspan="4" class="py-4 text-center text-slate-500">No recent activity</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

{% include "partials/confirm_modal.html" %}
{% endblock %}

{% block scripts %}
<script>
function ipPage() {
    return {
        profile: {
            total_events: 0,
            unique_ja4: 0,
            fingerprints: [],
            is_banned: false,
            geo: {country: 'Unknown', asn: 'Unknown'},
            history: [],
            hourly_scores: [],
        },
        chart: null,

        async init() {
            await this.fetchProfile();
            this.$nextTick(() => this.renderChart());
        },

        async fetchProfile() {
            try {
                const resp = await fetch('/api/v1/ip/{{ ip }}/profile');
                if (resp.ok) {
                    this.profile = await resp.json();
                }
            } catch (e) {
                console.error('Failed to load IP profile:', e);
            }
        },

        renderChart() {
            const canvas = this.$refs.scoreChart;
            if (!canvas) return;
            const scores = this.profile.hourly_scores || [];
            const labels = scores.map(s => {
                const d = new Date(s.timestamp * 1000);
                return d.getHours().toString().padStart(2, '0') + ':00';
            });
            const avgData = scores.map(s => s.avg_score);
            const maxData = scores.map(s => s.max_score);

            if (this.chart) this.chart.destroy();
            this.chart = new Chart(canvas, {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'Avg Score',
                            data: avgData,
                            backgroundColor: 'rgba(59, 130, 246, 0.5)',
                            borderColor: 'rgba(59, 130, 246, 1)',
                            borderWidth: 1,
                        },
                        {
                            label: 'Max Score',
                            data: maxData,
                            backgroundColor: 'rgba(239, 68, 68, 0.4)',
                            borderColor: 'rgba(239, 68, 68, 1)',
                            borderWidth: 1,
                        },
                    ],
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {beginAtZero: true, max: 100, grid: {color: 'rgba(148, 163, 184, 0.1)'}},
                        x: {grid: {display: false}},
                    },
                    plugins: {legend: {labels: {color: '#94a3b8'}}},
                },
            });
        },
    };
}
</script>
{% endblock %}
```

---

## 7. Step D: Make Live Feed Items Clickable

### 7.1 Update the SSE Event Generator

The current `management/api/routes/events.py` reads from the stale stream key `ja4proxy:events` with field name `data`. Phase 235 must **fix** it to read from `events:connection` and parse the `event` field, then emit enriched rows with clickable links.

**Key changes to `events.py`:**
- Change `_STREAM_KEY = "ja4proxy:events"` to `_STREAM_KEY = "events:connection"`
- Change `fields.get("data", "{}")` to `fields.get("event", "{}")`
- Parse the JSON and extract `source.ip`, `ja4proxy.fingerprint.ja4`, etc.
- Yield enriched HTML rows with clickable links

```diff
--- a/management/api/routes/events.py
+++ b/management/api/routes/events.py
@@ -1,11 +1,17 @@
-"""SSE events endpoint — GET /api/v1/events.
-
-Streams events from the ``ja4proxy:events`` Redis Stream to connected
-clients using Server-Sent Events (SSE).
-
-Each event read from the stream is forwarded as a SSE ``data:`` line
-containing the JSON payload.
-
-Implementation notes
--------------------
-- Uses XREAD with BLOCK=1000ms to avoid busy-waiting.
-- Tracks the last stream ID seen so reconnecting clients don't get
-  duplicate events (they start from the current tip).
-- Handles client disconnect gracefully via asyncio.CancelledError.
-- Multiple concurrent clients are supported (each has its own cursor).
-"""
+"""SSE events endpoint — GET /api/v1/events.
+
+Streams connection events from ``events:connection`` (the stream the Go
+proxy writes to) and yields enriched HTML table rows with clickable IP
+and JA4 links to the drill-down pages.
+
+Each Redis stream entry has one field ``event`` containing a JSON string
+of flat ECS-dotted keys (written by the Go proxy at ``cmd/ja4pd/main.go``).
+
+Implementation notes
+--------------------
+- Uses XREAD with BLOCK=1000ms to avoid busy-waiting.
+- Tracks the last stream ID seen so reconnecting clients don't get
+  duplicate events (they start from the current tip).
+- Handles client disconnect gracefully via asyncio.CancelledError.
+- Multiple concurrent clients are supported (each has its own cursor).
+"""

 _STREAM_KEY = "ja4proxy:events"
+_STREAM_KEY = "events:connection"
```

**Update the event generator body:**

```python
async def _event_generator(request: Request, redis):
    """Async generator that yields SSE events from the Redis Stream.

    Each event is a JSON string of flat ECS-dotted keys. We parse it,
    extract the fields needed for the live feed table, and yield an
    enriched HTML row with clickable IP/JA4 links.
    """
    last_id = "$"

    while True:
        if await request.is_disconnected():
            logger.debug("events | event=client_disconnected")
            break

        try:
            results = await redis.xread(
                {_STREAM_KEY: last_id},
                block=_BLOCK_MS,
                count=10,
            )
        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            logger.warning("events | event=stream_error | error=%s", exc)
            await asyncio.sleep(1)
            continue

        if not results:
            yield {"comment": "keepalive"}
            continue

        for _stream_key, messages in results:
            for msg_id, fields in messages:
                last_id = msg_id
                raw = fields.get("event", "{}")
                try:
                    parsed = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    parsed = {}

                # ── Build live-feed table row ─────────────────────────────
                ts = parsed.get("@timestamp", "")
                if ts:
                    try:
                        # Format timestamp to HH:MM:SS
                        dt = datetime.fromisoformat(ts)
                        ts_display = dt.strftime("%H:%M:%S")
                    except (ValueError, TypeError):
                        ts_display = ts
                else:
                    ts_display = msg_id[:8] if msg_id else ""

                ip = parsed.get("source.ip", "")
                ja4 = parsed.get("ja4proxy.fingerprint.ja4", "")
                action = parsed.get("event.action", "allow")
                score = parsed.get("event.risk_score", 0)

                # Escape HTML in values
                from html import escape
                ip_esc = escape(ip)
                ja4_esc = escape(ja4)
                ts_esc = escape(ts_display)
                action_esc = escape(action)
                score_esc = escape(str(score))

                row_html = (
                    f'<tr class="border-b border-slate-700/50 hover:bg-slate-700/30 transition-colors">'
                    f'<td class="py-2 px-3 text-xs text-slate-400">{ts_esc}</td>'
                    f'<td class="py-2 px-3"><a href="/ip/{ip_esc}" '
                    f'class="text-blue-400 hover:underline font-mono text-xs">{ip_esc}</a></td>'
                    f'<td class="py-2 px-3"><a href="/fingerprint/{ja4_esc}" '
                    f'class="text-blue-400 hover:underline font-mono text-xs truncate max-w-[200px] inline-block">{ja4_esc}</a></td>'
                    f'<td class="py-2 px-3">'
                    f'<span class="px-1.5 py-0.5 rounded text-xs font-medium '
                    f'{"bg-red-900/50 text-red-300" if action in ("block","ban") else ""}'
                    f'{"bg-yellow-900/50 text-yellow-300" if action in ("flag","rate_limit") else ""}'
                    f'{"bg-green-900/50 text-green-300" if action == "allow" else ""}'
                    f'{"bg-purple-900/50 text-purple-300" if action == "tarpit" else ""}'
                    f'">{action_esc}</span></td>'
                    f'<td class="py-2 px-3 text-xs text-slate-300 text-right">{score_esc}</td>'
                    f'</tr>'
                )

                yield {"data": row_html, "id": msg_id}
```

### 7.2 Update the Live Feed Template

`management/templates/partials/live_feed.html` already renders an empty table body that the SSE fills. No template changes needed if the SSE now emits full `<tr>` HTML — verify the existing JS client appends `event.data` as raw HTML into `<tbody>`.

If the client uses `.textContent =` instead of `.innerHTML =`, update the receiving JS to use `innerHTML`:

```javascript
// Inside the EventSource handler in the dashboard template
source.addEventListener('message', function(e) {
    const tbody = document.querySelector('#live-feed tbody');
    if (tbody) {
        const tr = document.createElement('tr');
        tr.innerHTML = e.data;
        tbody.prependChild(tr);           // newest at top
        // Trim to 100 rows to avoid memory bloat
        while (tbody.children.length > 100) {
            tbody.removeChild(tbody.lastChild);
        }
    }
});
```

---

## 8. Test Strategy

### 8.1 Unit Tests

All tests must run inside the `ja4proxy-tools` container via `make test-unit` (or `docker run`).

| Test file | What it covers |
|-----------|---------------|
| `tests/unit/test_ip_profile.py` | `GET /api/v1/ip/{ip:path}/profile` — mock Redis, inject known events with correct `event` field JSON, assert profile shape, field parsing, ban status, hourly bucketing |
| `tests/unit/test_fingerprint_profile.py` | `GET /api/v1/fingerprints/{ja4}/profile` — same pattern, assert action_counts, unique IPs, hourly_scores |
| `tests/unit/test_pages.py` (extend) | `GET /ip/{ip}` and `GET /fingerprint/{ja4}` — assert 200 with `text/html`, verify template context |
| `tests/unit/test_events_sse.py` (extend) | `GET /api/v1/events` — assert stream key is `events:connection`, field key is `event`, output contains `<a href="/ip/...">` |
| `tests/unit/test_confirm_modal.py` | Modal JS — verify `confirmDisabled` state, reason field validation, ticketId field, danger warning display for allow action |
| `tests/unit/test_bans.py` (extend) | Verify `POST /api/v1/bans/{ip:path}` with ticket_id field in audit log |

**Key mock setup for event stream tests:**

```python
@pytest.fixture
def mock_redis_with_events(mocker):
    """Seed mock Redis with events matching the Go proxy's output format."""
    redis = mocker.AsyncMock()
    redis.xrevrange.return_value = [
        (
            "1718467200000-0",
            {
                "event": json.dumps({
                    "@timestamp": "2026-06-15T12:00:00.000000+00:00",
                    "event.action": "block",
                    "event.risk_score": 85,
                    "source.ip": "10.0.0.1",
                    "ja4proxy.fingerprint.ja4": "t13d1516h2_8a1a1a1a1a1a1a1a",
                    "ja4proxy.sni": "evil.com",
                }),
            },
        ),
    ]
    return redis
```

### 8.2 API Verification

```bash
# Query IP profile (dots preserved via :path converter)
curl -s -H "Cookie: session=$(make get-test-token)" \
  http://localhost:8090/api/v1/ip/1.2.3.4/profile | jq .

# Query fingerprint profile
curl -s -H "Cookie: session=$(make get-test-token)" \
  http://localhost:8090/api/v1/fingerprints/t13d1516h2_8a1a1a1a1a1a1a1a/profile | jq .
```

### 8.3 UI Verification

1. Open `/dashboard`, verify live feed shows clickable IP (blue link) and JA4 (blue link)
2. Click an IP → navigates to `/ip/{ip}` with chart rendering
3. Click a JA4 → navigates to `/fingerprint/{ja4}` with chart rendering
4. Click "Block" → modal opens, confirm button disabled, type reason → button enables
5. Submit block → ban created, undo toast appears with 30s countdown
6. Click "Undo" → ban deleted, notification shown

### 8.4 Pre-PR Gate

```bash
make preflight
# Must exit 0 with zero warnings/errors
```

---

## 9. Definition of Done

*   [ ] Clicking an IP or JA4 in the live feed redirects to `/ip/{ip}` or `/fingerprint/{ja4}`.
*   [ ] IP detail page renders risk score history chart via Chart.js with hourly avg/max buckets.
*   [ ] Fingerprint detail page renders risk score timeline and action breakdown.
*   [ ] Modal (Decision 4): target/current-state display, reason field (≥10 chars), optional ticket ID, confirm button disabled until filled, danger warning for allowlist.
*   [ ] Undo toast appears after block/tarpit with 30s countdown and DELETE-on-click.
*   [ ] All stream reads use key `events:connection` and parse the `event` JSON field.
*   [ ] All IP route parameters use `{ip:path}` FastAPI converter.
*   [ ] `GET /api/v1/events` SSE emits clickable `<a>` links in enriched HTML rows.
*   [ ] All new API endpoints registered in `management/api/main.py`.
*   [ ] Tests in `tests/unit/test_ip_profile.py`, `test_fingerprint_profile.py`, `test_events_sse.py` pass.
*   [ ] `make preflight` exits 0.
*   [ ] No host-Python virtual environments used — all commands via `make` targets or `ja4proxy-tools` Docker image.

---

## 10. Common Mistakes

*   **Wrong stream key:** The Go proxy writes to `events:connection`, not `ja4proxy:events`. Using the old key yields empty results — the SSE live feed is currently broken for this reason.
*   **Wrong payload shape:** Stream entries have a single `event` field whose value is a JSON string. Do **not** use `fields.get(b"ip", ...)` — the IP is at `parsed["source.ip"]` after `json.loads(fields["event"])`.
*   **Missing `:path` converter on IP routes:** FastAPI's default `str` converter truncates at the first dot. Use `{ip:path}` and `urllib.parse.unquote(ip)`.
*   **Chart.js canvas sizing:** Failing to wrap the `<canvas>` element in a relative container with a fixed height causes the chart to grow infinitely on window resize.
*   **Alpine.js x-data scope:** Defining the confirmation modal variables inside a nested child element rather than at the root modal container level.
*   **Lazy logger formatting:** Use `logger.info("profile fetched for %s", ip)` not `logger.info(f"profile fetched for {ip}")`.
*   **Container-strict rule:** Never run Python on the host. Use `make test-unit`, `make lint`, or `docker run --rm -v "$PWD":/src -w /src ja4proxy-tools ...`.
