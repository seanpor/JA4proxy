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

> **Before you touch a line of code**, read `docs/phases/PHASE_231.md`.
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
*   Verify that Tailwind and static assets are loading correctly in your local environment:
    ```bash
    cd /home/sean/LLM/JA4proxy
    ./.venv314/bin/python3 -m pytest tests/unit/test_pages.py
    ```

---

## 4. Step A: The Confirmation Modal & Undo Toast Components

We will create two reusable Alpine.js components in the `management/static/` folder.

### 4.1 Confirmation Modal Component
Create a new file `/home/sean/LLM/JA4proxy/management/static/confirm-modal.js`:

```javascript
document.addEventListener('alpine:init', () => {
    Alpine.data('confirmModal', () => ({
        isOpen: false,
        title: '',
        message: '',
        confirmText: 'Confirm',
        actionUrl: '',
        actionMethod: 'POST',
        reason: '',
        ttl: 3600,
        isDanger: false,

        open(config) {
            this.title = config.title || 'Confirm Action';
            this.message = config.message || 'Are you sure you want to proceed?';
            this.confirmText = config.confirmText || 'Confirm';
            this.actionUrl = config.actionUrl;
            this.actionMethod = config.actionMethod || 'POST';
            this.isDanger = config.isDanger || false;
            this.reason = '';
            this.ttl = config.ttl || 3600;
            this.isOpen = true;
        },

        close() {
            this.isOpen = false;
        },

        async submit() {
            if (this.reason.length < 10) {
                alert('A detailed justification (minimum 10 characters) is required.');
                return;
            }

            try {
                const response = await fetch(this.actionUrl, {
                    method: this.actionMethod,
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        reason: this.reason,
                        ttl_seconds: this.ttl
                    })
                });

                if (response.ok) {
                    this.close();
                    // Trigger custom event for undo toast
                    window.dispatchEvent(new CustomEvent('action-completed', {
                        detail: { message: `${this.title} applied successfully`, undoUrl: this.actionUrl }
                    }));
                    // Reload page or trigger HTMX swap
                    setTimeout(() => window.location.reload(), 1000);
                } else {
                    const err = await response.json();
                    alert(`Error: ${err.detail || 'Action failed'}`);
                }
            } catch (e) {
                console.error(e);
                alert('Network error executing request.');
            }
        }
    }));
});
```

### 4.2 Undo Toast Component
Create a new file `/home/sean/LLM/JA4proxy/management/static/undo-toast.js`:

```javascript
document.addEventListener('alpine:init', () => {
    Alpine.data('undoToast', () => ({
        visible: false,
        message: '',
        undoUrl: '',
        countdown: 30,
        timer: null,

        init() {
            window.addEventListener('action-completed', (e) => {
                this.show(e.detail.message, e.detail.undoUrl);
            });
        },

        show(msg, url) {
            this.message = msg;
            this.undoUrl = url;
            this.countdown = 30;
            this.visible = true;

            if (this.timer) clearInterval(this.timer);

            this.timer = setInterval(() => {
                this.countdown--;
                if (this.countdown <= 0) {
                    this.hide();
                }
            }, 1000);
        },

        hide() {
            this.visible = false;
            if (this.timer) clearInterval(this.timer);
        },

        async undo() {
            try {
                const response = await fetch(this.undoUrl, {
                    method: 'DELETE'
                });
                if (response.ok) {
                    alert('Action successfully reverted.');
                    this.hide();
                    window.location.reload();
                } else {
                    alert('Failed to undo action.');
                }
            } catch (e) {
                console.error(e);
            }
        }
    }));
});
```

### 4.3 Add Scripts to Base Layout
Add the script tags to `/home/sean/LLM/JA4proxy/management/templates/base.html`:

```diff
     <link rel="stylesheet" href="/static/custom.css">
     <script src="/static/vendor/alpine.min.js" defer></script>
     <script src="/static/vendor/htmx.min.js"></script>
+    <script src="/static/confirm-modal.js"></script>
+    <script src="/static/undo-toast.js"></script>
 </head>
```

---

## 5. Step B: JA4 Fingerprint Detail Page

### 5.1 Route Setup in `pages.py`
Add the route to `/home/sean/LLM/JA4proxy/management/api/routes/pages.py`:

```python
@router.get("/fingerprint/{ja4}", response_class=HTMLResponse)
async def fingerprint_detail_page(
    request: Request,
    ja4: str,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Render the detailed forensics page for a JA4 fingerprint."""
    templates = _get_templates()

    # Query existing connection endpoints or directly read stats
    # For this phase, fetch recent connections matching this JA4
    cursor = 0
    ips = set()
    action_counts = {"allow": 0, "monitor": 0, "block": 0, "tarpit": 0}

    # Retrieve history from Redis Stream (ja4proxy:events)
    # Reads recent 5000 events to build the stats
    events = await redis.xrevrange("ja4proxy:events", max="+", min="-", count=5000)
    for _, fields in events:
        evt_ja4 = fields.get(b"ja4", b"").decode("utf-8")
        if evt_ja4 == ja4:
            ip = fields.get(b"ip", b"").decode("utf-8")
            action = fields.get(b"action_taken", b"allow").decode("utf-8")
            ips.add(ip)
            if action in action_counts:
                action_counts[action] += 1

    return templates.TemplateResponse(
        request,
        "fingerprint.html",
        {
            "user": current_user[0],
            "role": current_user[1],  # passes role for RBAC
            "ja4": ja4,
            "associated_ips": list(ips)[:10],
            "action_counts": action_counts,
        },
    )
```

---

## 6. Step C: IP Detail Page

### 6.1 Create the API Endpoint
Add a new API route in `/home/sean/LLM/JA4proxy/management/api/routes/connections.py` to fetch IP profile data:

```python
@router.get("/api/v1/ip/{ip}")
async def get_ip_profile(
    ip: str,
    current_user=Depends(require_role(Role.analyst)),
    redis=Depends(get_redis),
):
    """Retrieve full history and aggregated profile for an IP address."""
    events = await redis.xrevrange("ja4proxy:events", max="+", min="-", count=2000)
    
    fingerprints = set()
    history = []
    geo_info = {"country": "Unknown", "asn": "Unknown"}

    for _, fields in events:
        evt_ip = fields.get(b"ip", b"").decode("utf-8")
        if evt_ip == ip:
            ja4 = fields.get(b"ja4", b"").decode("utf-8")
            score = int(fields.get(b"risk_score", b"0").decode("utf-8"))
            action = fields.get(b"action_taken", b"allow").decode("utf-8")
            ts = fields.get(b"timestamp", b"").decode("utf-8")
            
            fingerprints.add(ja4)
            history.append({"timestamp": ts, "score": score, "action": action})
            
            # Extract Geo/ASN if enriched
            if b"geo_country" in fields:
                geo_info["country"] = fields[b"geo_country"].decode("utf-8")
            if b"geo_asn" in fields:
                geo_info["asn"] = fields[b"geo_asn"].decode("utf-8")

    # Check ban status
    is_banned = await redis.exists(f"ban:{ip}")
    
    return {
        "ip": ip,
        "is_banned": bool(is_banned),
        "fingerprints": list(fingerprints),
        "geo": geo_info,
        "history": history[:50]
    }
```

### 6.2 Page Route in `pages.py`
Add the page route in `/home/sean/LLM/JA4proxy/management/api/routes/pages.py`:

```python
@router.get("/ip/{ip}", response_class=HTMLResponse)
async def ip_detail_page(
    request: Request,
    ip: str,
    current_user=Depends(get_current_user),
) -> HTMLResponse:
    """Render the detailed forensics page for an IP address."""
    templates = _get_templates()
    return templates.TemplateResponse(
        request,
        "ip_detail.html",
        {"user": current_user[0], "role": current_user[1], "ip": ip},
    )
```

---

## 7. Step D: Make Live Feed Items Clickable

Update the live feed row template to link IPs and JA4 values to their detail pages.

### File to modify: `/home/sean/LLM/JA4proxy/management/templates/partials/live_feed.html`

Modify the table cells to output links instead of raw text:

```diff
       <tbody>
         <!-- Example row format to be returned by SSE stream -->
         <tr>
-          <td>12:34:56</td>
-          <td>192.168.1.50</td>
-          <td>ja4_example_value</td>
+          <td class="text-[#f8fafc]">12:34:56</td>
+          <td><a href="/ip/{{ ip }}" class="text-[#3b82f6] hover:underline">{{ ip }}</a></td>
+          <td><a href="/fingerprint/{{ ja4 }}" class="text-[#3b82f6] hover:underline font-mono">{{ ja4 }}</a></td>
```

*(Note: the SSE stream generator in `events.py` should be updated if it generates raw HTML, but since it sends JSON, ensure the frontend template or JS client correctly constructs these links).*

---

## 8. Test Strategy

1.  **Unit Tests:**
    Run page rendering tests:
    ```bash
    pytest tests/unit/test_pages.py
    ```
2.  **API Verification:**
    Query the IP profile API via curl:
    ```bash
    curl -H "Cookie: session=<token>" http://localhost:8090/api/v1/ip/1.2.3.4
    ```
3.  **UI Verification:**
    Open the dashboard, click an IP, verify the detail page loads with Chart.js rendering a timeline.

---

## 9. Definition of Done

*   [ ] Clicking an IP or JA4 in the live feed redirects to `/ip/{ip}` or `/fingerprint/{ja4}`.
*   [ ] IP detail page renders a risk score history chart using Chart.js.
*   [ ] Actions (Block/Allow) are guarded by a confirmation modal requiring a reason >= 10 chars.
*   [ ] Applying a block displays a 30s undo toast.
*   [ ] No Python f-strings are used in logging calls.
*   [ ] All tests pass with zero warnings or errors.

---

## 10. Common Mistakes

*   **Chart.js canvas sizing:** Failing to wrap the `<canvas>` element in a relative container with a fixed height. This causes the chart to grow infinitely on window resize.
*   **Alpine.js x-data scope:** Defining the confirmation modal variables inside a nested child element rather than at the root modal container level.
*   **Lazy logger formatting:** Using f-strings inside logger calls instead of lazy parameters. Always write `logger.info("IP detail fetched for %s", ip)` rather than `logger.info(f"IP detail fetched for {ip}")`.
