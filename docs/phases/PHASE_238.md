---
phase: 238
title: Accessibility Hardening & Infrastructure Documentation
status: PROPOSED
size: MEDIUM
created: 2026-06-12
audience: [developer, operator, secops]
dependencies: [231, 237]
---

# Accessibility Hardening & Infrastructure Documentation

> **Before you touch a line of code**, read `docs/phases/PHASE_231.md`.
> Every design decision in this phase is cited by number from that document.
> If you disagree with a decision, raise it in a PR comment — do not silently
> implement a different approach.

---

## 1. Plain-English Goal

When this phase is complete, our security console will be accessible to all security operators, and our critical container privileges will be fully threat-modeled:

1.  **Triple-Enforced Status Indicators:** We will stop relying solely on green/yellow/red color dots for status. Status cards will use distinct colors, unique geometric shapes, and clear text labels (e.g. "● OK", "▲ WARN", "✖ CRIT"). This guarantees usability for operators with red-green color blindness.
2.  **Keyboard Navigable UI:** Focus rings will appear on all navigation links and interactive controls when tabbed through, allowing mouse-less operations.
3.  **Screen-Reader Support:** Dynamic polling regions (like the health cards and live feed) will use ARIA live regions so screen readers announce changes without interrupting the operator's current context.
4.  **Ambient Light Adaptability:** A clean, CSS-based Light Mode will activate automatically if the operator's OS is configured for light mode, preventing eye strain in bright room environments.
5.  **cAdvisor Threat Model Documented:** We will publish a threat model for cAdvisor detailing the security trade-offs of mounting the host filesystem with read-only root privileges.
6.  **Grafana Security Hardening:** Hardening flags (HSTS, secure cookie flags) will be activated for Grafana dashboard instances.
7.  **HAProxy TCP Mode Guard:** A CI lint assertion will be added to prevent accidental modification of HAProxy from TCP mode to HTTP mode (which breaks raw JA4 client hello packet captures).

---

## 2. Background: Why Each Problem Matters

### 2.1 WCAG 2.1 AA Compliance
The Web Content Accessibility Guidelines (WCAG) 2.1 AA is the industry standard for web application accessibility. It requires that information must be perceivable, operable, understandable, and robust.

### 2.2 The Reality of Deuteranopia (Red-Green Color Blindness)
Approximately 8% of men and 0.5% of women have deuteranopia (red-green color blindness). If a dashboard conveys a critical failure using only a red circle, and a nominal state using a green circle, these two states look identical to a color-blind operator.
*   **The Rule:** Color must never be the sole visual means of conveying information, indicating an action, prompting a response, or distinguishing a visual element. We must combine color, shape, and text.

### 2.3 ARIA Live Regions on Polling Components
An ARIA live region (`aria-live="polite"`) tells the browser that content inside this element will update dynamically. Without it, a screen reader is unaware of updates to the live feed or health cards. Using `polite` ensures updates are queued and read when the user is idle, rather than using `assertive` which cuts off their reading mid-word.

### 2.4 Light Mode in High-Ambient Light Environments
While dark modes are popular in SOCs, in high-ambient light environments (like an outdoor field setup or a bright room with window glare), dark screens suffer from high reflection, causing severe eye strain. Supporting `prefers-color-scheme` allows the browser to automatically adapt to the user's physical context.

### 2.5 cAdvisor Privilege Threat Modeling
To gather container metrics, cAdvisor mounts the host root directory `/` as `/rootfs:ro` and requests permissions like `SYS_PTRACE`. This means if the cAdvisor container is compromised, the attacker gains read access to the host's entire filesystem. We must document this blast radius and maintain a formal threat model detailing our mitigations (such as isolating cAdvisor in an internal bridge network and dropping unused Linux capabilities).

---

## 3. Prerequisites

*   `axe-core` CLI is required to run accessibility scans:
    ```bash
    npm install -g axe-cli
    ```
*   Verify your local node/npm version:
    ```bash
    node -v && npm -v
    ```

---

## 4. Step A: Shape+Color+Text Status Indicators

We will update the health cards to render status using shape, color, and text labels.

### 4.1 Shape Mapping Table

| Status | Old Indicator | New Shape Indicator | Color Token | Accessible Label |
| :--- | :--- | :--- | :--- | :--- |
| **OK** | Green Dot | `●` (Circle) | `#10b981` | OK |
| **WARN** | Amber Dot | `▲` (Triangle) | `#f59e0b` | WARN |
| **CRIT** | Red Dot | `✖` (X-Mark) | `#ef4444` | CRIT / DOWN |

### 4.2 File to modify: `management/templates/partials/health_cards.html`

Update the card layout:

```diff
   {% for card in cards %}
   {% set status_dot = {
-    "ok":    "bg-[#10b981] shadow-[0_0_8px_rgba(16,185,129,0.6)]",
-    "warn":  "bg-[#f59e0b] shadow-[0_0_8px_rgba(245,158,11,0.6)]",
-    "error": "bg-[#ef4444] shadow-[0_0_8px_rgba(239,68,68,0.6)]",
+    "ok":    "text-[#10b981] font-bold",
+    "warn":  "text-[#f59e0b] font-bold",
+    "error": "text-[#ef4444] font-bold",
   }.get(card.status, "bg-[#475569]") %}
 
   <div class="relative glass-card p-4 flex flex-col justify-between min-h-[110px]">
     <!-- Status Indicator (Shape + Color + Text) -->
-    <span class="absolute top-4 right-4 w-2 h-2 rounded-full {{ status_dot }}
-                 {% if card.status == 'error' %}animate-ping{% endif %}"></span>
+    <span class="absolute top-4 right-4 text-xs {{ status_dot }}" aria-label="Status: {{ card.status }}">
+      {% if card.status == 'ok' %}● OK{% elif card.status == 'warn' %}▲ WARN{% else %}✖ CRIT{% endif %}
+    </span>
```

---

## 5. Step B: Focus Rings on Nav Links

To ensure keyboard-only navigation, we must add visible focus indicators to all interactive elements.

### File to modify: `management/templates/base.html`

Add focus ring styles to navigation elements:

```diff
-        <a href="/" class="text-sm font-medium text-slate-300 hover:text-white transition">Dashboard</a>
+        <a href="/" class="text-sm font-medium text-slate-300 hover:text-white transition focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-slate-900 rounded px-2 py-1">Dashboard</a>
```

---

## 6. Step C: ARIA Live Regions

We will declare the health cards and live feed container as polite live regions.

### File to modify: `management/templates/dashboard.html`

```diff
-  <div id="health-cards-container" hx-get="/api/v1/partials/health-cards" hx-trigger="load, every 10s">
+  <div id="health-cards-container" hx-get="/api/v1/partials/health-cards" hx-trigger="load, every 10s" aria-live="polite" aria-atomic="true">
```

---

## 7. Step D: CSS Light Mode

We will append CSS media queries to support systems running a light theme.

### File to modify: `management/static/custom.css`

Append the following light mode variables at the bottom of the file:

```css
@media (prefers-color-scheme: light) {
    :root {
        --bg-primary: #f8fafc;
        --bg-secondary: #ffffff;
        --text-primary: #0f172a;
        --text-secondary: #475569;
        --glass-bg: rgba(255, 255, 255, 0.7);
        --glass-border: rgba(15, 23, 42, 0.08);
    }
    
    body {
        background-color: var(--bg-primary);
        color: var(--text-primary);
    }
    
    .glass-card {
        background: var(--glass-bg);
        border: 1px solid var(--glass-border);
        box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.05);
    }
    
    .text-slate-300 {
        color: #334155;
    }
}
```

---

## 8. Step E: Grafana Security Flags

We will secure cookie transmissions by forcing them over HTTPS.

### File to modify: `deploy/docker/docker-compose.monitoring.yml`

```diff
   grafana:
     image: grafana/grafana:11.1.0
     environment:
       - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD:-admin}
+      - GF_SECURITY_COOKIE_SECURE=true
+      - GF_SECURITY_ALLOW_EMBEDDING=false
```

---

## 9. Step F: cAdvisor Threat Model Document

Create a new file `/home/sean/LLM/JA4proxy2/docs/security/CONTAINER_THREAT_MODEL.md` (Decision 9):

```markdown
# Container Threat Model: cAdvisor Privilege Footprint

## 1. Description
cAdvisor (Container Advisor) provides resource usage and performance characteristics of running containers. To query this information, it requires read-only host-level access to the cgroup system and filesystem mounts.

## 2. Capabilities Requested
*   `volume: /:/rootfs:ro`
*   `cap_add: [SYS_PTRACE]`
*   `security_opt: [label=disable]` (on SELinux hosts)

## 3. Blast Radius Analysis
If the cAdvisor container is compromised (e.g. through a remote code execution vulnerability in its metrics collector API):
*   **Host Read Access:** The attacker can read all files on the host root directory (including `/etc/shadow`, credentials, and private keys) via the `/rootfs` mount.
*   **Process Inspection:** The `SYS_PTRACE` capability allows the attacker to trace processes running on the host, potentially extracting secrets from environment memory.

## 4. Current Mitigations
1.  **Network Isolation:** cAdvisor binds its port `8080` only to the internal bridge network `ja4proxy-mgmt`. It is not accessible from the public network.
2.  **No Host Network:** cAdvisor does not run with `network_mode: host`.
3.  **Read-Only Root Mount:** The host filesystem is mounted strictly read-only (`:ro`). The attacker cannot write to host files or overwrite configuration.

## 5. Residual Risk Rationale
The operational value of real-time memory exhaustion monitoring (to prevent silent Redis evictions) outweighs the residual risk, provided cAdvisor remains isolated behind the internal management network with no direct routing from the external interface.
```

---

## 10. Step G: HAProxy TCP Mode CI Assertion

We will write a python script to assert that HAProxy configuration is in TCP mode, preventing proxy bypass.

### File to create: `tests/unit/test_haproxy_mode.py`

```python
import os

def test_haproxy_config_mode():
    config_path = "/home/sean/LLM/JA4proxy2/deploy/monitoring/haproxy/haproxy.cfg"
    if not os.path.exists(config_path):
        # check alternative paths
        config_path = "/home/sean/LLM/JA4proxy2/deploy/docker/haproxy.cfg"
        if not os.path.exists(config_path):
            return # skip if no haproxy config in this env

    with open(config_path, "r") as f:
        content = f.read()

    assert "mode tcp" in content, "HAProxy config must use 'mode tcp' to preserve raw ClientHello packet captures."
    assert "mode http" not in content, "HAProxy must not decrypt TLS traffic at load balancer stage."
```

---

## 11. Running the axe-core scan

To verify that the console is accessible:
```bash
axe http://localhost:8090/
```
Ensure the scan output lists **0 violations**.

---

## 12. Tests to Run

Execute the test suites:
```bash
pytest tests/unit/test_haproxy_mode.py
```

---

## 13. Common Mistakes

*   **Forgetting focus-rings outline removal:** Writing `focus:ring-2` without `focus:outline-none` can cause the browser's default black outline to collide with the Tailwind ring color.
*   **Enabling cookie_secure over HTTP:** Setting `GF_SECURITY_COOKIE_SECURE=true` while accessing Grafana over standard HTTP will cause browser cookie drops and login failure loop.
*   **f-strings in tests:** Ensure standard print or logger syntax in test logs.
