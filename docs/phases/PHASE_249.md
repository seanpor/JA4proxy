<!--
title: "Phase 249 — Datacenter ASN One-Click Block"
audience: developer
last_reviewed: 2026-06-25
phase: 249
-->

# Phase 249 — Datacenter ASN One-Click Block

## Problem Statement

The scenario: a website owner's contact form is being hammered. They look at the
Under Attack page (Phase 247). Every single IP in the top-20 attacker list shows
"AWS", "GCP", "DigitalOcean", or "Hetzner" in the ASN column.

This is not unusual. Studies of bot traffic consistently show that 80–95% of
automated form spam originates from cloud and hosting provider IP ranges — not
from residential ISPs or mobile networks. Real users browse from home internet,
mobile data, and office networks. Bots run from rented servers.

JA4proxy already knows which ASNs belong to datacenters. The file
`config/asn_datacenter_list.yml` already contains hundreds of ASNs for every
major cloud provider. The Go proxy already reads this file and sets `is_datacenter`
on the risk signal. But today there is no way to say "treat all datacenter traffic
differently" without editing config files and restarting.

This phase adds a single toggle in the management UI: **Datacenter Action**. The
owner chooses one of three policies for all datacenter-origin traffic:
- `score` (default): datacenter IPs are scored normally. No special treatment.
- `tarpit`: all datacenter connections are tarpitted automatically.
- `block`: all datacenter connections are blocked automatically.

This is the highest-leverage single action available to a site owner under bot
attack, and it should take one click.

## Goals

1. The owner can change the datacenter action policy from the management UI with
   one click, no config file editing, no restart.
2. The proxy applies the new policy within seconds of the UI change (hot-reload
   via Redis pub/sub — the same mechanism already used for other config changes).
3. Per-ASN exceptions let the owner protect specific legitimate services. For
   example: Cloudflare's IPs are technically "datacenter" but are used by legitimate
   visitors proxied through Cloudflare. The owner can say "block all datacenters
   except Cloudflare."
4. The default policy is `score` — deploying JA4proxy changes nothing about how
   datacenter traffic is handled until the owner explicitly enables a stricter policy.

## What Already Exists (Do Not Rebuild)

This phase has the most existing infrastructure of the three. Read these before
writing code:

- **`config/asn_datacenter_list.yml`**: already lists hundreds of ASNs across all
  major cloud providers (AWS, GCP, Azure, DigitalOcean, Vultr, Linode/Akamai,
  Hetzner, OVH, Leaseweb, etc.). This file is the source of truth for datacenter
  classification. Do not duplicate it.

- **`internal/config/loader.go`**: already has `DatacenterASNs []uint` and
  `DatacenterOrgs []string` in the `ASNConfig` struct. Already loads
  `config/asn_datacenter_list.yml`.

- **`internal/security/risk_scorer.go`**: already produces a `datacenter` signal
  when the connecting IP's ASN is in the datacenter list. This signal contributes
  to the risk score.

- **`internal/security/pipeline.go`**: already has a `[BYPASS CHECKS]` section.
  The datacenter policy check will run in the **signal collection phase** — immediately
  after ASN classification (line ~560), not in the bypass section. This is because
  bypass checks (line ~468) run before ASN data is available. The check still causes
  an early return (datacenter IPs never reach the scorer), but the code lives in
  signal collection where ASN info exists.

- **`management/api/routes/config_ops.py`**: already handles hot-reloadable config
  updates. Follow this pattern for the new `datacenter_action` endpoint.

- **`internal/redis/pubsub.go`**: already handles the pub/sub channel for config
  reload. Use the existing `config:reload` channel.

## Sub-phases

### 249.1 — Config Schema & Go Loader
**Size:** SMALL | **Dependencies:** none

Add `datacenter_policy` section to `config/proxy.yml`:

```yaml
# Datacenter ASN policy (Phase 249)
# Controls how traffic from known cloud/hosting provider IP ranges is handled.
# Datacenter IPs are identified by the ASN list in config/asn_datacenter_list.yml.
#
# Why this matters: the majority of automated bot traffic originates from
# datacenter IPs, not residential or mobile IPs. Blocking all datacenter traffic
# is an effective defence against form spam, credential stuffing, and scraping.
#
# Caution: some legitimate traffic comes via datacenters (Cloudflare-proxied
# visitors, corporate VPNs, CI systems). Use 'tarpit' first to observe impact
# before switching to 'block'. Add exceptions for ASNs you want to allow.
datacenter_policy:
  action: score           # score | tarpit | block
                          # score: normal scoring, no special treatment (default)
                          # tarpit: all datacenter connections are tarpitted
                          # block: all datacenter connections are blocked (RST)

  # ASNs to exempt from the datacenter_policy action.
  # These ASNs are scored normally even when action is 'tarpit' or 'block'.
  # Common exceptions: Cloudflare (13335), Fastly (54113), Akamai (20940)
  exceptions:
    - 13335   # Cloudflare — real visitors may be proxied through Cloudflare
    - 54113   # Fastly
    - 20940   # Akamai

  # Whether to log datacenter connections that are tarpitted/blocked.
  # Set false if log volume is overwhelming during an attack.
  log_actions: true
```

Add to `internal/config/loader.go`:
```go
type DatacenterPolicyConfig struct {
    Action     string `yaml:"action"`      // "score" | "tarpit" | "block"
    Exceptions []uint `yaml:"exceptions"`  // ASN numbers exempt from the policy
    LogActions bool   `yaml:"log_actions"`
}
```

Validate `Action` on load: if not one of `score`, `tarpit`, `block`, log a warning
and default to `score`. This prevents a typo from accidentally enabling blocking.

**Acceptance criteria:**
- [ ] `config/proxy.yml` has `datacenter_policy` section with all fields and comments
- [ ] `internal/config/loader.go` loads `DatacenterPolicyConfig`
- [ ] Unknown `action` values default to `"score"` with a warning log
- [ ] Default exceptions include Cloudflare (13335), Fastly (54113), Akamai (20940)

### 249.2 — Pipeline Enforcement (Go)
**Size:** MEDIUM | **Dependencies:** 249.1

Add datacenter policy enforcement to `internal/security/pipeline.go`.

The enforcement happens in the **signal collection phase**, after ASN classification
has run but before the action decider. It cannot go in the bypass check section
because the ASN classifier (which tells us whether an IP is a datacenter) runs
during signal collection at line ~560 of `processInternal()`, **after** the bypass
checks at line ~468. The bypass checks have no ASN data yet.

**Add `IsDatacenter` to `ASNClassifier`:**

`ASNClassifier` already has the datacenter list in memory. Add a method:
```go
// IsDatacenter returns true if clientIP belongs to a known datacenter ASN,
// and returns the ASN number. Fast O(1) trie lookup — no Redis call.
func (a *ASNClassifier) IsDatacenter(clientIP string) (bool, uint32)
```

**Placement in the pipeline (in `processInternal()`):**

```go
// ASN classification (existing)
startASN := time.Now()
signals = append(signals, p.asnClassifier.Classify(conn.ClientIP)...)
p.measure("asn", startASN)

// [NEW] Datacenter policy enforcement — runs immediately after ASN classification.
if p.cfg.DatacenterPolicy.Action != "score" && p.cfg.DatacenterPolicy.Action != "" {
    if isDatacenter, asn := p.asnClassifier.IsDatacenter(conn.ClientIP); isDatacenter {
        // Check if this ASN is in the exception list.
        excepted := false
        for _, exASN := range p.cfg.DatacenterPolicy.Exceptions {
            if uint32(exASN) == asn {
                excepted = true
                break
            }
        }
        if !excepted {
            if p.cfg.DatacenterPolicy.LogActions {
                p.log.WithFields(logrus.Fields{
                    "event.action":      "datacenter_policy",
                    "client.ip":         conn.ClientIP,
                    "network.asn":       asn,
                    "ja4proxy.policy.action": p.cfg.DatacenterPolicy.Action,
                }).Warn("datacenter policy applied")
            }
            metrics.DatacenterPolicyActionsTotal.WithLabelValues(
                p.cfg.DatacenterPolicy.Action, "false").Inc()
            // Check whether PipelineResult has a BypassReason field.
            // Search pipeline.go for "BypassReason" — if other bypass paths
            // already use it, it exists. If not, add: BypassReason string
            // to the PipelineResult struct.
            return &PipelineResult{
                Action:       p.cfg.DatacenterPolicy.Action,
                Score:        100,
                BypassReason: "datacenter_policy",
            }
        }
    }
}
```

**Hot-reload:**

Do NOT use `sync/atomic.Value` — `Pipeline` already uses `p.mu sync.RWMutex`
with `ReplaceConfig()` to swap config atomically. Adding a separate atomic value
for just the datacenter policy creates two inconsistent synchronisation mechanisms.

Instead, add `DatacenterPolicy DatacenterPolicyConfig` to `PipelineConfig` and
update it through the existing `ReplaceConfig()` path. The reload flow is:
`config:reload` pub/sub → `proxy.reload()` in `main.go` → rebuild `PipelineConfig`
→ call `p.pipeline.ReplaceConfig(pipelineCfg)`. `ReplaceConfig` holds `p.mu.Lock()`
so the swap is safe.

On reload in `main.go`, after reading the file config, also check Redis for a
policy override:
```go
if raw := p.redis.GetString(ctx, "config:datacenter_policy"); raw != "" {
    var override DatacenterPolicyConfig
    if err := json.Unmarshal([]byte(raw), &override); err == nil {
        pipelineCfg.DatacenterPolicy = override
    }
}
```

Add `DatacenterPolicy DatacenterPolicyConfig` to `PipelineConfig` in `loader.go`.

**Observability:**

Add Prometheus counter to `internal/metrics/metrics.go`:
`ja4proxy_datacenter_policy_actions_total{action="tarpit|block", exception="false"}`

**Acceptance criteria:**
- [ ] `IsDatacenter(ip string) (bool, uint32)` added to `ASNClassifier`
- [ ] When `action: score`, the new code block is skipped entirely
- [ ] When `action: tarpit`, datacenter IPs return `Action: "tarpit"` before scoring
- [ ] When `action: block`, datacenter IPs return `Action: "block"` before scoring
- [ ] Exception ASNs bypass the policy (excepted=true, continue normally)
- [ ] h2/h1 ALPN traffic is handled by the allow-bypass before this code runs
- [ ] Config reload via `ReplaceConfig()` (not atomic.Value)
- [ ] `main.go` reload path reads `config:datacenter_policy` from Redis and overrides
- [ ] Prometheus counter incremented on each tarpit/block action
- [ ] ECS log line emitted when `log_actions: true`, suppressed when `false`
- [ ] Existing pipeline tests still pass

### 249.3 — Management API
**Size:** MEDIUM | **Dependencies:** 249.1

Add `GET` and `PUT` endpoints for the datacenter policy. Follow the pattern of
`management/api/routes/config_ops.py` for the implementation structure.

**`GET /api/v1/datacenter-policy`**

Returns the current policy. **Read from Redis first** (`config:datacenter_policy`
key); if absent, return the file-config defaults. This ensures GET reflects the
live state (which may have been changed by a previous PUT) rather than the
on-disk defaults. Also resolve exception ASN numbers to names from
`config/asn_datacenter_list.yml`.

```json
{
  "action": "score",
  "exceptions": [
    {"asn": 13335, "name": "Cloudflare"},
    {"asn": 54113, "name": "Fastly"},
    {"asn": 20940, "name": "Akamai"}
  ],
  "log_actions": true,
  "asn_list_count": 847,    // how many ASNs are in the datacenter list
  "asn_list_updated": "2024-01-01"
}
```

**`PUT /api/v1/datacenter-policy`**

Updates the policy and publishes a config reload event.

```json
// Request body:
{
  "action": "tarpit",        // required: "score" | "tarpit" | "block"
  "exceptions": [13335, 54113, 20940],  // optional, replaces current list
  "log_actions": true        // optional
}
```

```json
// Response 200:
{
  "action": "tarpit",
  "exceptions": [...],
  "log_actions": true,
  "updated_at": "2026-06-25T02:00:00Z"
}
```

The endpoint:
1. Validates `action` is one of the three allowed values.
2. Writes the new config to Redis: `config:datacenter_policy` → JSON.
3. Publishes to `config:reload` so the Go proxy picks it up immediately.
4. Writes an audit log entry.

**Exact publish call** (copy this pattern from `management/api/routes/config_ops.py`):
```python
from ..pubsub_signing import build_envelope
from datetime import datetime, timezone

payload = build_envelope("config:reload", datetime.now(timezone.utc).isoformat())
await redis.publish("config:reload", payload)
```
The `build_envelope` function signs the message with an HMAC when a secret is
configured. Always use it — do not publish a raw string to `config:reload`.

**Where is the config stored?**

`config:datacenter_policy` is a Redis String holding a JSON object. It has no TTL
(permanent until changed). On config reload, `main.go` reads this key and overrides
the file-based `DatacenterPolicy` field (see 249.2 for the exact code).

New Redis key: `config:datacenter_policy` — String (JSON), no TTL.

**Auth:** `Depends(require_role(Role.auditor))` for GET,
`Depends(require_role(Role.admin))` + `Depends(require_mfa_verified)` for PUT.
(`require_role` enforces a minimum role — all roles at or above auditor can GET.)

**File to create:** `management/api/routes/datacenter_policy.py`

**Acceptance criteria:**
- [ ] GET returns current policy with exception names resolved
- [ ] GET shows `asn_list_count` (count of entries in the YAML file)
- [ ] PUT validates `action` — returns 422 for invalid values
- [ ] PUT writes `config:datacenter_policy` to Redis
- [ ] PUT publishes to `config:reload`
- [ ] PUT writes audit log entry with before/after values
- [ ] Router registered in `management/api/main.py`
- [ ] Unit tests covering all validation cases

### 249.4 — Settings Page UI
**Size:** MEDIUM | **Dependencies:** 249.3

Add a **Datacenter Policy** card to the settings or security policy page in the
management UI. This is the owner-facing surface for the one-click change.

**Card layout:**

```
┌─────────────────────────────────────────────────────────────────┐
│  DATACENTER TRAFFIC POLICY                                      │
│                                                                 │
│  Most bot traffic originates from cloud provider IP ranges.     │
│  847 datacenter ASNs are monitored.                             │
│                                                                 │
│  Current action:  [● Score ○ Tarpit ○ Block]                   │
│                    (default)                                    │
│                                                                 │
│  ⚠ Tarpit: Slows down bots. Safe to try first.                 │
│  ✕ Block: Stops all datacenter connections. Also blocks some   │
│    legitimate users (VPN users, Cloudflare-proxied visitors).  │
│                                                                 │
│  ── Exceptions ──────────────────────────────────────────────  │
│  These ASNs are always scored normally:                         │
│  13335 Cloudflare  [Remove]                                     │
│  54113 Fastly      [Remove]                                     │
│  20940 Akamai      [Remove]                                     │
│                                                                 │
│  [Add exception: ASN number _______]  [Add]                    │
└─────────────────────────────────────────────────────────────────┘
```

**Implementation notes:**

> **There is no existing security policy page.** Create `management/templates/security_policy.html`
> from scratch. Use this minimal scaffold (copy the structure from any existing page,
> e.g. `management/templates/bans.html`):
> ```html
> {% extends "base.html" %}
> {% block title %}Security Policy{% endblock %}
> {% block page_title %}Security Policy{% endblock %}
> {% block content %}
> <!-- Datacenter policy card goes here -->
> {% endblock %}
> ```
> Add a page route in `management/api/routes/pages.py` following the same pattern
> as the other `@router.get("/bans")` etc. routes in that file.
> Add a sidebar link in `management/templates/base.html` (search for
> `href="/bans"` to find the right place).

The radio buttons use HTMX to **PUT** the change on selection — use `hx-put`,
not `hx-post`. The endpoint is `PUT /api/v1/datacenter-policy`. Show a
confirmation for switching to `block`:

```html
<!-- Score radio — no confirmation -->
<input type="radio" name="action" value="score"
  hx-put="/api/v1/datacenter-policy"
  hx-vals='{"action": "score"}'
  hx-target="#policy-feedback">

<!-- Tarpit radio — no confirmation, safe to try -->
<input type="radio" name="action" value="tarpit"
  hx-put="/api/v1/datacenter-policy"
  hx-vals='{"action": "tarpit"}'
  hx-target="#policy-feedback">

<!-- Block radio — confirmation required -->
<input type="radio" name="action" value="block"
  hx-put="/api/v1/datacenter-policy"
  hx-confirm="Block ALL datacenter traffic? This may affect legitimate users on VPNs or proxied through Cloudflare. You can revert this instantly."
  hx-vals='{"action": "block"}'
  hx-target="#policy-feedback">
```

Note: `hx-vals` sends a JSON body on the HTMX request. `hx-target="#policy-feedback"`
swaps in a success/error message. Add `<div id="policy-feedback"></div>` below
the radios to receive it.

Exception management is a simple list with inline Remove buttons and an "Add"
form at the bottom. Each Remove button calls `PUT /api/v1/datacenter-policy` with
the updated exceptions list (without the removed ASN). The Add form validates that
the input is a positive integer before submitting.

**Files to create:**
- `management/templates/security_policy.html` — new page (scaffold above)
- Add route to `management/api/routes/pages.py`
- Add sidebar link to `management/templates/base.html`
- `management/api/routes/datacenter_policy.py` — the API (from 249.3)

**Acceptance criteria:**
- [ ] Datacenter Policy card visible in UI
- [ ] Three-way radio (Score/Tarpit/Block) reflects current policy from API
- [ ] Selecting Tarpit applies immediately via HTMX, no page refresh
- [ ] Selecting Block shows confirmation dialog before applying
- [ ] Exception list shows ASN number and resolved name
- [ ] Remove button removes an exception immediately
- [ ] Add exception validates ASN is a positive integer < 4294967295
- [ ] Unknown ASN numbers are accepted (may be in the list without a name)
- [ ] Page renders without 500 error when not under attack

### 249.5 — Attack Mode Integration
**Size:** SMALL | **Dependencies:** 247.1, 249.3

> ⚠ **Sequential implementation note:** This sub-phase modifies `attack_mode.py`
> created in Phase 247.1. Implement phases 247, 248, and 249 **in order**.

When Attack Mode is activated (Phase 247), also switch the datacenter policy to
`tarpit` for the duration of attack mode.

Modify `POST /api/v1/attack-mode` in `attack_mode.py` to:
1. Read and save the current datacenter policy:
   ```python
   current_policy = await redis.get("config:datacenter_policy") or '{"action":"score"}'
   await redis.set("attack_mode:datacenter_policy_before", current_policy,
                   ex=revert_after_hours * 3600)
   ```
2. Write the tarpit policy and publish a reload:
   ```python
   await redis.set("config:datacenter_policy", '{"action":"tarpit"}')
   payload = build_envelope("config:reload", datetime.now(timezone.utc).isoformat())
   await redis.publish("config:reload", payload)
   ```

Modify `DELETE /api/v1/attack-mode` to restore the previous policy with a reload:
```python
before = await redis.get("attack_mode:datacenter_policy_before")
if before:
    await redis.set("config:datacenter_policy", before)
    payload = build_envelope("config:reload", datetime.now(timezone.utc).isoformat())
    await redis.publish("config:reload", payload)
    await redis.delete("attack_mode:datacenter_policy_before")
```

Also modify `GET /api/v1/attack-mode` to include the current datacenter action in
its response. Add to the `attack_mode.py` GET handler:
```python
dc_raw = await redis.get("config:datacenter_policy") or '{"action":"score"}'
dc_policy = json.loads(dc_raw)
# Include in response:
"datacenter_action": dc_policy.get("action", "score")
```

The auto-revert (when the TTL expires) does NOT automatically restore the
datacenter policy — the owner has to either cancel attack mode explicitly or
change the policy manually. This is intentional: the TTL expiry happens silently,
and silently reverting the datacenter policy could re-expose the site to attack
traffic without the owner noticing.

Document this limitation clearly in the UI when Attack Mode auto-revert is
approaching:

```
Attack Mode reverts in 45 minutes.
⚠ Datacenter policy will NOT auto-revert. If you want to restore it,
  go to Security Policy and change it back to "Score".
```

**Acceptance criteria:**
- [ ] `POST /api/v1/attack-mode` sets datacenter policy to `tarpit`
- [ ] Previous policy saved to `attack_mode:datacenter_policy_before`
- [ ] `DELETE /api/v1/attack-mode` restores previous datacenter policy
- [ ] Attack Mode countdown UI shows the "will not auto-revert" warning for datacenter policy
- [ ] `GET /api/v1/attack-mode` response includes `datacenter_action: "tarpit"` when active

### 249.6 — Tests
**Size:** MEDIUM | **Dependencies:** 249.1–249.5

**`internal/security/pipeline_datacenter_test.go`:**
- `action: score` → datacenter IP flows to scorer
- `action: tarpit` → datacenter IP is tarpitted, scorer never called
- `action: block` → datacenter IP is blocked, scorer never called
- Exception ASN → scored normally even when action is `block`
- h2/h1 ALPN traffic → always allowed regardless of policy
- Config swap via `ReplaceConfig()` → no race conditions (run with `-race` flag)
- `log_actions: false` → no log line emitted

**`management/tests/test_datacenter_policy.py`:**
- GET returns current policy
- PUT with valid action → 200, policy updated in Redis
- PUT with invalid action → 422
- PUT publishes to `config:reload`
- Exception add → appears in GET response
- Exception remove → absent from GET response
- Redis unavailable on GET → returns 200 with default `{action: "score"}` (fail open, not 500)
- Redis unavailable on PUT → returns 503 with clear error message

**`management/tests/test_pages.py`** (extend):
- Security policy page renders → 200 + HTML + "Datacenter" string
- Page without auth → < 500

**`management/tests/test_container_config.py`** (extend):
- `datacenter_policy` config section present in docker-compose environment (or defaults)

## Out of Scope

- Per-country blocking (separate phase — different UI surface)
- Residential proxy detection (separate phase — harder problem)
- Automatic ASN list updates from external feeds (separate phase)
- Tor exit node handling (already handled by existing Tor detection)
- IPv6 prefix blocking for datacenter ranges (the existing IP→ASN lookup handles
  this; we don't need separate IPv6 logic)

## Architecture Notes for Junior Engineers

**Why doesn't this use the risk scorer?**

The risk scorer takes all signals and produces a 0–100 score. The dial then
determines whether that score leads to a block. So at dial=0, a score of 95
still results in "allow". If datacenter blocking went through the scorer, it
would be silenced when the owner is in monitor mode.

This is different. When the owner has explicitly said "block all datacenter
traffic", they mean it — regardless of dial. This check is placed in the signal
collection phase (after ASN classification) rather than in the bypass check section
— because ASN data is not available at bypass time. But functionally it behaves like
a bypass: datacenter IPs exit the pipeline early and never reach the scorer or action
decider. It is an unconditional early-return policy, not a score contribution.

**Why are Cloudflare, Fastly, and Akamai in the default exceptions?**

Cloudflare (ASN 13335) operates a reverse proxy used by many websites. A visitor
to site A that is proxied through Cloudflare will appear to JA4proxy as coming
from a Cloudflare IP. Blocking Cloudflare IPs would block all visitors to any
Cloudflare-fronted origin. This is a very common false-positive trap.

Similarly, Fastly and Akamai are CDNs that forward legitimate user traffic. Their
IPs are "datacenter" in the technical sense but carry real user traffic.

The owner can always remove these exceptions if they are certain Cloudflare traffic
is not legitimate for their site. But the default-safe choice is to exempt them.

**Why tarpit instead of block for Attack Mode?**

When Attack Mode activates, we do not know which datacenter IPs are bots and which
are legitimate (a developer testing from a cloud machine, a Cloudflare proxy not
in the exceptions list, a legitimate CI system). Tarpit degrades the bot experience
dramatically (each connection takes much longer) while still allowing legitimate
datacenter traffic to eventually succeed. Block would hard-fail those connections.
The owner can escalate to block from the Security Policy page if tarpit is
insufficient.

## Redis Keys Introduced

| Key | Type | TTL | Purpose |
|-----|------|-----|---------|
| `config:datacenter_policy` | String (JSON) | none | Current datacenter policy (overrides file config) |
| `attack_mode:datacenter_policy_before` | String (JSON) | `revert_hours * 3600` | Saved policy before attack mode activation |

## CHANGELOG Fragment

Add `docs/fragments/phase-249-datacenter-policy.md`:

```markdown
### Added
- Datacenter ASN policy: one-click tarpit or block all cloud/hosting provider
  traffic from the Security Policy page — no config file editing, no restart
- Hot-reloadable policy change applies within seconds via Redis pub/sub
- Default exceptions for Cloudflare, Fastly, and Akamai (common CDN proxies)
- Attack Mode (Phase 247) now also activates datacenter tarpitting automatically
- 847 datacenter ASNs tracked across AWS, GCP, Azure, DigitalOcean, Vultr,
  Linode, Hetzner, OVH, and more
```
