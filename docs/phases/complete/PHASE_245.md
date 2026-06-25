---
phase: 245
title: "Front Door — Time-to-Protection & Operator UX"
size: LARGE
created: 2026-06-25
audience: [operator, developer, product]
---

# Phase 245: Front Door — Time-to-Protection & Operator UX

## What is this?

A critical usability review found that JA4proxy is well-engineered software with
a terrible front door. The proxy, management UI, ops tooling, and test coverage
are all production-grade — but a SecOps engineer under active attack cannot get
from "I found this project" to "it's protecting my server" in under an hour.

This phase addresses the gap between **what the product is** (an A-grade proxy)
and **what the onboarding experience delivers** (a D+ first-deploy story).

### The Core Problem

The project is documented and structured for someone *evaluating* — not someone
*drowning*. Every friction point compounds under pressure:

- No single `docker compose up` in the repo root
- Config requires understanding 1000+ lines of YAML before the first connection
- PROXY protocol is on by default (`proxy_protocol: true` in `proxy.yml`),
  meaning the proxy expects an upstream LB — but no guidance exists for
  environments without one
- The management UI exists but isn't surfaced in the quickstart
- The ±10 dial limit prevents rapid escalation during an active attack
- The best incident response tooling (`ja4-admin.sh`, emergency Ansible
  playbooks) is buried in docs most operators will never find

### What's NOT Wrong

This phase is not about code quality, architecture, or security posture — those
are strong. It's about the gap between the product's capability and the
operator's ability to access that capability under pressure.

---

## Review Findings (Detailed)

### Finding 1: No Minimal Deploy Path

**Current state:** The POC quickstart requires Docker Compose, 9 open ports, a
`.env` file with `BACKEND_HOST`, and launches 12 containers. The `make init`
wizard (`ja4p init`) collects ~20 configuration values — backend host, topology,
TLS certs, firewall backend, fail2ban/crowdsec, threat intel API keys, backup
encryption, monitoring stack, log forwarding — before a single connection is
proxied. It does support `--non-interactive` mode, but that still requires
pre-populating all fields.

**Impact:** An engineer under attack who needs "proxy in front of my server in
5 minutes" gets a 12-container orchestration exercise. They'll reach for
iptables instead.

**Evidence:**
- `docs/operations/POC_QUICKSTART.md` lists 9 port prerequisites
- `internal/wizard/wizard.go:Answers` struct has ~30 fields including optional
  integrations (Firewall, Fail2Ban, CrowdSec, LogForwarding, BackupEncrypt)
- No `docker-compose.yml` exists in the repo root
- 7 Compose variants exist in `deploy/docker/` with no documented "just use
  this one" recommendation

### Finding 2: PROXY Protocol Default Creates an Unstated Prerequisite

**Current state:** The architecture diagram shows HAProxy as the entry point.
`config/proxy.yml` ships with `proxy_protocol: true` — meaning the proxy
*expects* PROXY protocol headers from an upstream TCP load balancer. The
capability to disable this exists (it's a config toggle), but:
- The default assumes an upstream LB is present
- There is no documented path for direct-to-internet, nginx, or cloud LB
  deployments
- No guidance on what `proxy_protocol: false` means for client IP extraction

**Impact:** An engineer with any setup other than HAProxy hits a wall at deploy
time. The proxy parses raw TLS ClientHello bytes as PROXY protocol and
immediately rejects the connection — a confusing failure mode with no actionable
error message.

**Evidence:**
- `config/proxy.yml` line 37: `proxy_protocol: true`
- Architecture diagram in README.md shows `HAProxy (LB)` as a fixed component
- No documentation for alternative load balancers or direct mode

### Finding 3: Config Overwhelm Before First Value

**Current state:** `config/proxy.yml` is 1066 lines. The minimum viable
configuration (bind address, backend host, Redis URL) is buried among signal
module weights, threat intel API keys, tarpit settings, and enrichment
configuration.

**Impact:** A new operator doesn't know which 5 lines matter and which 1000+
are optional. They either read the whole file (an hour they don't have) or
guess wrong and get a startup error.

**Prerequisite:** The Go proxy must have compiled-in defaults for every config
key not present in the minimal file. This likely already works (the config
loader in `internal/config/loader.go` uses struct defaults), but must be
verified before shipping `proxy.minimal.yml`.

### Finding 4: Emergency Escalation Friction

**Current state:** The dial endpoint (`PUT /api/v1/dial`) enforces a ±10 max
change per request (`_MAX_DIAL_CHANGE = 10` in `management/api/routes/dial.py`).
Going from dial=0 (monitor) to dial=75 (active blocking) requires 8 sequential
API calls. Phase 237 added `revert_after_hours` and a dial revert poller, but
this auto-revert is only accessible through the existing ±10-limited endpoint —
there is no way to jump to a high dial value in a single action.

**Impact:** During an active DDoS, the operator's most urgent action (start
blocking) is artificially throttled. The safety feature designed for steady-state
becomes a liability during an emergency.

**What exists (Phase 237):**
- `DialUpdateRequest.revert_after_hours` — schedules auto-revert via
  `config:dial_override` Redis key
- `run_dial_revert_poller` — polls every ~10s and reverts when TTL expires
- `DELETE /api/v1/dial/revert` — cancels a scheduled revert

**What's missing:**
- A bypass for the ±10 step limit during emergencies
- Presets for common emergency postures
- CLI integration (`ja4-admin.sh` has no dial command)
- UI surface for emergency escalation

### Finding 5: Incident Response Tooling is Buried

**Current state:** The project has excellent incident response tooling:
- `scripts/ja4-admin.sh` — CLI for status, top fingerprints, block/unblock
  (has `usage()` and categorised help, but no dial commands)
- `docs/operations/INCIDENT_RESPONSE.md` — step-by-step "Under Attack RIGHT NOW"
- Emergency Ansible playbooks (`emergency-ban-cidr.yml`, `temp-whitelist-ip.yml`)
- 40+ runbooks covering specific alert scenarios

**Impact:** None of this is discoverable from the README or the quickstart. A
new operator will never find `ja4-admin.sh` during an incident. The incident
response runbook — the single most valuable operator document — is linked from
the operations guide, not from the top of the README.

### Finding 6: Management UI Gaps Under Pressure

**Current state:** The management UI is functional and well-designed for
steady-state operations. Gaps that matter during an incident:

| Gap | Impact |
|-----|--------|
| No inline JA4 blocking from the live feed | Operator sees attacking fingerprint, must navigate to Lists page to block it |
| No search/filter on bans page | 500+ active bans = scrolling, not searching |
| No geographic attack view in UI | CLI has `geoip-report` but UI doesn't surface country patterns |
| No mobile responsiveness | Fixed 200px sidebar; 3am phone check is unusable |
| API docs disabled in production | Can't discover endpoints during an incident |
| Dashboard partials poll (10-30s), don't push | Health/threat widgets are stale during fast-moving attacks |

### Finding 7: GeoIP Data Acquisition Friction

**Current state:** The proxy needs MaxMind or IP2Location data for GeoIP/ASN
enrichment (`internal/security/asn_classifier.go` opens `.mmdb` via
`geoip2.Open()`). This requires a license key, a download step, and a volume
mount. The quickstart mentions `make update-geoip` but doesn't explain the
license key requirement or what happens when it's missing.

**Impact:** The proxy starts without GeoIP data and silently degrades — no
country blocking, no ASN enrichment. The operator doesn't know this is
happening until they try to block by country and it doesn't work.

---

## Steps Forward

The fixes below are ordered by **impact on time-to-protection**, not by
implementation complexity.

### Dependency Graph

Most steps are independent, but three have ordering constraints:

```
Step 3 (minimal config) ──must exist before──▶ Step 2 (root compose)
Step 4 (emergency API)  ──must exist before──▶ Step 6.3 (emergency UI button)
Step 4 (emergency API)  ──must exist before──▶ Step 5 (CLI dial commands)
```

All other steps can be executed in any order.

### Step 1: "Under Attack" README Banner + Emergency Quickstart

**Effort:** Small (1-2 hours)
**Impact:** Highest — this is the first thing a desperate operator sees

Add to the very top of `README.md`, above the badges:

```markdown
> **Under attack right now?** → [Emergency deployment](docs/operations/EMERGENCY_DEPLOY.md)
> (3 commands, 2 containers, <5 minutes)
>
> **Already running?** → [Incident response](docs/operations/INCIDENT_RESPONSE.md)
> (block a fingerprint in 30 seconds)
```

Create `docs/operations/EMERGENCY_DEPLOY.md` — a ruthlessly minimal document:
- 3 prerequisites (Docker, a backend URL, 2 ports)
- 3 commands (clone, configure, start)
- What you'll see when it's working
- "Now what?" links to the full quickstart and incident response

### Step 2: Root-Level Minimal Docker Compose

**Effort:** Medium (half day)
**Impact:** Very high — eliminates the biggest deployment blocker
**Depends on:** Step 3 (the proxy must start with minimal config)

Create `docker-compose.yml` in the repo root with exactly 2 services:
- `ja4proxy` — the Go binary, pre-built image from GHCR
- `redis` — stock Redis with a generated password

Sane defaults:
- Listens on `:8443` on the host (no root required), forwards to
  `BACKEND_HOST:443` (single env var)
- Dial starts at 0 (monitor mode) — no config file needed
- PROXY protocol OFF by default (direct mode)
- No HAProxy, no monitoring stack, no analytics
- No TLS configuration needed — the proxy does TLS passthrough, forwarding the
  client's encrypted connection to the backend unchanged

The full multi-container stack stays in the existing named Compose files
under `deploy/docker/`.

Acceptance: `BACKEND_HOST=mysite.com docker compose up` proxies TLS traffic
within 60 seconds of clone.

**Port note:** `:8443` avoids requiring `root` or `CAP_NET_BIND_SERVICE`. The
emergency deploy doc (Step 1) should mention that operators wanting `:443` can
either adjust the port mapping or use `setcap cap_net_bind_service=+ep`.

### Step 3: Minimal Config + Direct Mode

**Effort:** Medium (half day)
**Impact:** High — removes the config wall and HAProxy prerequisite

Create `config/proxy.minimal.yml`:
```yaml
# JA4proxy — minimal config (all you need to start)
listen: ":8443"
backend: "your-server.com:443"
redis: "redis://localhost:6379"
dial: 0  # monitor mode — scores everything, blocks nothing
proxy_protocol: false  # direct mode — no upstream LB required
```

**Implementation prerequisite:** Verify that `internal/config/loader.go`
provides sane compiled-in defaults for every key absent from the minimal file.
The config loader uses Go struct defaults and YAML unmarshalling — this likely
works, but must be tested. Key defaults to verify:
- Signal module weights (should default to production values)
- Tarpit/rate-limit settings (should default to disabled or conservative)
- TLS settings (passthrough mode should be the zero-value default)
- Health/metrics endpoints (should bind to defaults)

Document "direct mode" (no upstream LB, no PROXY protocol) as the default
deployment model. HAProxy integration becomes an "advanced" topic, not a
prerequisite.

### Step 4: Emergency Dial Override

**Effort:** Small-Medium (2-4 hours)
**Impact:** High — removes escalation friction during active incidents

**Build on Phase 237's infrastructure.** The auto-revert poller and
`config:dial_override` key already exist. The emergency override is a new
endpoint that bypasses the ±10 step limit while reusing the existing revert
mechanism.

Add to the Management API:
- `POST /api/v1/dial/emergency` — accepts a target dial value with no ±10
  limit. Requires `admin` role + MFA. Logs prominently. Writes
  `config:dial_override` with a default TTL of 1 hour (reuses Phase 237's
  revert poller).
- Presets as query parameters or body fields: `preset=block_known_bad` (50),
  `preset=active_defense` (75), `preset=lockdown` (90).

Add to the Management UI:
- An "Emergency Mode" button on the dashboard (red, prominent)
- Presets: "Block Known Bad" (dial 50), "Active Defense" (dial 75),
  "Lockdown" (dial 90)
- Confirmation dialog: "This will immediately start blocking connections
  scoring above X. Auto-reverts in 1 hour unless you confirm."

Keep the ±10 limit for the normal dial widget — it's good design for
steady-state. The emergency path is a separate, audited, auto-reverting
mechanism.

**Safety:** Confirmation extends the TTL but does not make it permanent. A
confirmed emergency dial resets the TTL to another interval (default 1 hour,
max 4 hours). The operator must re-confirm periodically. This prevents
"confirmed and forgotten" scenarios where an aggressive dial outlives the
incident.

### Step 5: Surface `ja4-admin.sh` as a First-Class CLI

**Effort:** Medium (1 day)
**Impact:** High — the CLI is the real incident response hero
**Depends on:** Step 4 (for dial commands)

- Document `ja4-admin.sh` in the README quickstart section
- Add a `make admin` target that runs the script
- Add dial commands to the existing `ja4-admin.sh`:
  - `dial` — show current value
  - `dial N` — set via the ±10 API (may require multiple calls)
  - `dial N --emergency --ttl 1h` — call the emergency endpoint
- Verify the existing `help`/`usage` output is comprehensive and categorised:
  - **Triage:** `status`, `top N`, `geoip-report`
  - **Block:** `block-ip`, `block-ja4`, `block-country`, `block-cidr`
  - **Unblock:** `unblock-ip`, `unblock-ja4`
  - **Dial:** `dial [value]`, `dial --emergency N --ttl T`
- Consider aliasing it as `ja4ctl` for discoverability

### Step 6: Management UI — Incident Response Shortcuts

**Effort:** Medium (1-2 days)
**Impact:** High — makes the UI useful during active attacks

These are the incident-critical UI improvements. Each is an independent work
item (except 6.3 which depends on Step 4):

1. **Inline block from live feed.** Each row in the SSE connection feed gets a
   "Block" button (JA4 fingerprint) and "Ban" button (source IP). One click,
   with confirmation toast showing undo.

2. **Search/filter on bans page.** Text filter over IP, reason, and expiry.
   Basic — not a search engine, just a text match.

3. **Emergency mode dashboard button.** Red button, presets, auto-revert. (See
   Step 4 — this is the UI surface for that API. Cannot ship before Step 4.)

### Step 7: Management UI — Polish (Lower Priority)

**Effort:** Large (2-3 days)
**Impact:** Medium — improves steady-state usability but not urgent

These items improve the UI but are not incident-critical. They can be deferred
or done in a later phase without affecting time-to-protection:

1. **Mobile-responsive sidebar.** Hamburger menu on narrow viewports. The
   dashboard and bans pages are the priority — an operator checking from their
   phone at 3am needs these two.

2. **Geographic attack visualisation.** Country-level breakdown of blocked
   connections in the last N minutes. One-click "block country" from the list.
   (A full heatmap is disproportionate effort — a sorted table with counts is
   sufficient and faster to build.)

### Step 8: `ja4p init --minimal` Fast Path

**Effort:** Small (2-3 hours)
**Impact:** High — removes the wizard wall for emergency deployments

The wizard already supports `--non-interactive` mode but requires pre-populating
all `Answers` fields. Add a `--minimal` flag that:
- Prompts for only `BACKEND_HOST` (or accepts it as an argument)
- Generates a `.env` with `BACKEND_HOST` and a random `REDIS_PASSWORD`
- Uses safe defaults for everything else (dial=0, proxy_protocol=false,
  no threat intel, no firewall integration, no backup encryption)
- Prints: "Minimal setup complete. Run `docker compose up` to start."
- Links to `ja4p init` (full wizard) when the operator has time

Expose as both `ja4p init --minimal` and `make init-minimal` for discoverability.

### Step 9: Deployment Guides for Non-HAProxy Environments

**Effort:** Medium (1 day of documentation)
**Impact:** Medium-High — removes the unstated prerequisite for many operators

Create `docs/operations/DEPLOYMENT_MODES.md`:

- **Direct mode** (default): JA4proxy listens on :8443, clients connect
  directly. `proxy_protocol: false`. Client IP from the TCP connection.
- **Behind HAProxy**: TCP mode, PROXY protocol v2. Include a minimal
  HAProxy config snippet.
- **Behind nginx**: `stream` block with `proxy_protocol on`. Include config.
- **Behind AWS NLB/ALB**: Target group settings, PROXY protocol v2 enablement.
- **Behind Cloudflare**: Spectrum or direct origin, with caveats about
  Cloudflare's own TLS termination.

Each mode is a 10-line section with a config snippet, the corresponding
`proxy.yml` settings, and a "verify it works" curl command.

### Step 10: Graceful GeoIP Degradation + Setup Guidance

**Effort:** Small (2-3 hours)
**Impact:** Low-Medium — removes a silent failure mode

- On startup without GeoIP data: log a WARN with a direct link to the
  setup instructions (not just "GeoIP not found"). The Go proxy already
  opens `.mmdb` files in `internal/security/asn_classifier.go` — add an
  actionable log message at the point where `geoip2.Open()` fails.
- Add a health check subsystem for GeoIP that reports "degraded" in
  `/health/deep`
- Document the MaxMind/IP2Location license key requirement in the quickstart
  with a direct signup link
- Consider bundling IP2Location LITE (CC-BY-SA) as a default fallback so
  basic country blocking works out of the box

---

## Acceptance Criteria

### Deployment & Config
- [ ] README.md has a prominent "Under Attack?" banner linking to emergency docs
- [ ] `docs/operations/EMERGENCY_DEPLOY.md` exists with 3-command deploy path
- [ ] `docker-compose.yml` in repo root starts proxy + Redis with a single env var
- [ ] Root compose uses `:8443` (no root required); documents `:443` as an option
- [ ] `config/proxy.minimal.yml` exists and the proxy starts with only it
- [ ] Proxy can run in direct mode (`proxy_protocol: false`) as the default
- [ ] `ja4p init --minimal` / `make init-minimal` generates a working `.env`
  with only `BACKEND_HOST` + random Redis password, skipping all optional setup

### Emergency Escalation
- [ ] `POST /api/v1/dial/emergency` bypasses ±10 limit, requires admin + MFA
- [ ] Emergency endpoint reuses Phase 237's `config:dial_override` and revert poller
- [ ] Emergency dial auto-reverts after configurable TTL (default 1h, max 4h)
- [ ] Confirmation extends (not removes) the TTL
- [ ] Presets available: "Block Known Bad" (50), "Active Defense" (75), "Lockdown" (90)

### CLI & Discoverability
- [ ] `ja4-admin.sh` has `dial`, `dial N`, `dial N --emergency` commands
- [ ] `ja4-admin.sh` is documented in README quickstart section
- [ ] `make admin` target runs the script

### Management UI
- [ ] Live feed has inline block (JA4) and ban (IP) buttons
- [ ] Bans page has search/filter
- [ ] Emergency mode button on dashboard with presets and auto-revert

### Documentation
- [ ] `docs/operations/DEPLOYMENT_MODES.md` covers direct, HAProxy, nginx,
  AWS NLB, and Cloudflare — each with a config snippet and verify command
- [ ] GeoIP missing produces an actionable WARN with setup link, not silent degradation
- [ ] `/health/deep` reports GeoIP subsystem as "degraded" when data is missing

### End-to-End
- [ ] `git clone` → `docker compose up` → proxying traffic in under 5 minutes
  on a clean machine (no root, no config file editing)

## Out of Scope

- Rewriting the proxy core, config system, or management UI framework
- Changing the scoring algorithm or signal modules
- New security features or signal sources
- Performance optimisation
- Mobile app (responsive web is sufficient)
- WebSocket push for dashboard partials (polling is acceptable for this phase)

## Dependencies

None. All steps are additive — they layer onto the existing codebase without
modifying core proxy behaviour. Step 4 builds on Phase 237's dial revert
infrastructure.

## Risk

Low. This phase adds documentation, configuration shortcuts, and UI polish.
The proxy's core behaviour, security model, and fail-open design are unchanged.
The emergency dial override is the only behavioural change and it auto-reverts
by design.

**Risk: Minimal config breaks on missing defaults.** If the Go config loader
doesn't supply sane defaults for every absent key, a 5-line `proxy.minimal.yml`
will cause a startup panic. Step 3 must include verification of compiled-in
defaults before shipping. Mitigated by the fact that Go struct fields zero-value
to safe types, and the existing loader already handles missing YAML sections.
