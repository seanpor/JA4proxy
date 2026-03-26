# Phase 13 — Management UI

## Status: COMPLETE — implemented 2026-03-11 (v13.1.0)

---

## 1. Goal

A single, secure web interface for the secops admin. Manages every aspect of the
running proxy — blocking dial, IP/CIDR bans, JA4 fingerprints, policy bypasses,
integration health, live connection feed, analytics, TAP sensor status, and
intelligence export configuration — without touching YAML files or running Redis
commands. All mutations go via Redis + pub/sub so every proxy instance picks them
up immediately without restart.

---

## 2. Architecture

```
Browser (secops admin)
    │
    │  HTTPS on port 8090 (TLS terminated at nginx or directly at FastAPI)
    ▼
┌─────────────────────────────────────────────────────┐
│  Management Server (FastAPI, Python)                 │
│                                                     │
│  Static serving  ──── /app/*  ────  React SPA       │
│  REST API        ──── /api/v1/*                     │
│  SSE stream      ──── /api/v1/events                │
│  TAXII endpoints ──── /taxii2/*  (Phase 20)         │
│  EDL endpoints   ──── /export/edl/* (Phase 20)      │
│  Health endpoint ──── /health                       │
└──────────────────────────────┬──────────────────────┘
                               │  asyncio Redis client
                               ▼
                         Redis (shared)
                         pub/sub: ja4proxy:invalidate
                         streams: ja4proxy:events
                         keys:    ban:*, ja4:*, fp:*, management:*
```

### 2.1 Backend: FastAPI

- **Language:** Python 3.11+
- **Framework:** FastAPI with `uvicorn` (single worker; multiprocessing via `gunicorn` for production)
- **Redis client:** `redis-py` async (`redis.asyncio`) — same client factory as `src/config/loader.py`
- **SSE:** `sse-starlette` library — streams Redis Stream `ja4proxy:events` to browser clients
- **Port:** 8090 (configurable). Listen on `127.0.0.1:8090` by default; nginx or a load balancer handles TLS termination.
- **Process:** Runs as a separate process from the proxy (`management/server.py`). Shares Redis but no in-process state with the proxy.
- **File layout:**
  ```
  management/
    server.py          # FastAPI app factory, startup/shutdown lifecycle
    auth.py            # API key validation, rate limiting
    routers/
      events.py        # SSE live feed
      bans.py          # IP/CIDR ban management
      fingerprints.py  # JA4 blacklist/whitelist/candidates
      dial.py          # Dial control
      policy.py        # Security policy bypass toggles
      config.py        # Threshold sliders, feature toggles, GeoIP
      integrations.py  # AbuseIPDB, Spamhaus, RDAP, analytics node
      health.py        # Proxy instance health, Redis health
      tap.py           # TAP sensor status, fingerprint browser (Phase 20)
      export.py        # EDL config, F5/PA/Kafka/Syslog/TAXII/MISP status (Phase 20)
      audit.py         # Audit log viewer
    models.py          # Pydantic request/response models
    redis_helpers.py   # Redis query helpers used by multiple routers
  ```

### 2.2 Frontend: React SPA

- **Framework:** React 18 + TypeScript
- **Bundler:** Vite (fast HMR in dev; optimised production bundle)
- **Styling:** Tailwind CSS + shadcn/ui component library
- **State:** React Query (TanStack Query) for server state (API calls, cache invalidation)
- **Routing:** React Router v6
- **Charts:** Recharts (risk score histogram, trend lines, action breakdown)
- **SSE client:** Native `EventSource` API with automatic reconnection
- **Location:** `management/frontend/` — built artefacts output to `management/static/`
- **Served by:** FastAPI `StaticFiles` mount at `/app`; SPA fallback route catches all unknown paths

### 2.3 Authentication and Session Model

**Single API key** (`UI_API_KEY` environment variable). No username/password. Key must be
set before starting; proxy exits with FATAL if absent:
```
FATAL | management | event=startup_abort | reason=UI_API_KEY_not_set
```

**How auth works:**
1. Browser sends `Authorization: Bearer <key>` on every API request.
2. FastAPI dependency `require_api_key()` checks header; returns 401 if missing or wrong.
3. The React app stores the key in `sessionStorage` (not `localStorage` — cleared on tab close).
4. All SSE requests include the key as a query param (`?key=...`) because `EventSource` does
   not support custom headers. The server validates the query param on SSE connections.

**Rate limiting:** 10 failed auth attempts per IP per minute → 429 with `Retry-After` header.
The IP rate limiter uses Redis (`mgmt:ratelimit:{ip}` with 60s TTL and INCR).
After 100 failures from one IP in 1 hour → emit WARN log and Prometheus alert.

**RBAC:** Phase 13 has a single `admin` role. Future phases may add `read_only` role.
For now, every authenticated request has full write access. Document this limitation.

### 2.4 HTTPS / TLS

The management server should always run behind TLS. Two supported configurations:

**Option A — nginx reverse proxy (recommended for production):**
```nginx
server {
    listen 443 ssl;
    server_name mgmt.ja4proxy.internal;
    ssl_certificate     /etc/ssl/ja4proxy/mgmt.crt;
    ssl_certificate_key /etc/ssl/ja4proxy/mgmt.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://127.0.0.1:8090;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;   # SSE connections are long-lived
        proxy_buffering off;        # Required for SSE
    }
}
```

**Option B — FastAPI with direct TLS** (acceptable for internal tools):
```yaml
management_ui:
  tls:
    enabled: true
    cert: "/etc/ja4proxy/mgmt.crt"
    key:  "/etc/ja4proxy/mgmt.key"
```

**Development** — HTTP on localhost is acceptable for dev; the frontend Vite dev server
proxies API calls to `http://localhost:8090`.

### 2.5 Security Headers

FastAPI middleware adds the following to every response:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

No inline scripts. All JS is bundled by Vite. CSP violations are reported to
`/api/v1/csp-report` (logged, not stored).

---

## 3. API Endpoint Catalog

All routes require `Authorization: Bearer <key>` header or `?key=<key>` (SSE only).
All request/response bodies are JSON. All timestamps are ISO 8601 UTC.
API version prefix: `/api/v1`.

### 3.1 Live Feed

```
GET  /api/v1/events
     Query: filter_action=allow|flag|rate_limit|tarpit|block|ban
            filter_country=<ISO2>
            filter_asn_type=residential|datacenter|tor|vpn
     Response: text/event-stream (SSE)
     Event types:
       data: {"type":"connection","conn_id":"...","ip":"...","country":"GB",
              "asn_type":"datacenter","ja4":"t13d...","score":67,"action":"flag",
              "signals":[{"source":"asn","score":30,"reason":"datacenter"}],
              "timestamp":"2026-03-10T14:23:00Z"}
       data: {"type":"ban","ip":"1.2.3.4","score":87,"reason":"...","timestamp":"..."}
       data: {"type":"heartbeat","timestamp":"..."}  (every 15s to keep connection alive)

GET  /api/v1/events/recent
     Response: last 100 connection events from Redis Stream
     {"events": [...]}
```

### 3.2 IP & CIDR Ban Management

```
GET  /api/v1/bans
     Query: page=1&per_page=50&q=1.2.3&source=manual|rdap|spamhaus
     Response: {"bans": [{"ip":"1.2.3.4","score":87,"reason":"...","expires_at":"...","source":"manual"}],
                "total": 142, "page": 1}

POST /api/v1/bans
     Body: {"ip": "1.2.3.4", "reason": "manual block", "ttl_s": 3600}
     Response: {"ip":"1.2.3.4","expires_at":"..."}
     Side effect: writes ban:{ip}, publishes ban event on ja4proxy:invalidate

DELETE /api/v1/bans/{ip}
     Response: 204 No Content
     Side effect: DEL ban:{ip}, publishes ban_release on ja4proxy:invalidate

GET  /api/v1/cidrs
     Query: page=1&per_page=50&source=manual|rdap_expansion|spamhaus
     Response: {"cidrs": [{"cidr":"1.2.3.0/24","source":"rdap_expansion","added_at":"...","reason":"..."}]}

POST /api/v1/cidrs
     Body: {"cidr": "1.2.3.0/24", "reason": "manual block"}
     Response: {"cidr":"1.2.3.0/24","added_at":"..."}

DELETE /api/v1/cidrs/{cidr_urlencoded}
     Response: 204
```

### 3.3 JA4 Fingerprint Management

```
GET  /api/v1/fingerprints/blacklist
     Response: {"fingerprints": ["t13d...", ...], "count": 42}

POST /api/v1/fingerprints/blacklist
     Body: {"fingerprint": "t13d1516h2_...", "reason": "scanner tool"}
     Side effect: SADD ja4:blacklist, publish ja4_blacklist_add

DELETE /api/v1/fingerprints/blacklist/{fingerprint}
     Side effect: SREM ja4:blacklist, publish ja4_blacklist_remove

GET  /api/v1/fingerprints/whitelist
     (same structure as blacklist)

POST /api/v1/fingerprints/whitelist
DELETE /api/v1/fingerprints/whitelist/{fingerprint}

GET  /api/v1/fingerprints/candidates
     Query: sort=count|first_seen|last_seen  page=1&per_page=20
     Response: {"candidates": [{"fingerprint":"t13d...","count":847,
                "first_seen":"...","last_seen":"...","sample_ips":["1.2.3.4"]}]}

POST /api/v1/fingerprints/candidates/{fingerprint}/approve
     Body: {"reason": "confirmed scanner"}
     Side effect: adds to blacklist, removes from candidates, pub/sub

POST /api/v1/fingerprints/candidates/{fingerprint}/dismiss
     Side effect: removes from candidate queue only
```

### 3.4 Dial Control

```
GET  /api/v1/dial
     Response: {"dial": 45, "blocking_acknowledged": true,
                "counterfactual": {"pct_blocked": 12.4, "sample_window_minutes": 60},
                "max_change_per_hour": 10}

PUT  /api/v1/dial
     Body: {"dial": 55, "reason": "increasing aggression after campaign confirmed"}
     Response: {"dial": 55, "previous": 45}
     Errors:
       422 if abs(new - current) > max_change_per_hour
       422 if blocking_acknowledged is false and new > 0
     Side effect: publishes dial_change on ja4proxy:invalidate

POST /api/v1/dial/acknowledge
     Body: {"acknowledged": true}
     Response: 200
     Side effect: sets blocking_acknowledged flag in Redis
```

### 3.5 Security Policy Bypasses

```
GET  /api/v1/policy/bypasses
     Response: {"bypasses": [
       {"name": "alpn_browser_bypass", "enabled": true,
        "description": "h2/h1 ALPN → ALLOW without scoring",
        "risk_if_disabled": "browser traffic will be scored; false positive risk elevated"},
       ...
     ]}

PUT  /api/v1/policy/bypasses/{bypass_name}
     Body: {"enabled": false, "reason": "investigating h2 API client traffic"}
     Response: {"bypass": "alpn_browser_bypass", "enabled": false}
     Side effect: config_reload pub/sub; writes management:policy_audit entry
     Requires confirmation dialog in UI (shows risk_if_disabled before applying)

GET  /api/v1/policy/audit
     Query: page=1&per_page=20
     Response: {"entries": [{"ts":"...","bypass":"...","old_value":true,"new_value":false,
                             "changed_by":"192.168.1.10","reason":"..."}]}
```

### 3.6 Configuration

```
GET  /api/v1/config/thresholds
     Response: {"thresholds": {"flag":20,"rate_limit":35,"tarpit":55,"block":70,"ban":85}}

PUT  /api/v1/config/thresholds
     Body: {"tarpit": 60}
     Side effect: publishes config update via ja4proxy:invalidate

GET  /api/v1/config/countries/blocklist
     Response: {"countries": ["CN","RU","KP"], "count": 3}

PUT  /api/v1/config/countries/blocklist
     Body: {"countries": ["CN","RU","KP","IR"]}

GET  /api/v1/config/features
     Response: {"features": {"beaconing_detection":true,"rdap_block_expansion":false,...}}

PUT  /api/v1/config/features/{feature}
     Body: {"enabled": true}

GET  /api/v1/config/history
     Response: {"changes": [{"ts":"...","key":"...","old":"...","new":"...","actor_ip":"..."}]}
     (last 20 config changes)
```

### 3.7 Integration Status

```
GET  /api/v1/integrations/abuseipdb
     Response: {"configured":true,"quota_used":4200,"quota_limit":10000,
                "quota_resets_at":"2026-03-11T00:00:00Z","last_lookup":"..."}

POST /api/v1/integrations/abuseipdb/test
     Response: {"status":"ok","latency_ms":142} or {"status":"error","message":"..."}

GET  /api/v1/integrations/spamhaus
     Response: {"drop_count":42891,"edrop_count":18203,"last_refresh":"...","next_refresh":"..."}

POST /api/v1/integrations/spamhaus/refresh
     Response: 202 Accepted (refresh happens asynchronously)

GET  /api/v1/integrations/rdap
     Response: {"queue_depth":3,"registries":{"ARIN":{"status":"ok","tokens":45},
                "RIPE":{"status":"ok","tokens":12},...},"expansions_today":4}

GET  /api/v1/integrations/analytics
     Response: {"status":"healthy","stream_lag_s":0.3,"campaigns_active":2,
                "last_event":"...","modules":{"beaconing":true,"slow_scan":true}}
```

### 3.8 TAP Sensor (Phase 20)

```
GET  /api/v1/tap/status
     Response: {"mode":"tap","interface":"eth1","link_up":true,
                "packets_captured_total":1284732,"packets_dropped_total":0,
                "ring_buffer_fill":0.03,"streams_active":4821,
                "fingerprints_extracted_today":142891}

GET  /api/v1/tap/fingerprints/ip/{ip}
     (see Phase 20 §8.3)

GET  /api/v1/tap/fingerprints/ja4/{fingerprint}
     (see Phase 20 §8.3)

GET  /api/v1/tap/export/status
     Response: {"edl":{"list_sizes":{"banned-ips":142},"last_rebuild":"..."},
                "f5":{"status":"healthy","last_sync":"...","data_group_sizes":{...}},
                "kafka":{"status":"healthy","messages_sent_today":84221},
                "syslog":{"status":"healthy"},...}
```

### 3.9 Audit Log

```
GET  /api/v1/audit
     Query: page=1&per_page=50&actor_ip=...&event_type=ban|unban|dial_change|...
     Response: {"entries":[{"ts":"...","event":"ban_added","actor_ip":"192.168.1.10",
                            "detail":{"ip":"1.2.3.4","reason":"manual"}}],
                "total":342}
```

### 3.10 Health

```
GET  /health
     (unauthenticated — used by load balancers and monitoring)
     Response: {"status":"healthy","mode":"passthrough",
                "redis":"healthy","proxy_instances":2,
                "management_ui":"healthy"}

GET  /api/v1/health/detail
     (authenticated)
     Response: full health breakdown as per Phase 20 §13.4 structure
```

---

## 4. Frontend — UI Sections

### 4.1 Live Connection Feed

Real-time stream of connection events from `ja4proxy:events` via SSE. Each row shows:
- IP address (clickable → IP detail drawer)
- Country flag + ISO code
- ASN type badge (residential/datacenter/tor/vpn — colour coded)
- JA4 fingerprint (abbreviated; hover shows full; clickable → JA4 detail drawer)
- Risk score bar (green 0–19, yellow 20–54, orange 55–69, red 70+)
- Action badge (allow/flag/rate_limit/tarpit/block/ban)
- Signal chips (abbreviated: "ASN+30", "TLS-10", etc.)
- Click-to-block button (shows confirmation modal with counterfactual before applying)

Filters (persist in URL): action, country, ASN type, min score, JA4 fragment.

Auto-pauses when scrolled up (user is reviewing history). Resumes on scroll-to-bottom.
Shows reconnection state when SSE drops; displays last-received timestamp.

**IP Detail Drawer** (slides in from right when IP clicked):
- Full connection detail: all signals, full JA4, JA4T, OS fingerprint (if TAP mode)
- Ban history: has this IP been banned before?
- AbuseIPDB score (if available)
- RDAP org info (if available)
- Action buttons: Ban now / Add to watchlist / Copy IP

### 4.2 Intelligence Dashboard

Summary view of aggregated analytics. Data sourced from analytics node (Phase 12) via
Redis keys read by the management API.

**Panels:**
- Risk score histogram (last hour vs last 24h, overlaid)
- Action breakdown pie (allow/flag/rate_limit/tarpit/block/ban counts)
- "At current dial, N% of today's traffic would be blocked" — shown prominently
- 7-day trend line (score distribution over time)
- Top 10 attacking ASNs (bar chart)
- Top 10 attacking countries (flag list with counts)
- Active campaigns detected (list: campaign ID, start time, IPs involved, peak score)
- Slow scan suspects (IPs with beaconing signal, sorted by certainty)

### 4.3 IP & CIDR Management

Two tabs: **IPs** and **CIDRs**.

IP tab:
- Searchable/filterable list of all `ban:{ip}` Redis keys
- Columns: IP, Score at ban, Reason, Source, Expires at, Actions (Release)
- Bulk release (checkbox select → release selected)
- Add ban form (IP input, reason, TTL selector)
- Release triggers pub/sub cross-instance eviction immediately

CIDR tab:
- List of all `ban_cidr:{cidr}` Redis keys
- Source column: `manual` | `rdap_expansion` | `spamhaus` (colour coded)
- Add CIDR form with confirmation (shows count of IPs in range)
- Remove CIDR with confirmation

Both tabs: pagination (50 per page), export to CSV button.

### 4.4 JA4 Fingerprint Management

Three sub-tabs: **Blacklist** | **Whitelist** | **Candidates**

Blacklist/Whitelist:
- List of fingerprints with add (text input + reason) and remove buttons
- Remove from whitelist shows warning: "This fingerprint will now be scored"

Candidates:
- Fingerprints auto-detected by the proxy as "common but unclassified"
- Sorted by connection count (descending) — high count = high priority for review
- Each row: fingerprint, count, first/last seen, sample IPs (3)
- Approve button → confirm modal (reason field, shows "will add to blacklist + notify all instances")
- Dismiss button → removes from candidate queue without blacklisting

### 4.5 Blocking Dial Control

Prominent slider widget (0–100).

**States:**
- If `blocking_acknowledged = false`: slider disabled; shows "Blocking not yet enabled. Click to acknowledge you understand the implications." Acknowledge button opens a modal with a plain-English explanation of blocking risks.
- If `blocking_acknowledged = true` and `dial = 0`: shows "Monitor mode — all traffic observed, none blocked."
- If `dial > 0`: shows the dial slider plus the counterfactual text.

**Counterfactual** (loaded from `/api/v1/dial` on page open and after each change):
```
"At dial = 55, 12.4% of the last hour's traffic would have been blocked
(1,284 connections). Click Apply to change."
```

**Change guard:** UI enforces `max_dial_change_per_hour` increment limit. If the user
tries to move the dial more than the limit, the slider snaps back and shows:
"Maximum change is +10 per hour. Current limit reached."

**Audit trail:** last 10 dial changes shown below the slider with timestamp, actor IP, old → new value, and reason.

### 4.6 Security Policy Bypasses

Grid of bypass cards, one per bypass condition. Each card shows:
- Bypass name (human-readable)
- Current state: ENABLED (green badge) or DISABLED (red badge with warning icon)
- Description of what the bypass does
- Effect if disabled (shown as amber warning text when currently enabled)
- Toggle button (opens confirmation modal showing risk before applying)

**Startup warnings section** at top of page: if any high-risk bypass is currently
disabled, show a persistent yellow banner listing them. This mirrors the proxy's
startup WARN log entries.

### 4.7 Integration Management

Cards for each integration:

**AbuseIPDB:**
- API key input (masked, show/hide toggle)
- Current quota: `4,200 / 10,000 used today (42%)`
- Progress bar (red when > 80%)
- Test Connection button → shows latency or error
- Cache stats: hit rate, entries

**Spamhaus DROP/EDROP:**
- Entry counts for each feed
- Last refresh timestamp + "Next refresh in Xh"
- Manual Refresh Now button

**RDAP:**
- Enrichment queue depth gauge
- Registry status table (ARIN/RIPE/APNIC/LACNIC/AFRINIC): status, token bucket level
- Known-bad org list editor (add/remove org name fragments)
- Block expansion config (enabled toggle, max prefix length)
- Expansion audit log (last 50 expansions: CIDR, trigger IP, org, timestamp)
- Expansions today counter vs hourly cap

**Analytics Node:**
- Status badge (healthy/degraded/down)
- Stream lag (seconds behind live)
- Active campaigns count
- Module toggles (beaconing, slow scan, campaign detection)

**TAP Sensor (Phase 20, shown if `mode: tap`):**
- Capture interface status (link up/down)
- Packets/s, drop rate, ring buffer fill gauge
- Active streams count
- Fingerprints extracted today (by type)
- Export status for each configured exporter (EDL, F5, Kafka, etc.)

### 4.8 Configuration Panel

**Threshold Sliders** — drag to adjust, shows preview of what changes. Apply publishes
via pub/sub without restart:
- Flag threshold (default 20)
- Rate limit threshold (default 35)
- Tarpit threshold (default 55)
- Block threshold (default 70)
- Ban threshold (default 85)

**Feature Toggles** — on/off switches with description:
- Beaconing detection
- RDAP block expansion
- AbuseIPDB enrichment
- FCrDNS enrichment
- Tor exit list sync

**GeoIP Country Blocklist** — tag input for ISO country codes.

**Change History** — last 20 config changes: timestamp, what changed, old → new, actor IP.

### 4.9 Health Panel

**Proxy Instances** (one card per instance, keyed by `ja4proxy:instance:{id}`):
- Instance ID, uptime, conn/s, current dial, error rate
- Redis: memory used, eviction rate, stream length (`ja4proxy:events`)
- Grafana iframe (embeds the main Grafana dashboard; configurable URL)

**Management Server** self-health:
- Uptime, request rate, error rate, active SSE subscribers
- Redis connection status

---

## 5. Developer Setup

### 5.1 Prerequisites

```bash
# Backend
python3.11+ with pip
redis-server running on localhost:6379 (password: changeme)

# Frontend
node 20+ (LTS)
npm 10+
```

### 5.2 Running in Development

```bash
# Terminal 1 — backend (hot-reload)
cd /path/to/ja4proxy
UI_API_KEY=dev-secret python3 -m uvicorn management.server:app \
  --reload --port 8090 --host 127.0.0.1

# Terminal 2 — frontend (Vite HMR)
cd management/frontend
npm install
npm run dev
# Serves on http://localhost:5173
# Proxies /api/* and /export/* to http://localhost:8090
```

Vite dev config (`management/frontend/vite.config.ts`):
```typescript
server: {
  proxy: {
    '/api': 'http://localhost:8090',
    '/export': 'http://localhost:8090',
    '/taxii2': 'http://localhost:8090',
    '/health': 'http://localhost:8090',
  }
}
```

### 5.3 Building for Production

```bash
cd management/frontend
npm run build
# Output: management/static/ (committed if small; gitignored and built in CI otherwise)

# FastAPI serves management/static/ at /app/*
# SPA fallback: all unmatched GET routes return index.html
```

In Docker: the frontend is built in a multi-stage Dockerfile:
```dockerfile
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY management/frontend/package*.json ./
RUN npm ci
COPY management/frontend/ .
RUN npm run build

FROM python:3.11-slim
COPY --from=frontend-builder /app/frontend/dist /app/management/static
# ... rest of Python image
```

### 5.4 Frontend Code Structure

```
management/frontend/
  src/
    api/           # React Query hooks wrapping fetch calls (api/bans.ts, api/events.ts, ...)
    components/    # shadcn/ui component wrappers + JA4proxy-specific components
    pages/         # One file per route (LiveFeed.tsx, BanManagement.tsx, ...)
    hooks/         # useSSE.ts, useDial.ts, usePolicyBypasses.ts
    store/         # Zustand stores for: auth (api key), ui preferences
    utils/         # formatScore.ts, countryFlag.ts, truncateJA4.ts
    types/         # TypeScript interfaces matching Pydantic models
  index.html
  vite.config.ts
  tailwind.config.ts
  tsconfig.json
  package.json
```

### 5.5 Adding a New API Endpoint

1. Add the route to the appropriate `management/routers/*.py` file.
2. Add Pydantic request/response models to `../../src/security/models.py`.
3. Add a React Query hook in `management/frontend/src/api/`.
4. Add unit test in `tests/unit/test_management_ui.py`.
5. Add the endpoint to the catalog in this doc (§3).

---

## 6. SecOps Operator Guide

### 6.1 What Requires the UI vs What Requires CLI/Redis

**UI is sufficient for:**
- Blocking/unbanning IPs and CIDRs
- Approving/dismissing JA4 candidates
- Adjusting the blocking dial
- Toggling bypass conditions
- Adjusting risk thresholds
- Managing AbuseIPDB/RDAP config
- Reading the audit log

**Requires CLI/Redis (not in UI):**
- Changing `redis_url`, `backend_host`, `listen_port` — requires proxy restart
- Bulk importing thousands of IPs — use `redis-cli SADD` or a script
- Rotating `UI_API_KEY` — requires process restart
- Changing `mode: passthrough|tap` — requires restart

### 6.2 Standard Operating Procedures

**Blocking a Campaign:**
1. Open Live Feed → filter by action=flag
2. Identify common signals (same ASN, same JA4 fingerprint)
3. Check JA4 Candidates tab — the fingerprint should be there
4. Click Approve → enter reason → confirm
5. All proxy instances receive the blacklist update within 100ms
6. Monitor Live Feed — connections with that JA4 should now show action=block

**Raising the Dial During an Attack:**
1. Go to Dial Control
2. Note the counterfactual ("at dial 60, 15% of traffic blocked")
3. Move slider up by ≤ 10 → confirm with reason
4. Monitor Live Feed and Health panel for false positives
5. If FP detected: immediately lower dial or release affected IPs

**Investigating a Specific IP:**
1. Click the IP in Live Feed → IP Detail Drawer opens
2. Review: AbuseIPDB score, RDAP org, OS fingerprint, all signals
3. Check "Ban history" tab — has this IP been released before?
4. Decision: Ban / Dismiss / Add note to audit log

**Emergency: Unban a Legitimate IP:**
1. IP & CIDR Management → search for the IP
2. Click Release → confirm
3. Pub/sub propagates to all proxy instances within 1 Redis round trip
4. Or from CLI: `make unblock-ip IP=1.2.3.4`

**Checking Policy Health:**
1. Security Policy panel → look for DISABLED badges (should all be ENABLED in normal operation)
2. If any bypass is disabled, the top of the page shows a yellow banner
3. Config History panel → check recent changes; unexpected changes = possible unauthorised access

### 6.3 Audit Log Reference

Every write action is logged to `management:audit_log` (Redis LIST, capped at 1000):

| Event type | Triggered by | Key fields |
|-----------|-------------|-----------|
| `ban_added` | IP ban form / click-to-block | `ip`, `reason`, `ttl_s` |
| `ban_released` | IP release button | `ip` |
| `cidr_blocked` | CIDR add form | `cidr`, `reason` |
| `cidr_released` | CIDR remove button | `cidr` |
| `ja4_blacklisted` | Candidate approve / manual add | `fingerprint`, `reason` |
| `ja4_whitelisted` | Whitelist add | `fingerprint`, `reason` |
| `ja4_candidate_dismissed` | Dismiss button | `fingerprint` |
| `dial_changed` | Dial slider | `old_dial`, `new_dial`, `reason` |
| `bypass_changed` | Policy toggle | `bypass`, `old_value`, `new_value`, `reason` |
| `threshold_changed` | Threshold slider | `threshold`, `old_value`, `new_value` |
| `country_list_changed` | Country list editor | `added`, `removed` |
| `feature_toggled` | Feature toggle | `feature`, `enabled` |
| `config_reloaded` | Manual or SIGHUP | — |

All entries include: `ts` (ISO 8601 UTC), `actor_ip` (management client IP), `event`.

### 6.4 Access Control and Key Rotation

`UI_API_KEY` is a shared secret. Rotation procedure:
1. Generate a new key: `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`
2. Update the environment variable (systemd unit file, Docker env, k8s secret)
3. Restart the management server process only (not the proxy)
4. Log into the UI with the new key; confirm old key is rejected

**If the key is compromised:**
1. Rotate immediately (above procedure)
2. Review `management:audit_log` for unauthorised actions since last key rotation
3. Check audit log for unusual bypass disables or dial changes

---

## 7. Performance

### 7.1 SSE Subscriber Scaling

Each SSE connection holds an open HTTP connection. FastAPI + uvicorn handles these as
async generators — no thread-per-connection.

**Limits:**
- Default: 10 concurrent SSE subscribers (configurable: `management_ui.max_sse_subscribers`)
- Beyond limit: 429 response with `Retry-After: 60`
- Each subscriber receives a copy of every event — avoid subscribing to the raw feed
  from automated systems; use Redis Stream directly

**Redis Stream reading:** The SSE handler uses `XREAD COUNT 100 BLOCK 1000` (1s timeout).
Each SSE handler coroutine issues one Redis command per second at most. 10 subscribers =
10 Redis commands/s, which is negligible.

### 7.2 Large List Pagination

IP bans, CIDR blocks, audit log — all paginated at 50 per page. Backend implementation:

IP bans: `SCAN 0 MATCH ban:* COUNT 100` iterated until complete, cached for 5s in
`LocalCache`. Never `KEYS ban:*` — that blocks Redis.

Audit log: `LRANGE management:audit_log 0 49` for page 1, `LRANGE 50 99` for page 2.
O(N) on the range, not the whole list.

### 7.3 Expensive Query Caching

| Query | Cache | TTL |
|-------|-------|-----|
| `SCAN` for all bans | `LocalCache.ban_list` | 5s |
| Counterfactual % (requires stream scan) | `LocalCache.counterfactual` | 60s |
| Analytics dashboard data | `LocalCache.analytics_summary` | 30s |
| Fingerprint candidate list | `LocalCache.fp_candidates` | 10s |

All cached with `LocalCache` (in-process, per management server process).

### 7.4 Rate Limiting

| Endpoint | Limit | Action on exceed |
|----------|-------|-----------------|
| Auth failures | 10 / IP / min | 429 |
| `POST /api/v1/bans` | 60 / min global | 429 |
| `POST /api/v1/dial` | 10 / hour (enforced) | 422 |
| `POST /api/v1/integrations/*/test` | 5 / min | 429 |
| `POST /api/v1/integrations/spamhaus/refresh` | 1 / hour | 429 |

---

## 8. Observability

### 8.1 Prometheus Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ja4proxy_mgmt_requests_total` | Counter | `method`, `endpoint`, `status` | HTTP requests to management API |
| `ja4proxy_mgmt_request_duration_ms` | Histogram | `endpoint` | Response time per endpoint |
| `ja4proxy_mgmt_sse_subscribers_active` | Gauge | — | Current SSE connections |
| `ja4proxy_mgmt_auth_failures_total` | Counter | — | 401 responses (brute force indicator) |
| `ja4proxy_mgmt_actions_total` | Counter | `action` | Admin actions (ban/unban/dial_change/etc.) |
| `ja4proxy_policy_changes_total` | Counter | `bypass` | Bypass state changes |
| `ja4proxy_mgmt_redis_errors_total` | Counter | `operation` | Redis errors during API requests |

### 8.2 AlertManager Rules

```yaml
- alert: ManagementUIAuthBruteForce
  expr: rate(ja4proxy_mgmt_auth_failures_total[5m]) > 2
  severity: warning
  annotations:
    summary: "Management UI receiving brute-force auth attempts"

- alert: ManagementUIDown
  expr: up{job="ja4proxy_management"} == 0
  severity: critical

- alert: PolicyBypassDisabled
  expr: ja4proxy_policy_changes_total{result="disabled"} > 0
  severity: warning
  annotations:
    summary: "A security policy bypass has been disabled — review is recommended"
```

### 8.3 Structured Logging

```
INFO  | management | event=server_start    | port=8090 | tls=true
INFO  | management | event=action_taken    | actor_ip=192.168.1.10 | action=ban_added    | target=1.2.3.4 | reason="scanner confirmed"
INFO  | management | event=action_taken    | actor_ip=192.168.1.10 | action=dial_changed | old=45 | new=55 | reason="campaign response"
WARN  | management | event=bypass_disabled | actor_ip=192.168.1.10 | bypass=spamhaus_bypass | effect="Spamhaus matches scored as signal(+80) instead of hard block"
WARN  | policy     | event=bypass_disabled | bypass=alpn_browser_bypass | effect="browser traffic will be scored; false positive risk elevated"
WARN  | management | event=auth_failure    | source_ip=10.0.0.5 | count=7 | window_s=60
ERROR | management | event=redis_error     | operation=ban_added | error=connection_refused | action=failed_with_503
INFO  | management | event=sse_connected   | subscriber_ip=192.168.1.10 | active_count=2
INFO  | management | event=sse_disconnected| subscriber_ip=192.168.1.10 | active_count=1
```

### 8.4 Grafana Dashboard

Dashboard file: `monitoring/grafana/dashboards/management_ui.json`

**Row 1 — Request Health:**
- `rate(ja4proxy_mgmt_requests_total[1m])` by status — stacked area
- `histogram_quantile(0.99, ja4proxy_mgmt_request_duration_ms)` — p99 latency
- `ja4proxy_mgmt_auth_failures_total` — red alert line

**Row 2 — Admin Activity:**
- `rate(ja4proxy_mgmt_actions_total[1h])` by action — bar chart
- `ja4proxy_policy_changes_total` — table (recent policy changes)
- `ja4proxy_mgmt_sse_subscribers_active` — gauge

---

## 9. Debugging Guide

### 9.1 Common Problems

**"UI shows stale data / actions don't take effect"**
- Check: is pub/sub working? `redis-cli SUBSCRIBE ja4proxy:invalidate` — do messages appear when you make UI changes?
- Check: is the proxy reading from the same Redis instance as the management UI?
- Check: `ja4proxy_mgmt_redis_errors_total` metric — non-zero means Redis commands are failing silently

**"SSE feed not updating / shows disconnected"**
- Check: nginx config has `proxy_buffering off` and long `proxy_read_timeout`
- Check: browser DevTools → Network → events endpoint — is the connection open?
- Check: `ja4proxy_mgmt_sse_subscribers_active` — does it increment when you open the feed?

**"401 on all requests despite correct API key"**
- Check: `UI_API_KEY` env var is set on the management server process (not just the proxy)
- Check: trailing whitespace in the key (copy-paste issue)
- Check: auth rate limiter — `ja4proxy_mgmt_auth_failures_total` may have triggered a lockout

**"Dial change rejected with 422"**
- Check: `blocking_acknowledged` is true
- Check: the change is within `max_dial_change_per_hour` (check current dial vs requested)
- Check: `management:dial_changes:{hour}` Redis key for current hour's change count

**"JA4 candidate approval not propagating"**
- Check: `ja4:blacklist` Redis set — is the fingerprint present after approval?
- Check: pub/sub — is `ja4_blacklist_add` message published? (`redis-cli SUBSCRIBE ja4proxy:invalidate`)
- Check: proxy logs for `event=blacklist_updated`

### 9.2 Useful Debug Commands

```bash
# Watch all management UI actions in real time
redis-cli -a "${REDIS_PASSWORD}" SUBSCRIBE ja4proxy:invalidate

# Read last 20 audit log entries
redis-cli -a "${REDIS_PASSWORD}" LRANGE management:audit_log 0 19

# Check current dial
redis-cli -a "${REDIS_PASSWORD}" GET dial:current

# Check SSE Redis Stream lag
redis-cli -a "${REDIS_PASSWORD}" XLEN ja4proxy:events

# Check active SSE subscribers (via management API)
curl -H "Authorization: Bearer ${UI_API_KEY}" http://localhost:8090/api/v1/health/detail | python3 -m json.tool

# Force config reload (triggers pub/sub, equivalent to SIGHUP on proxy)
curl -X POST -H "Authorization: Bearer ${UI_API_KEY}" http://localhost:8090/api/v1/config/reload

# Check auth rate limiter state
redis-cli -a "${REDIS_PASSWORD}" GET "mgmt:ratelimit:192.168.1.5"
```

---

## 10. Redis Key Schema

| Key | Type | TTL | Written by | Notes |
|-----|------|-----|------------|-------|
| `management:audit_log` | List (LPUSH + LTRIM 1000) | none | Management UI | All secops actions |
| `management:policy_audit` | List (LPUSH + LTRIM 1000) | none | UI, config reload | Bypass changes only |
| `mgmt:ratelimit:{ip}` | String (INCR) | 60s | Auth middleware | Brute-force counter |
| `mgmt:dial_changes:{YYYYMMDDHH}` | String (INCR) | 3600s | Dial router | Hourly change count |
| `dial:current` | String | none | Proxy + UI | Current dial value 0–100 |
| `dial:blocking_acknowledged` | String | none | UI | "true" once admin has acknowledged |

---

## 11. Config Reference

```yaml
management_ui:
  enabled: true
  port: 8090
  # Set via UI_API_KEY environment variable. No default. Startup fails without this.
  api_key: ""

  # Restrict UI access to these CIDRs. Empty list = allow all.
  # In production, restrict to your ops team's IP range.
  allowed_cidr: []     # e.g. ["192.168.1.0/24", "10.0.0.0/8"]

  # Idle session expiry (seconds). After this long without a request, the
  # browser must re-enter the API key.
  session_timeout_seconds: 3600

  # Maximum concurrent SSE subscribers. Prevents resource exhaustion if
  # many automated consumers connect to the live feed.
  max_sse_subscribers: 10

  # Audit log size cap (entries in management:audit_log Redis LIST).
  audit_log_max_entries: 1000

  # TLS termination (Option B — direct TLS without nginx).
  tls:
    enabled: false
    cert: ""    # path to PEM certificate
    key: ""     # path to PEM private key

  # Grafana embed URL (shown in Health panel iframe).
  grafana_url: "http://localhost:3001"

  # Hot-reload: all keys except `port` and `tls.*` are hot-reloadable.
  # `port` and `tls.*` require restart.
```

---

## 12. Test Plan

### 12.1 Unit Tests (`tests/unit/test_management_ui.py`)

```python
# Auth
test_missing_api_key_returns_401
test_wrong_api_key_returns_401
test_correct_api_key_returns_200
test_rate_limiter_blocks_after_10_failures
test_rate_limiter_resets_after_60s

# Bans
test_ban_add_writes_redis_key
test_ban_add_publishes_pubsub
test_ban_add_writes_audit_log
test_ban_release_deletes_redis_key
test_ban_release_publishes_ban_release
test_ban_list_pagination
test_ban_list_ipv6_displayed_correctly

# JA4 Fingerprints
test_candidate_approve_adds_to_blacklist
test_candidate_approve_publishes_pubsub
test_candidate_dismiss_removes_from_queue
test_whitelist_remove_publishes_eviction

# Dial
test_dial_change_within_limit_succeeds
test_dial_change_exceeds_limit_returns_422
test_dial_change_without_acknowledged_returns_422
test_dial_acknowledge_enables_blocking
test_dial_counterfactual_returns_correct_percentage

# Policy
test_bypass_disable_writes_policy_audit
test_bypass_disable_publishes_config_reload
test_bypass_enable_writes_policy_audit

# SSE
test_sse_requires_api_key_in_query_param
test_sse_sends_heartbeat_every_15s
test_sse_subscriber_count_increments_on_connect
test_sse_subscriber_count_decrements_on_disconnect
test_sse_over_max_subscribers_returns_429
```

### 12.2 Integration Tests (`tests/integration/test_management_ui.py`)

```python
test_ban_propagates_to_proxy_via_pubsub          # UI ban → proxy reads within 100ms
test_bypass_disable_rebuilds_proxy_bypass_list   # UI disable → proxy rebuilds within 100ms
test_dial_change_applies_to_proxy                # UI dial → proxy uses new dial within 100ms
test_sse_feed_receives_proxy_events              # proxy emits event → SSE delivers within 1s
```

### 12.3 E2E Tests (`tests/e2e/test_management_ui_e2e.py`)

Using **Playwright** (Python bindings):

```python
# Install: pip install playwright && playwright install chromium
test_login_and_view_live_feed
test_click_to_block_shows_confirmation_and_bans_ip
test_dial_slider_shows_counterfactual_before_applying
test_bypass_toggle_shows_risk_dialog
test_candidate_approve_flow
test_audit_log_shows_all_actions
```

### 12.4 Chaos Tests (`tests/chaos/test_management_chaos.py`)

```python
test_redis_down_returns_503_not_500             # 503 with message, not unhandled exception
test_analytics_node_down_shows_stale_banner     # degraded, not error
test_sse_reconnects_after_redis_restart
test_sse_client_disconnect_no_task_leak         # asyncio.all_tasks() count stable after disconnect
test_auth_ratelimiter_works_under_concurrent_failures
```

---

## 13. Acceptance Criteria

### 13a. Infrastructure

- [ ] FastAPI server starts on port 8090; `UI_API_KEY` required; startup fails with FATAL if not set
- [ ] `allowed_cidr` restriction works: IP outside CIDR gets 403
- [ ] TLS terminates correctly (nginx config or direct TLS config)
- [ ] Security headers present on all responses (CSP, HSTS, X-Frame-Options, etc.)
- [ ] React SPA served from `/app`; all unknown routes return `index.html` (SPA routing)
- [ ] Frontend builds without warnings: `npm run build`

### 13b. Authentication & Security

- [ ] Missing API key → 401; wrong key → 401; correct key → 200
- [ ] Auth rate limiter: 11th failure within 60s → 429 with `Retry-After`
- [ ] After 100 failures from one IP in 1 hour → WARN log emitted + Prometheus metric
- [ ] SSE endpoint requires `?key=` query param; missing → 401
- [ ] `sessionStorage` (not `localStorage`) used for key in browser

### 13c. Live Feed

- [ ] New proxy connection appears in SSE feed within 1s
- [ ] Filters (action, country, ASN type, min score) work correctly
- [ ] Click-to-block: confirmation dialog appears; on confirm, `ban:{ip}` written and pub/sub published
- [ ] Feed pauses when user scrolls up; resumes on scroll-to-bottom
- [ ] Reconnection state shown when SSE disconnects; reconnects automatically
- [ ] Over `max_sse_subscribers` → 429

### 13d. IP/CIDR Management

- [ ] Ban add: writes `ban:{ip}`, publishes pub/sub, writes audit log entry
- [ ] Ban release: deletes `ban:{ip}`, publishes `ban_release`, writes audit log
- [ ] IPv4 and IPv6 bans managed correctly
- [ ] CIDR block: source column shows `manual|rdap_expansion|spamhaus` correctly
- [ ] Pagination works at 50/page; export to CSV correct

### 13e. JA4 Fingerprints

- [ ] Candidate approve → added to `ja4:blacklist`, pub/sub fired, audit log entry
- [ ] Candidate dismiss → removed from queue only, no blacklist entry
- [ ] Whitelist remove → pub/sub cross-instance eviction message fired

### 13f. Dial Control

- [ ] Counterfactual % shown before applying change
- [ ] Change > `max_dial_change_per_hour` → 422 + UI snap-back
- [ ] `blocking_acknowledged = false` → slider disabled, acknowledge flow works
- [ ] Dial change writes audit log with old/new/reason

### 13g. Security Policy

- [ ] All bypass states displayed with correct current state
- [ ] Disabling any bypass shows confirmation dialog with `risk_if_disabled` text
- [ ] Policy change written to `management:policy_audit` with actor IP
- [ ] Startup warnings banner visible when any high-risk bypass is disabled

### 13h. Observability

- [ ] All 7 Prometheus metrics present in `/metrics` output
- [ ] AlertManager rules validated (alerting/rules: `promtool check rules`)
- [ ] Grafana dashboard JSON valid and importable
- [ ] Every admin action produces structured JSON log entry with `actor_ip` and `action_type`
- [ ] WARN log emitted when bypass disabled via UI

### 13i. Performance

- [ ] 10 concurrent SSE connections: no degradation in feed latency
- [ ] `GET /api/v1/bans` with 10,000 ban entries: response in < 500ms (pagination + scan cache)
- [ ] `GET /api/v1/bans` does not use `KEYS ban:*` (confirmed by Redis slowlog)

### 13j. Tests

- [ ] Unit tests: ≥ 35 tests covering all routers
- [ ] Integration tests: all 4 pub/sub propagation tests pass
- [ ] E2E tests: all 6 Playwright scenarios pass (requires running server + Redis)
- [ ] Chaos tests: all 5 resilience tests pass
- [ ] Test-to-code ratio ≥ 1.3× for `management/` Python code

### 13k. Documentation

- [ ] `docs/REDIS_SCHEMA.md` updated with all `management:*` and `mgmt:*` keys
- [ ] Runbook `docs/runbooks/management_ui.md`: access setup, key rotation, SOPs, debugging
- [ ] `config/proxy.yml` inline comments for all `management_ui:` keys
- [ ] `CHANGELOG.md` updated
- [ ] ADR written: why React+FastAPI vs alternatives (`docs/decisions/ADR-013.md`)
