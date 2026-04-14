# Phase 13b — Management UI Completion

## Status: OPEN

---

## 1. Goal

Complete Phase 13. The backend routers for bans, dial, policy, and fingerprints were
built in Phase 13a. This phase adds everything still missing:

- SSE live connection feed
- Extracted config / health / integrations / audit routers (they are inlined in
  `server.py` — extract them to match the spec and add missing features)
- Startup guard: FATAL if `UI_API_KEY` not set
- `allowed_cidr` access restriction
- `management_ui:` section in `config/proxy.yml` with hot-reload support
- React 18 SPA served from `/app` — every screen the spec requires
- AlertManager rules and Grafana dashboard
- Docs: `docs/REDIS_SCHEMA.md` management keys, ADR-013, runbook, CHANGELOG entry
- Tests: fill unit gaps, all integration pub/sub tests, 6 Playwright E2E scenarios,
  remaining chaos scenarios; achieve ≥ 1.3× test-to-code ratio for `management/`

---

## 2. What Is Already Done (Phase 13a)

Do **not** rewrite or delete any of the following. Build on top of it.

| File | Status |
|------|--------|
| `management/auth.py` | Complete — bearer auth, rate limiting, Redis-based fail counter |
| `../../src/security/models.py` | Complete — all Pydantic v2 models |
| `management/metrics.py` | Complete — all 7 Prometheus metrics |
| `management/redis_helpers.py` | Complete — scan_iter bans/cidrs, audit log, candidates, publish_invalidation |
| `management/routers/bans.py` | Complete — GET/POST/DELETE bans and CIDRs |
| `management/routers/dial.py` | Complete — GET/PUT dial, POST acknowledge, rate limit, safety rules |
| `../../src/backup/policy.py` | Complete — GET/PUT bypasses, GET policy audit |
| `management/routers/fingerprints.py` | Complete — blacklist/whitelist/candidates CRUD |
| `management/server.py` | Partial — needs startup guard, `allowed_cidr` middleware, router
|   | extraction, static file mount |
| Tests (unit 54 tests, integration 6, chaos 13) | Partial — gaps listed in §10 |

---

## 3. Backend Completion

### 3.1 Startup Guard

`management/server.py` `create_app()` must check `UI_API_KEY` at startup and abort if
not set:

```python
import sys

api_key = os.environ.get("UI_API_KEY", "")
if not api_key:
    logger.critical(
        "management | event=startup_abort | reason=UI_API_KEY_not_set"
    )
    sys.exit(1)
```

This must run **before** any route or middleware is registered so the process fails
cleanly in Docker/systemd.

### 3.2 `allowed_cidr` Middleware

Add to `server.py` using the `management_ui.allowed_cidr` config value (see §4):

```python
@app.middleware("http")
async def enforce_allowed_cidr(request: Request, call_next):
    """Block requests from outside the configured management CIDR."""
    allowed_cidr = app.state.config.get("management_ui", {}).get("allowed_cidr", "")
    if allowed_cidr:
        client_ip = _get_client_ip(request)
        try:
            network = ipaddress.ip_network(allowed_cidr, strict=False)
            addr = ipaddress.ip_address(client_ip)
            if addr not in network:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Access denied: IP not in allowed CIDR"}
                )
        except ValueError:
            pass  # Malformed config — fail open, log at startup
    return await call_next(request)
```

Health endpoints (`/health`, `/ready`) are exempt from CIDR restriction so load
balancers can probe them.

### 3.3 Router Extraction

The following routes in `server.py` must be extracted to dedicated router files and
removed from the inline body of `create_app()`. The existing inline implementations
contain bugs (decode bytes as string, missing try/except) — the new router files must
fix these.

#### `../../src/analytics/config.py`

Owns:
```
GET  /api/v1/config/thresholds
PUT  /api/v1/config/thresholds
PUT  /api/v1/config/features/{feature}
GET  /api/v1/config/countries/blocklist
PUT  /api/v1/config/countries/blocklist
```

Bugs to fix from the inlined versions:
- `thresholds.get(b"flag", b"20")` — Redis returns strings when `decode_responses=True`;
  use `thresholds.get("flag", "20")` (no bytes literals).
- `PUT /api/v1/config/thresholds` must validate thresholds are in ascending order using
  `ThresholdConfig` model (already in `../../src/security/models.py`).
- `PUT /api/v1/config/countries/blocklist` must write to audit log.
- All endpoints must use `Depends(require_api_key)` and have proper try/except.

Redis keys owned by this router:
```
config:thresholds         HASH  flag / rate_limit / tarpit / block / ban
config:features:{name}   String "true"/"false"
config:countries:blocklist  SET of ISO-3166-1 alpha-2 codes
```

#### `management/routers/health.py`

Owns:
```
GET /health         (unauthenticated — exempt from CIDR too)
GET /ready          (unauthenticated — exempt from CIDR too)
GET /api/v1/health/detail  (authenticated)
```

These routes are currently inlined in `server.py`. Extract them unchanged; keep the
unauthenticated `/health` and `/ready` endpoints accessible without a token.

#### `management/routers/audit.py`

Owns:
```
GET /api/v1/audit
```

Currently inlined in `server.py`. Extract and use the `get_audit_log` helper from
`redis_helpers.py` for consistency.

#### `management/routers/integrations.py`

Owns:
```
GET /api/v1/integrations/abuseipdb
GET /api/v1/integrations/spamhaus
GET /api/v1/integrations/rdap
GET /api/v1/integrations/analytics
```

Currently only AbuseIPDB and Spamhaus exist inlined. Add RDAP and analytics status
endpoints:

```
GET /api/v1/integrations/rdap
    Returns: {"status": "enabled"|"disabled", "service": "rdap",
              "block_expansion": bool}
    Reads: config:features:rdap_block_expansion

GET /api/v1/integrations/analytics
    Returns: {"status": "enabled"|"disabled", "service": "analytics",
              "last_event_age_s": <seconds since last analytics:events entry>}
    Reads: config:features:analytics; XLEN/XREVRANGE analytics:events
```

### 3.4 Updated `server.py` Router Wiring

After extraction, `create_app()` must include all routers:

```python
from management.routers import bans, dial, policy, fingerprints, config, health, audit, integrations, events

app.include_router(bans.router,          prefix="/api/v1", tags=["bans"])
app.include_router(dial.router,          prefix="/api/v1", tags=["dial"])
app.include_router(policy.router,        prefix="/api/v1", tags=["policy"])
app.include_router(fingerprints.router,  prefix="/api/v1", tags=["fingerprints"])
app.include_router(config.router,        prefix="/api/v1", tags=["config"])
app.include_router(integrations.router,  prefix="/api/v1", tags=["integrations"])
app.include_router(audit.router,         prefix="/api/v1", tags=["audit"])
app.include_router(events.router,        prefix="/api/v1", tags=["events"])
app.include_router(health.router,        tags=["health"])
```

The FastAPI static files mount (for the React SPA) is added in `create_app()` after
all routers:

```python
from fastapi.staticfiles import StaticFiles

static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/app", StaticFiles(directory=str(static_dir), html=True), name="spa")
```

### 3.5 SSE Live Feed — `management/routers/events.py`

This is the only entirely new backend module.

**Redis source:** `ja4proxy:events` Redis Stream (written by the proxy via
`analytics.stream_writer` in Phase 12 — same stream as `analytics:events`).

**Note on stream name:** PHASE_13.md calls it `ja4proxy:events`. Phase 12 writes to
`analytics:events`. Use whichever the proxy actually writes to — read the proxy stream
writer to confirm. The events router must use the same key. Document the actual key in
`../REDIS_SCHEMA.md`.

**Endpoint:**

```
GET /api/v1/events
    Auth: Bearer token OR ?key= query param
    Query params:
      filter_action=allow|flag|rate_limit|tarpit|block|ban
      filter_country=<ISO2>
      filter_asn_type=residential|datacenter|tor|vpn
      min_score=<0-100>
    Response: text/event-stream (SSE)
```

**Event types emitted:**

```
data: {"type":"connection","conn_id":"...","ip":"...","country":"GB",
       "asn_type":"datacenter","ja4":"t13d...","score":67,"action":"flag",
       "signals":[...],"timestamp":"2026-03-10T14:23:00Z"}

data: {"type":"ban","ip":"1.2.3.4","score":87,"reason":"...","timestamp":"..."}

data: {"type":"heartbeat","timestamp":"..."}   (every 15s)
```

**Implementation pattern using `sse-starlette`:**

```python
import asyncio
import json
import time
from typing import AsyncGenerator, Optional

import redis.exceptions
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from sse_starlette.sse import EventSourceResponse

from management.auth import require_api_key
from management.metrics import mgmt_sse_subscribers_active, mgmt_redis_errors_total

router = APIRouter()

_MAX_SSE_SUBSCRIBERS = 50
_HEARTBEAT_INTERVAL = 15.0
_STREAM_KEY = "ja4proxy:events"   # Confirm against actual proxy stream key


async def _event_generator(
    request: Request,
    filter_action: Optional[str],
    filter_country: Optional[str],
    filter_asn_type: Optional[str],
    min_score: int,
) -> AsyncGenerator[dict, None]:
    """Read from Redis Stream, filter, and yield SSE events."""
    r = request.app.state.redis
    last_id = "$"  # Only new events
    last_heartbeat = time.monotonic()

    try:
        while True:
            if await request.is_disconnected():
                break

            # Heartbeat
            now = time.monotonic()
            if now - last_heartbeat >= _HEARTBEAT_INTERVAL:
                yield {"event": "heartbeat", "data": json.dumps({
                    "type": "heartbeat",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                })}
                last_heartbeat = now

            try:
                results = await r.xread(
                    {_STREAM_KEY: last_id}, count=100, block=1000
                )
            except redis.exceptions.RedisError:
                mgmt_redis_errors_total.labels(operation="sse_xread").inc()
                await asyncio.sleep(1.0)
                continue

            if not results:
                continue

            for _stream, messages in results:
                for msg_id, fields in messages:
                    last_id = msg_id
                    try:
                        raw = fields.get("data") or fields.get(b"data", b"")
                        event = json.loads(raw)
                    except (json.JSONDecodeError, TypeError):
                        continue

                    # Apply filters
                    if filter_action and event.get("action") != filter_action:
                        continue
                    if filter_country and event.get("country") != filter_country:
                        continue
                    if filter_asn_type and event.get("asn_type") != filter_asn_type:
                        continue
                    if event.get("score", 0) < min_score:
                        continue

                    yield {"event": "message", "data": json.dumps(event)}
    finally:
        pass


@router.get("/events")
async def live_feed(
    request: Request,
    filter_action: Optional[str] = None,
    filter_country: Optional[str] = None,
    filter_asn_type: Optional[str] = None,
    min_score: int = 0,
    _key: str = Depends(require_api_key),
):
    """Stream live connection events via SSE."""
    # Subscriber cap
    current = mgmt_sse_subscribers_active._value.get()
    if current >= _MAX_SSE_SUBSCRIBERS:
        from fastapi import HTTPException
        raise HTTPException(status_code=429, detail="Too many SSE subscribers")

    mgmt_sse_subscribers_active.inc()
    try:
        return EventSourceResponse(
            _event_generator(request, filter_action, filter_country,
                             filter_asn_type, min_score),
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )
    except Exception:
        mgmt_sse_subscribers_active.dec()
        raise
```

**Subscriber gauge** must be decremented on disconnect. Wrap the generator so that
`finally:` calls `mgmt_sse_subscribers_active.dec()`.

**`GET /api/v1/events/recent`** — return last 100 events from the stream without SSE:

```
GET /api/v1/events/recent
    Auth: Bearer token
    Response: {"events": [...]}  (newest first, max 100)
```

Uses `XREVRANGE ja4proxy:events + - COUNT 100`.

---

## 4. Config — `config/proxy.yml` Addition

Add the following section to `config/proxy.yml`. It must be documented inline and
loaded by `src/config/loader.py`. The `allowed_cidr` and `port` values are **not**
hot-reloadable (document this in the inline comment).

```yaml
# ── Management UI ──────────────────────────────────────────────────────────────
management_ui:
  # Port for the FastAPI management server.
  # Not hot-reloadable — requires restart to change.
  port: 8090

  # Bind address. Use 127.0.0.1 for local-only (behind nginx/LB).
  # Not hot-reloadable — requires restart to change.
  host: "127.0.0.1"

  # CIDR of allowed management clients. Empty string = no restriction.
  # Not hot-reloadable — requires restart to change.
  # Example: "10.10.0.0/16" restricts to the ops network.
  allowed_cidr: ""

  # SSE subscriber cap. Requests beyond this limit receive 429.
  # Hot-reloadable.
  max_sse_subscribers: 50

  # Maximum dial changes per hour (safety guard).
  # Hot-reloadable.
  max_dial_changes_per_hour: 10

  # Maximum auth failures per IP per minute before 429.
  # Hot-reloadable.
  max_auth_failures_per_minute: 10
```

---

## 5. React SPA Frontend

### 5.1 Technology Stack

| Component | Choice |
|-----------|--------|
| Framework | React 18 + TypeScript |
| Bundler | Vite 5 |
| Styling | Tailwind CSS 3 + shadcn/ui |
| State — server | TanStack Query (React Query) v5 |
| State — client | React context (auth key only) |
| Routing | React Router v6 |
| Charts | Recharts |
| SSE | Native `EventSource` API |
| HTTP client | Axios (consistent error handling) |
| E2E tests | Playwright |

### 5.2 File Layout

```
management/frontend/
  package.json
  tsconfig.json
  vite.config.ts
  tailwind.config.ts
  index.html
  src/
    main.tsx            # React root, QueryClientProvider, Router
    App.tsx             # Routes + auth guard
    api/
      client.ts         # Axios instance with Bearer token header
      bans.ts           # useListBans, useAddBan, useReleaseBan hooks
      cidrs.ts          # useListCidrs, useAddCidr, useRemoveCidr hooks
      dial.ts           # useGetDial, useUpdateDial, useAcknowledge hooks
      policy.ts         # useListBypasses, useUpdateBypass hooks
      fingerprints.ts   # useBlacklist, useWhitelist, useCandidates hooks
      config.ts         # useThresholds, useUpdateThresholds, useFeatures hooks
      events.ts         # useSSEFeed hook (EventSource wrapper)
      health.ts         # useHealth hook
      integrations.ts   # useIntegrations hook
      audit.ts          # useAuditLog hook
    components/
      layout/
        AppShell.tsx    # Sidebar + top nav
        Sidebar.tsx     # Navigation links
      common/
        AuthGuard.tsx   # Redirects to /login if no key in sessionStorage
        PaginatedTable.tsx
        ConfirmDialog.tsx
        StatusBadge.tsx
        ScorePill.tsx
    pages/
      LoginPage.tsx
      DashboardPage.tsx       # Live feed + summary stats
      BansPage.tsx            # IP ban management
      CIDRsPage.tsx           # CIDR block management
      FingerprintsPage.tsx    # Blacklist/whitelist/candidates
      DialPage.tsx            # Blocking dial control
      PolicyPage.tsx          # Bypass toggles
      ConfigPage.tsx          # Thresholds + feature flags + countries
      AuditPage.tsx           # Paginated audit log
      HealthPage.tsx          # Proxy health + integrations
    types/
      index.ts                # Shared TypeScript interfaces
```

Build output goes to `management/static/`. FastAPI serves it at `/app`.

### 5.3 Authentication

- `LoginPage` presents a single password input.
- On submit, the entered key is stored in `sessionStorage` under `ja4proxy_api_key`.
- Every Axios request reads the key from `sessionStorage` and sets
  `Authorization: Bearer <key>`.
- `AuthGuard` component wraps all routes: if no key in `sessionStorage`, redirect to
  `/login`.
- On 401 response from any API call, clear `sessionStorage` and redirect to `/login`.
- SSE connections use `?key=<key>` query param (EventSource does not support headers).

### 5.4 Page Specifications

#### LoginPage (`/login`)

- Single `<input type="password">` labelled "API Key"
- On submit: `GET /api/v1/health/detail` to validate key; on 200 store and redirect
  to `/`; on 401 show error.
- Key is **never** written to `localStorage`.

#### DashboardPage (`/`)

- Left column: live SSE feed using `useSSEFeed` hook.
  - Table rows: timestamp, IP, country flag, ASN type badge, JA4 (truncated 20 chars),
    score pill (colour-coded: ≥85 red, ≥70 orange, ≥55 yellow, else green), action
    badge.
  - Feed pauses when user scrolls up (via `IntersectionObserver` on the bottom sentinel
    element); resumes on scroll-to-bottom.
  - Reconnecting state shown when SSE disconnects; auto-reconnects with 3s backoff.
  - Click any IP row → "Ban this IP?" confirmation dialog → `POST /api/v1/bans`.
  - Filter bar: action, country, ASN type, min score.
- Right column: summary cards from React Query (auto-refresh every 30s):
  - Active bans count
  - CIDR blocks count
  - Current dial value
  - Candidates awaiting review count
- The feed itself is exempt from React Query caching — SSE push model.

#### BansPage (`/bans`)

- Paginated table of active bans (50/page).
- Columns: IP, reason, expires (relative time), source tag.
- Filter by IP prefix (client-side on current page).
- "Add Ban" button → sheet/drawer: IP input, reason text, TTL selector (1h/4h/24h/
  permanent).
- Release button per row → confirmation dialog → DELETE.
- "Export CSV" button — downloads current page as CSV; **not** all pages.

#### CIDRsPage (`/cidrs`)

- Same pattern as BansPage but for CIDR blocks.
- CIDR input validates on blur with the regex `\d+\.\d+\.\d+\.\d+/\d+` or IPv6.

#### FingerprintsPage (`/fingerprints`)

Three tabs: **Candidates**, **Blacklist**, **Whitelist**.

- **Candidates** tab: sorted by observation count descending. Each row has:
  - JA4 fingerprint, observation count.
  - "Approve" button → POST `/approve` with confirmation ("This will add to blacklist
    and block matching connections. Are you sure?").
  - "Dismiss" button → POST `/dismiss` (no confirmation needed).
- **Blacklist/Whitelist** tabs: paginated, add/remove buttons, same pattern as bans.

#### DialPage (`/dial`)

- Large slider 0–100. Current value displayed prominently.
- If `blocking_acknowledged = false`, slider is disabled; "Acknowledge Blocking Risk"
  button shown below.
  - Acknowledge flow: confirmation dialog explaining that connections will be blocked
    once the dial is above 0 → POST `/dial/acknowledge` → slider unlocks.
- Slider change triggers debounced (500ms) PUT. If the request returns 429 (rate
  limit), the slider snaps back to the previous value and shows an error toast.
- Counterfactual display: show text "At this dial level, N% of recent traffic would be
  blocked" — read from a `GET /api/v1/dial/counterfactual` endpoint (see §3.3 below).

**Add `GET /api/v1/dial/counterfactual` endpoint to dial router:**

```
GET /api/v1/dial/counterfactual?dial={value}
    Auth: Bearer token
    Returns: {"dial": 75, "estimated_block_pct": 12.4,
              "sample_size": 1000, "window": "last_15_min"}
    Implementation: read last N events from ja4proxy:events stream;
    apply the configured thresholds at the given dial value;
    count what fraction would be blocked.
    If < 50 events in window → {"estimated_block_pct": null, "reason": "insufficient_data"}
```

#### PolicyPage (`/policy`)

- List all 8 bypasses with toggle switches.
- Each toggle shows current state (enabled/disabled).
- Clicking a toggle to disable an ALLOW bypass shows a confirmation dialog with the
  `description` from `_BYPASS_DESCRIPTIONS` and a ⚠️ risk notice.
- Disabling a BLOCK bypass shows a softer informational note.
- Banner at top of page if any bypass is disabled: "⚠️ N bypass(es) are currently
  disabled. Review carefully."

#### ConfigPage (`/config`)

Three sections:

1. **Score Thresholds**: five sliders (flag/rate_limit/tarpit/block/ban). Sliders are
   constrained so each cannot exceed the next. Save button sends `PUT /api/v1/
   config/thresholds`. Shows current thresholds on load.
2. **Feature Flags**: toggle list for all features read from `config:features:*`.
   Feature names shown in human-readable form.
3. **Country Blocklist**: tag-input for ISO-2 country codes. Current blocklist loaded
   on mount. Save replaces the entire list.

#### AuditPage (`/audit`)

- Paginated table of audit log entries (50/page).
- Columns: timestamp, event type, actor IP, detail (expandable JSON snippet).
- Filter by event type (dropdown of known event types).
- Newest first.

#### HealthPage (`/health`)

- Card for each integration: AbuseIPDB, Spamhaus, RDAP, Analytics Node.
- Each card: status badge (healthy/degraded/disabled), last updated time.
- Redis health card: ping latency.
- Overall system status at the top.
- Auto-refreshes every 60s.

### 5.5 Build Configuration

`../../package.json` must include:

```json
{
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "test:e2e": "playwright test"
  }
}
```

`vite.config.ts` must output to `../static`:

```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: path.resolve(__dirname, '../static'),
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/api': 'http://localhost:8090',
    },
  },
})
```

`npm run build` must produce no warnings and no TypeScript errors.

---

## 6. Observability

### 6.1 AlertManager Rules

Create `../../deploy/monitoring/alertmanager/rules/management_ui_rules.yml`:

```yaml
groups:
  - name: management_ui
    rules:
      - alert: ManagementUIHighAuthFailures
        expr: rate(ja4proxy_mgmt_auth_failures_total[5m]) > 2
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Management UI: high authentication failure rate"
          description: "Auth failure rate {{ $value | humanize }}/s over 5 minutes. Possible brute-force."

      - alert: ManagementUIRedisErrors
        expr: rate(ja4proxy_mgmt_redis_errors_total[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Management UI: Redis errors"
          description: "Redis error rate {{ $value | humanize }}/s. Check Redis connectivity."

      - alert: ManagementUISSESubscribersCapped
        expr: ja4proxy_mgmt_sse_subscribers_active >= 45
        for: 1m
        labels:
          severity: info
        annotations:
          summary: "Management UI: SSE subscriber cap approaching"
          description: "{{ $value }} active SSE subscribers (cap: 50)."

      - alert: DialAtMaxBlocking
        expr: ja4proxy_dial_setting == 100
        for: 30m
        labels:
          severity: info
        annotations:
          summary: "Blocking dial is at maximum (100)"
          description: "Dial has been at 100 for 30 minutes. Confirm this is intentional."
```

Validate with `promtool check rules alerting/management_ui_rules.yml`.

### 6.2 Grafana Dashboard

Create `grafana/dashboards/management_ui.json` — a valid Grafana 10 dashboard JSON.

Required panels:

| Panel | Query |
|-------|-------|
| Auth failure rate | `rate(ja4proxy_mgmt_auth_failures_total[5m])` |
| API request rate by endpoint | `rate(ja4proxy_mgmt_requests_total[1m])` grouped by `endpoint` |
| API p99 latency | `histogram_quantile(0.99, rate(ja4proxy_mgmt_request_duration_ms_bucket[5m]))` |
| Active SSE subscribers | `ja4proxy_mgmt_sse_subscribers_active` |
| Admin actions per minute | `rate(ja4proxy_mgmt_actions_total[1m])` grouped by `action` |
| Redis error rate | `rate(ja4proxy_mgmt_redis_errors_total[5m])` |
| Current dial value | `ja4proxy_dial_setting` |

Dashboard UID: `management-ui-v1`. Data source variable: `${datasource}`.

---

## 7. Documentation

### 7.1 `docs/REDIS_SCHEMA.md`

Add a "Phase 13 — Management UI" section. New keys to document:

| Key pattern | Type | TTL | Written by | Notes |
|-------------|------|-----|------------|-------|
| `mgmt:ratelimit:{ip}` | String (INCR) | 60s | Management auth | Auth failure counter per IP; rate-limit gate |
| `mgmt:dial_changes:{YYYYMMDDHH}` | String (INCR) | 3600s | Dial router | Hourly dial change counter; max 10/hour safety gate |
| `policy:bypass:{name}` | String "true"/"false" | none | Policy router | Enabled state of each of the 8 security bypasses |
| `management:audit_log` | List (JSON entries) | none | All routers | Admin action audit trail; LPUSH+LTRIM 1000 |
| `management:policy_audit` | List (JSON entries) | none | Policy router, config reload | Security policy change audit; LPUSH+LTRIM 1000 |
| `dial:current` | String (integer 0–100) | none | Dial router, proxy | Current dial value |
| `dial:blocking_acknowledged` | String "true"/"false" | none | Dial router | Blocking risk acknowledgment flag |
| `config:thresholds` | Hash | none | Config router | flag/rate_limit/tarpit/block/ban score thresholds |
| `config:features:{name}` | String "true"/"false" | none | Config router | Individual feature flags |
| `config:countries:blocklist` | Set (ISO-2 codes) | none | Config router | GeoIP country blocklist |

### 7.2 ADR-013

Create `docs/decisions/ADR-013.md`:

```markdown
# ADR-013: Management UI Technology Choices

## Status: Accepted

## Context
Phase 13 requires a management web interface. Choices evaluated:
1. React 18 + FastAPI (REST + SSE)
2. Django with server-side rendering
3. Streamlit / Gradio (data science dashboards)
4. HTMX + FastAPI

## Decision
React 18 + FastAPI.

## Rationale
- FastAPI is already the backend framework; no new dependency.
- React + TypeScript provides type safety across the client boundary.
- Vite gives sub-second HMR in development.
- SSE (not WebSockets) is sufficient for the feed use case: unidirectional,
  proxy-friendly, reconnects automatically.
- shadcn/ui gives production-quality components without design budget.
- Streamlit/Gradio rejected: no support for custom auth, SSE, or arbitrary REST.
- HTMX rejected: poor TypeScript integration; would complicate test coverage.
- Django rejected: heavier ORM dependency incompatible with async Redis usage.

## Consequences
- Frontend build step required in CI.
- Two runtimes (Python backend + Node build tools) in the development environment.
- Playwright adds a Chromium dependency for E2E tests.
```

### 7.3 Runbook

Create `docs/runbooks/management_ui.md`:

```markdown
# Management UI Runbook

## Access Setup
1. Set `UI_API_KEY` in the management server environment (use `openssl rand -base64 32`).
2. Start management server: `uvicorn management.server:app --host 127.0.0.1 --port 8090`.
3. Access at http://localhost:8090/app (dev) or https://mgmt.ja4proxy.internal (prod).

## Key Rotation
1. Generate new key: `openssl rand -base64 32`.
2. Set new `UI_API_KEY` in the environment.
3. Restart the management server process.
4. Distribute new key to authorised operators.
5. Old key is immediately invalid on restart.

## SOPs

### Raising the dial
1. Navigate to Dial page.
2. If slider is disabled, click "Acknowledge Blocking Risk" and confirm.
3. Move slider. The counterfactual impact is shown before you release.
4. Confirm the change in the dialog.
5. Monitor the live feed for unexpected blocks (Dashboard page).
6. If false positives appear, immediately set dial back to 0.

### Banning an IP
- Manual: Bans page → Add Ban → enter IP, reason, TTL.
- From live feed: click the row → "Ban this IP?" → confirm.
- Both paths write `ban:{ip}` to Redis and publish to `ja4proxy:invalidate`.

### Releasing a ban
Bans page → Release button in the row → confirm.

### Approving a JA4 fingerprint candidate
Fingerprints page → Candidates tab → Approve → confirm.
The fingerprint moves to the blacklist and pub/sub fires immediately.

## Debugging

### "Redis unavailable" in the UI
1. Check Redis process: `redis-cli ping`.
2. Check `UI_API_KEY` is set.
3. Check server logs: `journalctl -u ja4proxy-management`.

### SSE feed not receiving events
1. Confirm proxy instances are writing to the events stream:
   `redis-cli XLEN ja4proxy:events`
2. Check subscriber count metric: `curl localhost:8090/metrics | grep sse_subscribers`.
3. Check the stream key name matches between the proxy and events router.
```

### 7.4 `config/proxy.yml`

Add the `management_ui:` section from §4. Every key must have an inline comment.

### 7.5 CHANGELOG.md

Add an entry:

```markdown
## [13.1.0] - YYYY-MM-DD - Management UI — Complete

### Added
- SSE live connection feed (`GET /api/v1/events`, `GET /api/v1/events/recent`)
- React 18 SPA served at `/app` — all 9 pages implemented
- `GET /api/v1/dial/counterfactual` — estimated blocking impact at a given dial value
- Config router: threshold management, feature flags, country blocklist
- Health router: `/health`, `/ready`, `/api/v1/health/detail`
- Integrations router: AbuseIPDB, Spamhaus, RDAP, analytics status
- Audit router: paginated audit log viewer
- RDAP and analytics integration status endpoints
- Startup guard: FATAL if `UI_API_KEY` not set
- `allowed_cidr` middleware: restrict management access to a CIDR range
- `management_ui:` section in `config/proxy.yml`
- AlertManager rules: `../../deploy/monitoring/alertmanager/rules/management_ui_rules.yml`
- Grafana dashboard: `grafana/dashboards/management_ui.json`
- ADR-013: Management UI technology rationale
- Runbook: `docs/runbooks/management_ui.md`
- `docs/REDIS_SCHEMA.md` updated with all management keys
```

---

## 8. Dependency Changes

### Python (`requirements.txt`)

Add if not present:
```
sse-starlette>=1.6.5
```

### Node (`../../package.json`)

All frontend dependencies. Minimum viable set:
```json
{
  "dependencies": {
    "react": "^18.3.0",
    "react-dom": "^18.3.0",
    "react-router-dom": "^6.23.0",
    "@tanstack/react-query": "^5.40.0",
    "axios": "^1.7.0",
    "recharts": "^2.12.0",
    "class-variance-authority": "^0.7.0",
    "clsx": "^2.1.0",
    "tailwind-merge": "^2.3.0",
    "lucide-react": "^0.390.0"
  },
  "devDependencies": {
    "@types/react": "^18.3.0",
    "@types/react-dom": "^18.3.0",
    "@vitejs/plugin-react": "^4.3.0",
    "autoprefixer": "^10.4.0",
    "postcss": "^8.4.0",
    "tailwindcss": "^3.4.0",
    "typescript": "^5.4.0",
    "vite": "^5.3.0",
    "@playwright/test": "^1.44.0"
  }
}
```

---

## 9. Playwright E2E Tests

Location: `management/frontend/e2e/` (Playwright config in `playwright.config.ts`).

These run against a real server (`make start` or `docker compose up`) — not mocks.

Playwright config:

```typescript
import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './e2e',
  use: {
    baseURL: 'http://localhost:8090',
    storageState: 'e2e/.auth/state.json',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
```

**`e2e/auth.setup.ts`** — global setup that authenticates once and saves storage state:

```typescript
import { test as setup } from '@playwright/test'

setup('authenticate', async ({ page }) => {
  await page.goto('/login')
  await page.fill('[placeholder="API Key"]', process.env.UI_API_KEY!)
  await page.click('button[type="submit"]')
  await page.waitForURL('/')
  await page.context().storageState({ path: 'e2e/.auth/state.json' })
})
```

**The 6 required scenarios:**

```
e2e/
  01_login.spec.ts           — wrong key → error; correct key → dashboard
  02_live_feed.spec.ts       — SSE events appear; click-to-ban flow works
  03_ban_management.spec.ts  — add ban; release ban; pagination
  04_fingerprints.spec.ts    — approve candidate; dismiss candidate; whitelist remove
  05_dial_control.spec.ts    — acknowledge flow; move slider; 429 snap-back
  06_policy_bypasses.spec.ts — toggle bypass; confirmation dialog appears; banner shown
```

Each scenario must be independent (set up and tear down its own Redis state via the API).

---

## 10. Python Test Gaps

All tests in `tests/unit/test_management_ui.py`, `tests/integration/test_management_ui.py`,
and `tests/chaos/test_management_chaos.py` must continue to pass. Add the following.

### 10.1 New Unit Tests (`tests/unit/test_management_ui.py`)

Add test classes for every new/refactored router:

| Class | Minimum tests |
|-------|--------------|
| `TestConfigRouter` | get thresholds returns defaults; update thresholds validates ordering; update thresholds rejects out-of-range; country blocklist get/update; feature toggle |
| `TestHealthRouter` | `/health` returns 200 without auth; `/ready` returns 503 on Redis down; `/api/v1/health/detail` requires auth |
| `TestAuditRouter` | returns paginated entries; filters by event_type |
| `TestIntegrationsRouter` | returns correct enabled/disabled for each service; analytics endpoint includes last_event_age_s |
| `TestEventsRouter` | subscriber cap returns 429; recent events returns correct format; missing key → 401 |
| `TestDialCounterfactual` | insufficient data returns null; correct percentage with sample data |
| `TestStartupGuard` | server refuses to start without UI_API_KEY; starts successfully with key set |
| `TestAllowedCIDR` | IP outside CIDR → 403; IP inside CIDR → 200; empty allowed_cidr → allow all; health endpoint exempt |

Target: ≥ 35 new unit tests (combined with existing 54 = ≥ 89 total unit tests for `management/`).

### 10.2 Integration Tests (`tests/integration/test_management_ui.py`)

Add 4 pub/sub propagation tests (require real Redis):

```python
async def test_ban_add_publishes_invalidation():
    """POST /bans publishes an event on ja4proxy:invalidate."""

async def test_ban_release_publishes_invalidation():
    """DELETE /bans/{ip} publishes ban_release event."""

async def test_fingerprint_blacklist_publishes_invalidation():
    """POST /fingerprints/blacklist publishes ja4_blacklist_add."""

async def test_bypass_disable_publishes_invalidation():
    """PUT /policy/bypasses/{name} publishes policy_change."""
```

Each test reads from the Redis Stream after the API call and asserts the correct event
was written.

### 10.3 Chaos Tests (`tests/chaos/test_management_chaos.py`)

Add 2 remaining resilience tests:

```python
async def test_sse_subscriber_cap():
    """N+1th SSE connection returns 429 when cap reached."""

async def test_startup_without_api_key_exits():
    """create_app() calls sys.exit(1) when UI_API_KEY not set."""
```

### 10.4 Test-to-Code Ratio

Current management Python: 2096 lines. Current test lines: ~1071.
Ratio: 0.51× — well below the 1.3× target.

After adding the tests in 10.1–10.3 plus tests for the new router files, target ≥ 2730
test lines for `management/` Python code. The ratio is measured as:

```
total lines in tests/**/*management* / total lines in management/**/*.py
```

---

## 11. Implementation Order

Follow this order strictly. Each step can be verified independently.

```
Step 1:  Add startup guard + allowed_cidr middleware to server.py
         Tests: TestStartupGuard, TestAllowedCIDR

Step 2:  Extract config router (management/routers/config.py)
         Tests: TestConfigRouter

Step 3:  Extract health router (management/routers/health.py)
         Tests: TestHealthRouter

Step 4:  Extract audit router (management/routers/audit.py)
         Tests: TestAuditRouter

Step 5:  Extract + expand integrations router (management/routers/integrations.py)
         Tests: TestIntegrationsRouter

Step 6:  Add dial counterfactual endpoint to dial router
         Tests: TestDialCounterfactual

Step 7:  Implement SSE events router (management/routers/events.py)
         Tests: TestEventsRouter

Step 8:  Wire all routers into server.py; remove all inline routes from create_app()
         Run: python3 -m pytest tests/unit/test_management_ui.py — all pass

Step 9:  Add management_ui section to config/proxy.yml
         Add sse-starlette to requirements.txt

Step 10: Implement React SPA
         Start with auth + layout shell, then each page in dependency order:
         LoginPage → DashboardPage → BansPage → CIDRsPage → FingerprintsPage
         → DialPage → PolicyPage → ConfigPage → AuditPage → HealthPage
         Run: npm run build — zero warnings, zero TypeScript errors

Step 11: Integration tests (pub/sub propagation)
         Chaos tests (SSE cap, startup guard)

Step 12: Playwright E2E tests (requires running server + Redis)

Step 13: AlertManager rules, Grafana dashboard JSON
         Run: promtool check rules alerting/management_ui_rules.yml

Step 14: Documentation — REDIS_SCHEMA.md, ADR-013, runbook, proxy.yml comments,
         CHANGELOG.md

Step 15: Final check — run ./run-tests.sh; all 1293 existing tests + new tests pass
```

---

## 12. Acceptance Criteria

All boxes must be ticked before Phase 13 is marked complete.

### 12a. Infrastructure

- [ ] FastAPI server refuses to start (sys.exit(1) + FATAL log) if `UI_API_KEY` not set
- [ ] IP outside `allowed_cidr` gets 403; `/health` and `/ready` exempt from CIDR check
- [ ] Security headers present on all responses (HSTS, CSP, X-Frame-Options, nosniff,
      Referrer-Policy)
- [ ] React SPA served from `/app`; unknown routes return `index.html` (SPA routing)
- [ ] `npm run build` produces zero TypeScript errors and zero Vite warnings
- [ ] `sse-starlette` added to `requirements.txt`

### 12b. Routers Extracted and Wired

- [ ] `../../src/analytics/config.py` exists; all 5 config endpoints work
- [ ] `management/routers/health.py` exists; `/health` and `/ready` require no auth
- [ ] `management/routers/audit.py` exists; returns paginated, filterable audit entries
- [ ] `management/routers/integrations.py` exists; includes RDAP and analytics endpoints
- [ ] `server.py` `create_app()` has no inline route handlers (all extracted to routers)
- [ ] Bytes-vs-string decode bug in threshold handler fixed (no `b"flag"` keys)

### 12c. SSE Live Feed

- [ ] New proxy connection appears in SSE feed within 2s
- [ ] Filters (action, country, ASN type, min_score) correctly exclude non-matching events
- [ ] Heartbeat emitted every 15s when no events
- [ ] Over `max_sse_subscribers` cap → 429
- [ ] `GET /api/v1/events` with missing key → 401
- [ ] `GET /api/v1/events/recent` returns last ≤ 100 events, newest first
- [ ] `mgmt_sse_subscribers_active` gauge increments on connect, decrements on disconnect

### 12d. Dial Counterfactual

- [ ] `GET /api/v1/dial/counterfactual?dial=75` returns `estimated_block_pct` as float
- [ ] Returns `{"estimated_block_pct": null, "reason": "insufficient_data"}` when < 50
      events in the window

### 12e. React SPA Pages

- [ ] LoginPage: wrong key shows error; correct key stores in `sessionStorage`, redirects to `/`
- [ ] Key stored in `sessionStorage`, NOT `localStorage`
- [ ] On 401 API response: key cleared from `sessionStorage`, redirect to `/login`
- [ ] DashboardPage: live SSE feed appears; feed pauses on scroll-up; resumes on
      scroll-to-bottom; reconnects automatically after disconnect
- [ ] Click-to-ban from live feed: confirmation dialog appears; on confirm, POST /bans fired
- [ ] BansPage: add/release bans; pagination works; IPv6 addresses handled
- [ ] CIDRsPage: add/remove CIDRs
- [ ] FingerprintsPage: approve candidate → blacklist; dismiss → removed from queue; whitelist remove
- [ ] DialPage: slider disabled when `blocking_acknowledged=false`; acknowledge flow unlocks slider;
      429 response snaps slider back
- [ ] PolicyPage: all 8 bypasses shown; disable ALLOW bypass shows confirmation with risk text;
      banner visible when any bypass disabled
- [ ] ConfigPage: threshold sliders save; feature toggles; country blocklist add/remove
- [ ] AuditPage: entries displayed; event_type filter works
- [ ] HealthPage: integration status cards; auto-refreshes

### 12f. Tests

- [ ] ≥ 89 total unit tests for `management/` (54 existing + ≥ 35 new)
- [ ] All 4 pub/sub integration tests pass (require Redis)
- [ ] All 6 Playwright E2E scenarios pass (require running server + Redis)
- [ ] All 15 chaos tests pass (13 existing + 2 new)
- [ ] Test-to-code ratio ≥ 1.3× for `management/` Python code

### 12g. Observability

- [ ] `../../deploy/monitoring/alertmanager/rules/management_ui_rules.yml` passes `promtool check rules`
- [ ] `grafana/dashboards/management_ui.json` is valid JSON and importable into Grafana 10
- [ ] All 7 Prometheus metrics present in `/metrics` output under load

### 12h. Documentation

- [ ] `docs/REDIS_SCHEMA.md` has a Phase 13 section with all 10 new keys documented
- [ ] `docs/decisions/ADR-013.md` exists and explains React+FastAPI choice
- [ ] `docs/runbooks/management_ui.md` exists with access setup, SOPs, key rotation,
      debugging steps
- [ ] `config/proxy.yml` has `management_ui:` section with all keys inline-commented
- [ ] `CHANGELOG.md` updated with [13.1.0] entry
