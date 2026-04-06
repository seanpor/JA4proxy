# Phase 13/51/52 — Management UI: Revised Plan

> This document supersedes the original PHASE_13.md, PHASE_51.md, and PHASE_52.md
> for the purposes of the management UI implementation. The consolidated architecture
> described here replaces the three-phase split with a single cohesive delivery.

---

## 1. Original Plan Critique

### Phase 13 — Backend API
The original plan was solid in scope (FastAPI, Redis integration, JWT auth, health
endpoints) but left the authentication mechanism underspecified. It did not clarify
whether tokens should be stored in localStorage (XSS-vulnerable) or httpOnly cookies
(safe). The plan also did not specify how the management port should be network-isolated.

### Phase 51 — Frontend Dashboard
Phase 51 proposed React + TypeScript + Vite. For an internal operations UI used by
at most a handful of secops engineers, this is heavyweight:

- Requires a Node.js build pipeline and npm dependency tree
- Produces a separate build artefact that must be served by a second process or mounted
  as a Docker volume
- Adds ~400 MB of node_modules to the build context
- TypeScript compilation is a meaningful latency source in CI
- A separate React container (or Nginx server) is needed to serve the built bundle

None of these costs are justified for an ops tool. The alternative (Jinja2 templates +
HTMX + Alpine.js via CDN) achieves the same interactive UX with zero build step, zero
Node dependency, and a single container.

### Phase 52 — Admin Tooling
Phase 52 proposed a GeoIP heatmap using Leaflet.js or D3.js. A country-level heatmap is
visually compelling but provides no operational value not already available from
`top-attackers` and `geoip-report` in the Makefile. Deferred to a later phase or
permanently deprioritised. Everything else in Phase 52 (list management, ban management,
audit log) is retained.

### Three Phases, One Container
The original split across three phases implied three separate deliveries. Given the
revised architecture, all requirements fit in one FastAPI container and one cohesive
delivery.

---

## 2. Revised Architecture

### Single Container

```
ja4proxy-management:1.0.0
  FastAPI app at :8090
  Jinja2 templates → full-page HTML
  HTMX → partial HTML swap on user actions
  Alpine.js → minimal JS interactivity (tabs, dial widget state)
  Tailwind CSS + Chart.js → via CDN, zero build step
  SSE endpoint → live connection feed pushed to browser
  Redis async client → all proxy data read/write
```

### Network Topology

```
Internet ──NOT REACHABLE──▶  :8090 (bound to 127.0.0.1 only)
                                │
Chromebook ──SSH tunnel──▶  localhost:8090
                                │
                           Management container
                                │
                         mgmt_net + data_net
                                │
                            Redis ←── Proxy
```

Port 8090 is bound to loopback (`127.0.0.1:8090:8090`). It is never reachable from
the internet. Access is always via SSH tunnel from a machine with SSH access to the
server.

### Authentication

- Single admin user configured via environment variables
  (`MANAGEMENT_ADMIN_USER`, `MANAGEMENT_ADMIN_PASSWORD`)
- On successful login, a JWT is issued and stored in an httpOnly, Secure, SameSite=Strict
  cookie — XSS cannot read it
- JWT signed with `MANAGEMENT_JWT_SECRET` (must be set to a random 32+ char string in
  production)
- Login endpoint rate-limited to 5 attempts per 60 seconds
- All authenticated actions include the session source IP in the audit log

### Live Feed

The live connection feed uses Server-Sent Events (SSE). The management service reads
from the Redis Stream (`events:connections`) and pushes updates to the browser. No
WebSocket needed — SSE is unidirectional, works through HTTP/1.1, and requires no
special proxy configuration.

---

## 3. Security Model

| Control | Mechanism |
|---------|-----------|
| Network isolation | Port bound to 127.0.0.1; not reachable from internet |
| Remote access | SSH tunnel only |
| Auth token storage | httpOnly cookie (XSS-resistant) |
| Auth token algorithm | HS256 JWT, signed with MANAGEMENT_JWT_SECRET |
| Brute force protection | Rate limit: 5 login attempts / 60s |
| CSRF | SameSite=Strict cookie; all mutating actions POST-only |
| Audit trail | Every write action logged to `management:audit_log` LIST in Redis |
| Reload/restart | Triggered via Redis pubsub — no shell exec needed |
| Secret injection | Environment variables, never baked into image |

---

## 4. What Is Implemented

### All Phase 13 backend requirements
- `/api/v1/health` — deep health endpoint (Redis connectivity, proxy process state)
- `/api/v1/status` — current dial, active bans, block/allow/flag counts
- `/api/v1/dial` — GET current value; POST to change (validates ±10 per request)
- `/api/v1/config/reload` — triggers proxy config reload via Redis pubsub
- Full JWT auth middleware on all state-mutating endpoints

### Phase 51 dashboard requirements (without GeoIP map)
- `/` — main dashboard: health indicators, current dial with widget, recent event feed
- SSE endpoint at `/api/v1/feed` — live connection events from Redis Stream
- Risk score distribution chart (Chart.js, data from Prometheus or Redis counters)
- Active bans count and action breakdown

### Phase 52 list management and ban management
- `/lists/whitelist` — view, add, remove JA4 fingerprints from whitelist
- `/lists/blacklist` — view, add, remove JA4 fingerprints from blacklist
- `/lists/allowlist` — view, add, remove IPs from static IP allowlist
- `/bans` — view active bans, apply manual ban with TTL, lift ban
- `/audit` — paginated audit log of all management actions
- Config reload trigger from UI

### GeoIP heatmap
Deferred. The operational value does not justify the Leaflet.js/D3.js dependency for v1.
A country breakdown table (top 10 by ban count) is provided instead.

---

## 5. Acceptance Criteria

- `make management-up` builds and starts the management container with no errors
- `curl http://localhost:8090/api/v1/health` returns `{"status": "ok"}` (or equivalent)
- Navigating to `http://localhost:8090` in a browser via SSH tunnel shows the login page
- Login with `MANAGEMENT_ADMIN_USER` / `MANAGEMENT_ADMIN_PASSWORD` succeeds and redirects
  to the dashboard
- Dashboard displays: dial value, health status, recent connection events via SSE
- Dial can be changed via the UI; change is validated (max ±10 per request)
- JA4 fingerprints can be added to and removed from the whitelist and blacklist
- IPs can be added to and removed from the static allowlist
- Manual ban can be applied and lifted
- Config reload can be triggered from the UI
- Every mutating action appears in the audit log at `/audit`
- Login rate limiting: 6th attempt within 60 seconds returns HTTP 429
- Port 8090 is NOT reachable from outside the server (verify: `curl http://<server-external-ip>:8090` times out)
- SSH tunnel access works from a Chromebook Linux terminal

---

## 6. File Ownership

```
management/                  — Phase 13/51/52 owns entirely
  __init__.py
  auth.py
  models.py
  redis_client.py
  requirements.txt
  api/
    __init__.py
    auth.py
    models.py
    redis_client.py
    routes/
  static/
  templates/
  tests/
docker/Dockerfile.management  — Phase 13/51/52 adds
docker/docker-compose.poc.yml         — Phase 13/51/52 adds management service (bottom of services)
Makefile                       — Phase 13/51/52 adds targets at bottom only
docs/MANAGEMENT_UI_ACCESS.md   — Phase 13/51/52 adds
```

---

## 7. Environment Variables

| Variable | Default | Notes |
|----------|---------|-------|
| `REDIS_URL` | `redis://redis:6379/0` | Redis connection URL |
| `MANAGEMENT_JWT_SECRET` | `change-me-in-production` | Must be changed before exposing to team |
| `MANAGEMENT_ADMIN_USER` | `admin` | Login username |
| `MANAGEMENT_ADMIN_PASSWORD` | `admin` | Must be changed before exposing to team |

Set these in your `.env` file (never commit `.env` to git).

---

## 8. Dependencies

All Python. No Node.js. No npm. No build step.

| Package | Purpose |
|---------|---------|
| `fastapi` | ASGI web framework |
| `uvicorn[standard]` | ASGI server |
| `redis[asyncio]` | Async Redis client |
| `python-jose[cryptography]` | JWT signing and verification |
| `passlib[bcrypt]` | Password hashing |
| `jinja2` | HTML templating |
| `python-multipart` | Form data parsing |
| `sse-starlette` | Server-Sent Events |
| `httpx` | HTTP client for health checks in tests |

Frontend assets loaded from CDN (no build step required):
- Tailwind CSS
- Alpine.js
- HTMX
- Chart.js
