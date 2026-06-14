---
phase: 232b
title: Threat Posture Situation Bar & Heartbeat Alerting
status: PROPOSED
size: SMALL
created: 2026-06-14
audience: [developer, operator]
dependencies: [232a]
---

# Threat Posture Situation Bar & Heartbeat Alerting

> **STATUS: PROPOSED — plan for review. No code until approved.**
> Part 2 of 4 of the split Phase 232. Adds ambient security posture awareness to the Management Console.

## Goal

Provide operators with immediate awareness of the proxy security posture. This requires two things that don't exist today:
1. **Go proxy heartbeat** — a goroutine that periodically writes `proxy:heartbeat:{hostname}` (SET EX 90) so the management API can detect proxy liveness.
2. **Situation bar endpoint** — `/api/v1/partials/situation` that queries Redis (recent `events:connection` stream, heartbeat keys) and returns an HTML situation bar polled every 10s.
3. **Template** — full-width bar at dashboard top showing NOMINAL / ELEVATED / ACTIVE / PROXY_DOWN states.

## Scope

### Files to create/modify:
- `cmd/ja4pd/main.go` — add heartbeat goroutine in `serve()` (SET `proxy:heartbeat:{hostname}` EX 90 every 60s)
- `management/api/routes/partials.py` — add `situation_partial()` route
- `management/templates/partials/situation_bar.html` — new template for the 4 states
- `management/templates/dashboard.html` — insert HTMX polling slot for the bar
- `tests/unit/test_situation_partial.py` — unit tests for all 4 states
- `docs/OPERATIONS_GUIDE.md` — document threat posture states and operator response

### Out of scope:
- Compiling static Tailwind CSS or vendoring JS files (covered by 232a).
- Container networking or port changes (covered by 232c).
- Admin-API decommissioning (covered by 232d).
- `stats:events_per_min` counter — this phase computes rate from stream instead.
- Full dashboard redesign (covered by 234–238).

## Prerequisites & Ground Truth

| Key | Written by | Status |
|---|---|---|
| `proxy:heartbeat:{hostname}` | Nothing | **NEVER WRITTEN** — this phase adds Go producer |
| `events:connection` | Go proxy via XADD | **Working** — each entry is ECS JSON with `event.action`, `event.risk_score`, `source.ip`, `ja4proxy.fingerprint.ja4` |
| `stats:events_per_min` | Nothing | **NEVER WRITTEN** — this phase computes rate from stream |
| `config:dial` | Go proxy | **Working** — used for dial badge |

## Implementation Plan

### 1. Go Heartbeat Producer (`cmd/ja4pd/main.go`)

In `serve()`, launch a goroutine that every 60s does:
```
hostname, _ := os.Hostname()
p.redis.Set(ctx, "proxy:heartbeat:"+hostname, epoch, 90*time.Second)
```
On graceful shutdown (ctx.Done), best-effort DEL the key so PROXY_DOWN is detected within one poll cycle (10s). Hard crash (SIGKILL) leaves the key — TTL expiry (90s) handles that, and the management API will detect PROXY_DOWN at most 30s after the last missed write.

### 2. Situation Endpoint (`management/api/routes/partials.py`)

Add `GET /api/v1/partials/situation` (authenticated, HTML response):

**Data gathering:**
- Detect proxy liveness: SCAN `proxy:heartbeat:*` — if count == 0, state = `PROXY_DOWN`
- Read last 5 min of `events:connection` via XREVRANGE (count 1000, capped). Count events by parsing the `event` JSON field and reading `event.action`:
  - `block`, `ban`, `tarpit` → block count
  - All entries → total events, derive events/min
- Find the highest `event.risk_score` and top attacking `source.ip` from recent entries
- Read `config:dial` for context
- **Note:** `events:connection` is uncapped (no MAXLEN) until Phase 233 — XREVRANGE with COUNT 1000 is safe for reasonable traffic levels; on high-throughput deployments this may undercount but the bar is a rough indicator, not a precise meter

**State classification:**
| Condition | State |
|---|---|
| No heartbeat keys | `PROXY_DOWN` |
| 0 blocks in last 5 min | `NOMINAL` |
| 1–9 blocks in last 5 min | `ELEVATED` |
| 10+ blocks in last 5 min | `ACTIVE` |

**Error handling:** If Redis is unreachable, return `PROXY_DOWN` (fail-closed — operator should investigate).

### 3. Situation Bar Template (`management/templates/partials/situation_bar.html`)

Full-width bar using color + shape + text for WCAG 2.1 AA:
- `PROXY_DOWN` — red bg, white text, alert icon, link to recovery runbook
- `NOMINAL` — green bg, "All Clear" + events/min + 0 blocks — shows the proxy is processing traffic
- `ELEVATED` — amber/yellow bg, warning icon, show block count + top attacking IP
- `ACTIVE` — red bg, alert icon, show block count + top attacking IP

Every state includes: events/min, block count (elided to "—" if 0 for NOMINAL), highest risk score, top attacking IP in the window.

### 4. Wire into Dashboard (`management/templates/dashboard.html`)

Insert above the health cards row:
```html
<div id="situation-bar"
     hx-get="/api/v1/partials/situation"
     hx-trigger="load, every 10s"
     hx-swap="outerHTML">
  {% include "partials/situation_bar.html" %}
</div>
```

Use negative margins (`-mx-6 -mt-6`) to stretch edge-to-edge.

### 5. Update Operations Guide

Add "Threat Posture Monitoring" section to `docs/OPERATIONS_GUIDE.md`:
- Thresholds and state interpretation
- Recommended actions for each state
- How heartbeat monitoring works

## Test Strategy

### Unit Tests (`tests/unit/test_situation_partial.py`)

Mock Redis to simulate each state:
- `PROXY_DOWN` — SCAN returns no heartbeat keys
- `NOMINAL` — heartbeat exists, stream has 0 block/tarpit actions
- `ELEVATED` — heartbeat exists, stream has 3 block actions
- `ACTIVE` — heartbeat exists, stream has 15 block/tarpit actions

Assert correct HTML output, CSS classes, and visible text for each state.

### Manual Verification
- Start the full stack, confirm the bar shows NOMINAL
- `redis-cli DEL proxy:heartbeat:*` → bar flips to PROXY_DOWN within 10s
- Inject block events via `redis-cli XADD events:connection * <event_json>` → bar escalates

## Acceptance Criteria

- [ ] Go proxy heartbeat goroutine writes `proxy:heartbeat:{hostname}` every 60s with 90s TTL
- [ ] Heartbeat key deleted on graceful shutdown (PROXY_DOWN detected within 10s)
- [ ] `GET /api/v1/partials/situation` returns correct HTML for all 4 states
- [ ] Dashboard includes situation bar in a 10s HTMX polling slot
- [ ] `situation_bar.html` renders with proper colors, icons, and data for each state
- [ ] `docs/OPERATIONS_GUIDE.md` updated with threat posture section
- [ ] Unit tests cover all 4 states, 100% pass rate
- [ ] `make lint` exits 0 (Go + Python)
- [ ] `make test-unit` passes
