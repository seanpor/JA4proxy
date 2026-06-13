# Threat Posture Dashboard & Infrastructure Rows

## Goal

Build the main Threat Posture dashboard and live connection panels in the FastAPI + HTMX console. Ensure all visual elements map directly to the unified event stream key (`events:connection`), nested ECS fields, and correct Redis structures (such as `ban:*` for active bans and `mgmt:node:*` for active proxy nodes). This prevents dead charts and ensures operators see real-time, accurate security data.

---

## A — Dashboard UI Structure

Implement the dashboard layout in the management console using HTMX for partial page updates:
- **Proxy Status Panel:** Displays the list of live proxies retrieved by scanning `mgmt:node:*` keys.
- **Traffic Overview Panel:** Renders connection rates per second, grouped by actions (`allow, flag, rate_limit, tarpit, block, ban`).
- **Enforcement Gauge:** Displays the count of active bans by querying the quantity of `ban:*` keys.
- **Tarpit Statistics:** Displays active tarpit concurrency using the `ja4proxy_tarpit_concurrent` metric or direct Redis stats.

---

## B — Stream Backend Integration

Connect the dashboard API endpoints to the stream reader:
- The `/api/v1/dashboard/metrics` route must read and aggregate the latest events from the `events:connection` stream.
- Deserialize the nested event JSON (reusing the mapping logic defined in PHASE_321) to count actions and scores.
- Return structured data to the HTMX views.
- Ensure all charts fallback gracefully (displaying "No Data") if the Redis stream is empty, rather than rendering empty/broken HTML frames.

---

## C — Dashboard Rendering Tests

Write automated rendering and contract tests:
- `management/tests/test_pages.py` — Add tests to:
  - Assert GET `/dashboard` returns `200 OK` and contains key dashboard landmarks (e.g. "Active Bans", "Proxy Status").
  - Verify that mock stream events with various actions (`tarpit`, `ban`, etc.) correctly change the counter metrics on the rendered HTML page.
  - Assert that an unauthenticated user gets redirected safely instead of crashing the view.

---

## Acceptance Criteria

- [ ] GET `/dashboard` renders a responsive, styled interface with valid HTML and CSS.
- [ ] No Javascript or CSS files fail to load or reference external CDN hosts.
- [ ] Dashboard charts successfully populate when synthetic ECS events are pushed to the `events:connection` Redis stream.
- [ ] All UI indicators map to real action names (`allow`, `flag`, etc.) and do not reference retired actions (like `monitor`).

---

## Files to Modify

| File | Change |
|------|--------|
| `management/templates/dashboard.html` | New template or update — Unified Threat Posture dashboard layout |
| `management/api/routes/dashboard.py` | Update API route to stream and aggregate `events:connection` data |
| `management/tests/test_pages.py` | Add dashboard integration and rendering tests |
| `CHANGELOG.md` | Add Phase 324 entry |
