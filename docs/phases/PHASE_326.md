# Analytics Intelligence & Findings UI

## Goal

Expose the analytics engine's real-time threat intelligence findings, baseline calibration alerts, and distribution shift metrics in the management console. Bind the UI panels to the actual Redis keys used by the analytics engine (such as `analytics:alerts:calibration_issue`, `analytics:alerts:distribution_shift`, and `analytics:shadow_scores:latest`) instead of fictional/dead keys, ensuring operators can monitor ML and behavior-analysis status from the UI.

---

## A — Analytics Status Panel

Implement an "Analytics Intelligence" row or section in the management dashboard:
- **Calibration Alerts Panel:** Queries `analytics:alerts:calibration_issue` from Redis. If set, parse the JSON payload and display the warning (e.g. baseline skew, model drift).
- **Distribution Shift Panel:** Queries `analytics:alerts:distribution_shift` from Redis. If set, parse the JSON payload and display the warning (e.g. unexpected changes in connection volume or cipher diversity).
- **Shadow Scoring Panel:** Queries `analytics:shadow_scores:latest` and displays active shadow scoring statistics and calibration drift.
- If any of these keys are missing or expired, the UI renders the status as "Nominal / No Issues" instead of raising an exception.

---

## B — API Handlers integration

Add API handlers in FastAPI to fetch and serialize these analytics states:
- `/api/v1/analytics/status` — Retrieves and aggregates the above Redis keys, returning a structured JSON payload to the HTMX views.
- Ensure the endpoints are decorated with proper OIDC/SAML auth and role-based access control (Auditor+ role required).
- Do not attempt to invoke non-existent python detector functions synchronously from the web process (let the analytics worker run independently in the background).

---

## C — Integration Tests

Extend the test suite:
- `management/tests/test_pages.py` — Add tests to:
  - Mock active Redis keys (e.g., `analytics:alerts:calibration_issue`) with mock alert data and assert the warnings are displayed in the dashboard HTML.
  - Verify that when no keys are present, the page renders "Nominal" with no 500 errors.
  - Assert the `/api/v1/analytics/status` endpoint returns accurate serialised data.

---

## Acceptance Criteria

- [ ] GET `/api/v1/analytics/status` returns `200 OK` and correctly serialises real-world Redis JSON outputs.
- [ ] Active shadow scores from `analytics:shadow_scores:latest` render correctly on the UI page.
- [ ] Active drift alerts are displayed clearly in red/yellow warning boxes when simulated in tests.
- [ ] No blocking/synchronous ML execution is performed in the web thread.

---

## Files to Modify

| File | Change |
|------|--------|
| `management/templates/partials/analytics_row.html` | New template — Analytics alerts and metrics row |
| `management/api/routes/analytics.py` | New file — Analytics API route (handling status and shadow score lookups) |
| `management/tests/test_pages.py` | Add analytics UI rendering and fallback tests |
| `CHANGELOG.md` | Add Phase 326 entry |
