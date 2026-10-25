# Phase 824d — UI Health Four-State Endpoint

- Added authenticated `/api/v1/health/ui` four-state endpoint in `management/api/routes/ui_health.py`.
- Probes all console partials in-process via ASGITransport, forwarding session credentials.
- Classifies each panel into `OK`, `EMPTY`, `DEGRADED`, or `BROKEN` with stable reason codes.
- Aggregate status reports `RED` if any panel is `BROKEN`; `EMPTY` and `DEGRADED` (e.g. Redis/Prometheus down) remain `GREEN`.
- Hardened Redis resilience on partial routes (`_get_dial`, `attack-mode-indicator`, `intelligence`) to fail open gracefully when Redis is disconnected.
- Added test coverage in `management/tests/test_ui_health.py` asserting authentication, baseline GREEN, DEGRADED mapping, BROKEN detection, and timeout handling.
