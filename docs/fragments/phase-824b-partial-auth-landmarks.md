# Phase 824b — Partial Auth Enforcement & Panel Landmarks

- Added route-contract tests for console partials in `management/tests/test_partial_contract.py`.
- Parametrised `test_partial_requires_auth` across all 26 extracted GET targets from console templates, ensuring 401 unauthenticated response.
- Added `test_partial_renders_its_panel` asserting panel-specific landmark strings that survive the empty state.
- Verified `attack-mode-indicator` returns 200 text/html with empty body when attack mode is inactive.
