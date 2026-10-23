- **The console's route-coverage gate no longer drops Jinja-wrapped targets.** Tier 1
  (`management/tests/test_ui_regression.py`) extracted `hx-get` URLs with a brace
  filter, so the two targets built as `...attack-top{% if attack_mode_active %}...`
  were invisible: a renamed or deleted partial behind them would have blanked a panel
  with every test green. A single shared extractor
  (`management/tests/hx_targets.py`) now strips `{% %}` blocks, substitutes a sample
  for `{{ }}` expressions, and raises on any surviving brace instead of silently
  discarding the URL — Tier 1 covers all 48 targets across 19 partials.
- **New static gate: `management/tests/test_template_route_targets.py`.** Every
  extracted `hx-*` target must resolve to a registered route by **method and path**
  (48/48 forward, 11 of them mutating), every registered partial must be referenced
  or listed in an explicit allowance set with a test proving the one entry
  (`/api/v1/partials/attack-table`, the legacy alias printed only inside an HTML
  comment) really is unreferenced, and the guard guards itself (≥20 targets, ≥6
  mutating) so a broken extractor cannot pass vacuously. Routes are parsed from
  decorators, not from `create_app()`, so the gate stays static and cheap.
- **The repaired extractor immediately found a real bug.** `/api/v1/partials/attack-top`
  calls the JSON handler `top_attackers` directly, bypassing FastAPI's dependency
  injection, so its `window: int = Query(...)` default reached `time.time() - window`
  (TypeError) and the response's `window_seconds` field (not JSON serialisable). The
  panel had never rendered its content path; htmx's failure branch hid it. Fixed at
  the call site and pinned by a partial-level test in `management/tests/test_attack.py`.
- **The forward check had to be repaired before it could prove anything.** It matched
  a declared route against a request path by string prefix, so two routes satisfied
  every target: `GET /` (prefix `/`) and `GET /api/v1/{list_name}` (prefix
  `/api/v1/`, a one-segment route from `canonical_lists.py`). All 48 targets
  "resolved" regardless of whether their route existed. Matching is now segment-wise
  — a literal must be equal, `{name}` matches one segment, `{name:path}` consumes the
  rest — and is deliberately stricter than the prefix rule in `test_pages.py`.
  Demonstrated by renaming a partial route: the forward check now fails (3 failed /
  51 passed), as does removing the alias allowance (2 failed / 52 passed).
- **`tests/integration/journeys/check_console_journey.sh`** now probes all 20 registered
  partials (the hand-maintained list covered 13, and nothing noticed the gap because a
  shell list cannot import the route table). A parity test in
  `test_template_route_targets.py` parses `PARTIALS=(...)` and fails when it drifts
  from the registered routes — the first draft of this refresh dropped
  `attack-mode-indicator` while claiming completeness, and the test caught it.
