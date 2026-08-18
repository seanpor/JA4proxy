- **Unreadable input text on light-scheme systems (Phase 828)**: `custom.css`
  overrode `.glass-input` fully inside `@media (prefers-color-scheme: light)`
  but overrode `.glass-input:focus` for `border-color` only, so the base focus
  rule's near-black background survived while the light block's dark text colour
  applied — **1.04:1 contrast while typing**. It affected every input in the
  app, including the login form's username and password fields.
- **Live feed no longer shows permanent placeholder bars (Phase 828)**: the SSE
  generator started at `"$"` (live-only) and nothing ever removed the five
  `animate-pulse` skeleton rows. With 54,790 events in the stream but no traffic
  in flight, the feed was five pulsing grey bars indefinitely. It now backfills
  the 25 most recent events on connect, clears the placeholders on a
  `backfill-complete` event, and states plainly when the stream is genuinely
  empty.
- **`[x-cloak]` behaviour retained (Phase 828)**: unchanged from 827, noted here
  because the new empty-state row depends on it.
- **Phase 828 planned (`docs/phases/PHASE_828.md`)**: operator decision support.
  Records that the proxy computes a full per-signal explanation
  (`PipelineResult.Signals`, each with a human-readable `Reason`) plus dial
  counterfactuals and emits neither, that the live feed drops
  `ja4proxy.bypass_reason` so blocked-by-list and blocked-by-score are
  indistinguishable, and that no endpoint joins IP to fingerprint. 12 testable
  outcomes with named tests.
- **New guard tests (Phase 828)**: `management/tests/test_css_contrast.py`
  resolves the CSS cascade per colour scheme and asserts readable contrast;
  `management/tests/test_events_backfill.py` asserts the feed paints history on
  connect. Both mutation-checked against the original defects.
