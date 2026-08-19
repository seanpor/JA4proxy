- **Connection events now carry the decision's explanation (Phase 828a)**: the
  pipeline has always computed `PipelineResult.Signals` — every contributing
  signal with the human-readable `Reason` its scoring module wrote — and
  `Counterfactuals`, the action the same connection would have received at other
  dial settings. Neither had ever left the process; the event carried
  `event.risk_score`, a single integer. Events now include `ja4proxy.signals`
  and `ja4proxy.counterfactuals`, so the console can say *why* a connection
  scored what it did instead of only *what* it scored.
- **Counterfactuals are computed at every dial (Phase 828a)**: they were gated
  on `dial == 0` ("for monitor-mode logging"), so the data was absent in exactly
  the enforcing deployments where "what would I catch at 100" and "what would I
  stop blocking at 50" are the live questions. Removing the gate costs 259ns/op
  with zero allocations.
- **Both payloads are bounded (Phase 828a)**: at most 20 signals per event, each
  reason at most 200 runes, truncated rune-wise so a multi-byte character is
  never split. A misbehaving scoring module cannot inflate every event on the
  stream. Signals for a bypassed connection marshal as an explicit `null` —
  "the scorer never ran" and "the scorer ran and found nothing" stay
  distinguishable, with `ja4proxy.bypass_reason` explaining the first.
- **`scripts/demo-scan.py` sets a TLS 1.2 floor (Phase 828a)**: closes CodeQL
  alert #105 (`py/insecure-protocol`) as fixed rather than dismissed.
  Empirically confirmed not to change the fingerprint the script produces —
  the JA4 is `t13d051100_c96ac5133cd7_8e6e362c5eac` before and after — because
  JA4 encodes the highest offered version and hashes extension types, neither
  of which a minimum-version floor touches.
