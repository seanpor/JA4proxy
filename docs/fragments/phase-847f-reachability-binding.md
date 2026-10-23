- **Phase 847f — a waiver's reachability claim is now an assertion, not prose.**
  Every `security/waivers.yaml` entry names a registered check in
  `scripts/reachability_checks.py`, and `make reachability-check` (part of
  `lint-static`) executes it against the live compose/source tree. The enum is
  `internal-monitoring-only`, `local-socket-only`, `dev-tooling-only`,
  `not-imported` and `input-path-unreachable`; the last is *attested* and
  requires written evidence, and the renderer rejects an unbound entry or an
  attested one with no evidence. Three premises that were already false were
  found and re-justified rather than deleted: a port-parsing bug that over-split
  interpolated `${VAR:-default}` bindings (fixed in the shared
  `scripts/compose_exposure.py`; the 152-finding MEDIUM count was unchanged, but
  "published surfaces" corrected from 51 to 1), `CVE-2026-103111` moved to
  `input-path-unreachable` with written evidence because haproxy really does
  publish on 443/80, and `local-socket-only` tightened to mean "no published
  port at all".
- **A 37th waiver, authored mid-phase, exposed a vacuous-pass hole.** The new
  OpenTelemetry `tracestate` DoS (`CVE-2026-114603`, `opentelemetry-api~=1.37.0`
  pinned inside `semgrep`, fix 1.45.1 unresolvable) had to be waived
  `not-imported` — and that claim was passing *vacuously*, because the
  distribution's import root is the namespace `opentelemetry`, which the check
  never looked for. `IMPORT_ALIASES` now maps it and every hyphenated
  distribution's underscore form is tried, so the claim fails if it should.
  (The registry is 21 entries at the programme's close-out — 847g removed ten
  image waivers its bumps made dead, and the close-out removed seven pip waivers
  whose fix had already been adopted. The checks run over whatever is in the
  file.)
