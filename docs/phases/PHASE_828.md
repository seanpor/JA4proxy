<!--
title: Operator_Console_Decision_Support
audience: developer
last_reviewed: 2026-08-18
phase: 828
-->

# Phase 828 — Tell John what we already know

**Status:** PROPOSED
**Depends on:** 826 (Intelligence pipeline), 827 (ASN/geo provenance reaching the event)

## Who this is for

John is the operator. He opens the console because something is happening, or
because someone asked him whether something is happening. He is not a TLS
researcher. He knows what CGNAT is — he knows that one Irish mobile IP can carry
a few hundred real subscribers — which is exactly why he will not ban an IP just
because the console shows him a big red number.

John's job is to make a decision he can defend afterwards. The console's job is
to give him what he needs to make it. Today it mostly gives him a number.

## The finding

**The proxy knows far more than the console shows, and the gap is not small.**

Two concrete, measured examples.

### 1. The decision explanation is computed and thrown away

`internal/security/models.go:66-76`:

```go
type PipelineResult struct {
	Action          string
	Bypassed        bool
	BypassReason    string
	Score           int
	Signals         []RiskSignal        // <- every contributing signal
	Dial            int
	Counterfactuals map[int]string      // <- what would happen at other dials
}
```

and `RiskSignal` (`models.go:9-21`) carries `Name`, `Score`, `Weight` and
**`Reason` — a human-readable explanation**, written by the module that scored
it.

`cmd/ja4pd/main.go:717-753` emits `"event.risk_score": result.Score`. One
integer. `Signals` and `Counterfactuals` are never serialised, never reach
Redis, and cannot reach the console.

So the proxy computes precisely the sentence John needs — *"this scored 100
because X, Y and Z"* — and discards it microseconds later. The console then
shows him `100` and he is on his own.

`Counterfactuals` is computed at `pipeline.go:843` for dials 25/50/75/100. That
is literally "what would this connection's fate be if you moved the dial" —
the question every operator asks before touching it — and it is dropped too.

### 2. The live feed discards two thirds of each event

A real entry from the running stack (`events:connection`, 54,790 entries):

```json
{"@timestamp":"2026-08-18T15:53:22.660500326Z","client.as.number":0,
 "client.as.organization.name":"","client.geo.country_iso":"",
 "destination.ip":"backend","destination.port":443,"event.action":"block",
 "event.risk_score":100,"ja4proxy.alpn":"","ja4proxy.bypass_reason":"ja4_blacklist",
 "ja4proxy.dial_setting":58,"ja4proxy.fingerprint.ja4":"t13d051100_c96ac5133cd7_8e6e362c5eac",
 "ja4proxy.sni":"scan.local","ja4proxy.tls_version":771,"source.ip":"172.25.200.54",
 "source.port":50183, ...}
```

`_build_row` (`management/api/routes/events.py:44`) renders five of these:
time, IP, JA4, action, score.

Dropped on the floor, per row:

| Field | What John loses |
|---|---|
| `ja4proxy.bypass_reason` | **The actual reason for the decision.** This row says `ja4_blacklist` — it was blocked by an explicit list entry, not by a score at all. The UI shows "block / 100" and implies the scorer decided. |
| `client.as.organization.name` | Vodafone Ireland, or Chinanet. |
| `client.geo.country_iso` | IE or CN. |
| `ja4proxy.sni` | What they asked for. |
| `ja4proxy.alpn` | Browser-shaped or not. |
| `ja4t` / `ja4x` | TCP and certificate fingerprints. |

The `bypass_reason` one matters most: a blocked-by-list connection and a
blocked-by-score connection look identical in the feed, and they call for
opposite responses. If it was a list entry, the interesting question is "who
added that and when". If it was a score, it is "which signals fired".

### 3. "How many times has this signature been seen at this IP?" has no answer

Neither endpoint can answer it:

- `/api/v1/fingerprints/{ja4}/profile` → totals per fingerprint, across all IPs
- `/api/v1/ip/{ip}/profile` → totals per IP, across all fingerprints

Nothing joins the two. Yet this is the question that separates the two cases
John actually cares about:

- *one* fingerprint seen *thousands* of times at *one* IP → one automated client
- *many* fingerprints at one IP, each a handful of times → **CGNAT, real people**

John already reasons this way. The console cannot show him the input.

### 4. "Unknown" hides three different situations

For `172.25.200.54` the geo/ASN fields come back empty and the UI renders
`Unknown`. That single label currently covers:

1. RFC1918 / CGNAT-internal address — **no owner exists**, the honest answer
2. MaxMind database absent — a fixable ops problem (runbook exists, phase 827)
3. Lookup ran and found nothing — genuinely unallocated space

These lead to different actions. Collapsing them into one word means John cannot
tell "there is nothing to know" from "we failed to look".

### 5. Nothing suggests an action, or shows what it would cost

The console offers **Block** and **Ban** buttons on every feed row. It never
says which one it would pick, why, or what the blast radius is. Banning a CGNAT
egress IP is one click, and the UI presents it with exactly the same weight as
banning a dedicated scanner.

### 6. The profile endpoints scan the entire stream per page load

`connections.py:254` calls `redis.xrange(_STREAM_KEY)` unbounded. The live
response reports `"scanned_events": 54790` for one fingerprint page. It is fine
today and will not be at ten million.

## Already fixed on this branch (reported defects, not phase work)

These were user-reported breakages fixed directly; listed so the phase scope is
unambiguous.

- **Black-on-black input text.** `custom.css` overrode `.glass-input` fully
  inside `@media (prefers-color-scheme: light)` but overrode
  `.glass-input:focus` for `border-color` only. The base `:focus` rule's
  near-black `background` survived while the light block's dark `color`
  applied — **contrast 1.04:1** while typing. It affected every input in the
  app, including the login form's username and password fields.
  Guarded by `management/tests/test_css_contrast.py`.
- **Live feed showed permanent grey placeholder bars.** The SSE generator
  started at `"$"` (live-only) and nothing ever removed the five
  `animate-pulse` skeleton rows. With 54,790 events in the stream and no
  traffic in flight, the feed was five pulsing bars, indefinitely. Now
  backfills 25 rows and clears the skeletons; an empty stream says so in words.
  Guarded by `management/tests/test_events_backfill.py`.

## Scope

### 828a — Emit what the proxy already knows (Go) — **DONE**

Add to the event written at `cmd/ja4pd/main.go:717`:

- `ja4proxy.signals` — array of `{name, score, weight, reason}` from
  `result.Signals`
- `ja4proxy.counterfactuals` — the `{dial: action}` map from
  `result.Counterfactuals`

Constraints:

- **Hot path stays untouched.** The event is already marshalled and XADDed
  fire-and-forget; this adds fields to an existing payload and must add no
  synchronous work.
- **Bounded.** Cap at 20 signals and truncate `reason` at 200 chars — a
  malformed module must not be able to inflate every event unboundedly.
- Bypassed connections carry `Signals: nil`; `bypass_reason` already explains
  those, and the schema must tolerate the empty case.

**Landed.** `internal/security/event_payload.go` builds both payloads under
hard caps; `cmd/ja4pd/main.go` emits `ja4proxy.signals` and
`ja4proxy.counterfactuals`. Verified on the live stack at dial 75:

```
action: allow | score: 35 | dial: 75
WHY THIS SCORE:
  ja4_tls_mismatch    35  JA4 prefix "t13" claims TLS 0x0304; negotiated 0x0303
WHAT IF THE DIAL MOVED:
  dial  25 -> allow      dial  75 -> allow
  dial  50 -> allow      dial 100 -> rate_limit
```

One change beyond "emit what already exists": counterfactuals were gated on
`dial == 0`, so they were absent in every enforcing deployment — precisely where
the question is asked. Gate removed; measured at 259ns/op, zero allocations.

**Known limitation, carried into 828b.** `Pipeline.Process` is asynchronous in
production (`Sync=false`): it enqueues to `workChan` and returns a stub
`{Action: "allow", Score: 0}`, and the event is marshalled from that stub. The
real scoring happens on a worker goroutine afterwards. So the **first**
connection for a given `(IP, JA4)` pair emits an event with score 0 and no
signals; every subsequent connection hits the decision cache and carries the
full result. This is pre-existing behaviour, not introduced here — the same
ordering trap that hid ASN provenance in phase 827 — but it caps what 828b can
display and needs deciding before the console promises an explanation for
every row.

### 828b — Show it (Python/console)

- Feed rows gain `bypass_reason`, country and ASN org as columns; SNI and ALPN
  behind a per-row expander.
- Fingerprint and IP pages gain a **"Why this score"** panel listing each
  signal, its contribution and its reason, ordered by absolute contribution.
- A **"What if"** strip showing the counterfactual action at dial 25/50/75/100,
  with the current dial marked.

### 828c — Answer the CGNAT question

- New `GET /api/v1/ip/{ip}/fingerprints` → per-`(ip, ja4)` counts, first seen,
  last seen, action breakdown.
- Both detail pages render it as a table.
- A derived, explicitly-labelled **shape** verdict:
  - one fingerprint ≥90% of that IP's events → `single-client`
  - ≥8 distinct fingerprints, none above 40% → `shared-egress (CGNAT-like)`
  - otherwise → `mixed`

The verdict is a **description of observed distribution**, never a
recommendation to block, and the UI must label it as such.

### 828d — Honest unknowns and a suggested action

- Replace `Unknown` with a resolution status: `not-routable` (RFC1918/CGNAT
  range), `lookup-failed` (DB absent — link the phase-827 runbook), or
  `unallocated`.
- A suggested action per fingerprint/IP with a one-line rationale and an
  explicit blast radius ("this IP carried 47 distinct fingerprints in 24h —
  banning it is likely to affect real users").
- Suggestions are advisory. **No suggestion may auto-apply**, and every one
  must state what it is inferring from.

## Testable outcomes

Each has a test named in the next section.

| # | Outcome | How it is measured |
|---|---|---|
| O1 | Every non-bypassed event carries a non-empty `ja4proxy.signals` array | Go test asserts the marshalled event contains one entry per `result.Signals` entry |
| O2 | Signal reasons survive to the console verbatim | Round-trip: pipeline → JSON → endpoint response |
| O3 | Adding signals does not slow the hot path | Benchmark: p99 of `Process()` within 5% of the pre-change baseline |
| O4 | A malformed module cannot inflate an event | 500 signals with 10KB reasons → event stays under the cap |
| O5 | `bypass_reason` is visible on every feed row that has one | Row-builder test asserts the string is present in the HTML |
| O6 | `(ip, ja4)` counts are correct | Endpoint test against a seeded stream with a known distribution |
| O7 | CGNAT shape is classified as shared-egress, not single-client | 25 fingerprints × 3 events on one IP → `shared-egress` |
| O8 | A real scanner is classified as single-client | 1 fingerprint × 400 events on one IP → `single-client` |
| O9 | Empty geo is disambiguated | RFC1918 → `not-routable`; DB absent → `lookup-failed`; the two are never the same string |
| O10 | Every suggestion states its blast radius | Endpoint test asserts a distinct-fingerprint count accompanies any ban suggestion |
| O11 | No suggestion auto-applies | Test asserts the suggestion endpoint is GET-only and mutates nothing |
| O12 | The profile scan is bounded | `scanned_events` never exceeds the configured cap on a 200k-entry stream |

## Tests

**Go — `internal/security/event_payload_test.go`**

- `TestEventCarriesSignalBreakdown` (O1) — build a result with three signals,
  marshal the event, assert all three names, scores and reasons are present.
- `TestEventCarriesCounterfactuals` (O1) — the four dial keys are present.
- `TestBypassedConnectionOmitsSignalsCleanly` (O1) — no signals, no crash, no
  `"signals": null` string in the payload.
- `TestSignalPayloadIsBounded` (O4) — 500 signals with 10KB reasons; assert
  ≤20 entries and each reason ≤200 chars.
- `BenchmarkProcessWithSignalPayload` (O3) — compared against the recorded
  baseline in the phase notes; **fails the gate if p99 regresses >5%**.

**Python — `management/tests/test_signal_explanation.py`**

- `test_signals_round_trip_to_the_api` (O2) — seed a stream entry containing a
  signals array; assert the profile endpoint returns each reason verbatim.
- `test_signals_ordered_by_absolute_contribution` (O2) — a −40 signal outranks
  a +5 one; a large negative contribution is as interesting as a large positive.
- `test_missing_signals_degrades_to_score_only` (O2) — an event from an older
  proxy has no `signals` key; the endpoint returns the score and an explicit
  `explanation_available: false` rather than erroring or implying zero signals.

**Python — `management/tests/test_feed_row_completeness.py`**

- `test_row_shows_bypass_reason` (O5).
- `test_row_shows_country_and_asn_org` (O5).
- `test_blocked_by_list_is_distinguishable_from_blocked_by_score` (O5) — the two
  rows must not render identically. This is the finding restated as an
  assertion.

**Python — `management/tests/test_ip_fingerprint_crosstab.py`**

- `test_crosstab_counts_pairs` (O6).
- `test_cgnat_pattern_is_shared_egress` (O7) — 25 fingerprints × 3 events.
- `test_scanner_pattern_is_single_client` (O8) — 1 fingerprint × 400 events.
- `test_shape_verdict_is_labelled_as_description_not_recommendation` (O7/O8) —
  the response carries no `action` field. Encodes the core asymmetry: this
  phase must not create a new path to a false positive.

**Python — `management/tests/test_geo_resolution_status.py`**

- `test_rfc1918_is_not_routable` (O9), `test_missing_db_is_lookup_failed` (O9),
  `test_the_two_statuses_differ` (O9) — a vacuity guard: if a refactor collapses
  both to `"unknown"` the first two could still pass.

**Python — `management/tests/test_suggestions.py`**

- `test_ban_suggestion_states_blast_radius` (O10).
- `test_suggestion_endpoint_is_read_only` (O11) — GET only; POST/PUT/DELETE
  return 405.
- `test_no_suggestion_for_a_shared_egress_ip` (O10) — the CGNAT case must never
  produce a ban suggestion. Directly encodes `CLAUDE.md`'s core asymmetry.

**Python — `management/tests/test_profile_scan_bounded.py`**

- `test_scan_is_capped` (O12) — 200k entries, assert `scanned_events` ≤ cap.
- `test_cap_is_reported_to_the_client` (O12) — `truncated: true` when hit, so
  the console can say "based on the last N events" instead of implying totality.

**Accessibility regression (extends this branch's work)**

- `management/tests/test_css_contrast.py` — extend `CASES` to cover every new
  control class introduced by 828b/c/d. The dial bug reached production because
  no test looked at rendered colour; anything new must be covered from the start.

## Non-goals

- No new signals or detectors. This phase surfaces what exists.
- No auto-remediation. Every suggestion needs a human click.
- No redesign of the dashboard layout.

## Risks

| Risk | Mitigation |
|---|---|
| Event size grows; Redis memory and XADD cost rise | Hard caps (O4); measure stream memory before/after and record it in the phase notes |
| Signal reasons leak internals into an operator-facing UI | Reasons are already written for humans; review all module reason strings once as part of 828a |
| A "shape" verdict gets read as a recommendation | O7/O8 assert no `action` field; UI labels it as an observation |
| Suggestions become de-facto automation | O11 keeps the endpoint read-only |

## Acceptance

- [ ] O1–O12 have passing tests, each mutation-checked to fail when its
      behaviour is removed
- [ ] `make test` and `make lint` pass
- [ ] Hot-path benchmark within 5% of baseline, baseline recorded in
      `PHASE_828_notes.md`
- [ ] A screenshot walkthrough of one blocked connection answering, in the UI
      alone: why it was blocked, who owns the IP, how often that fingerprint has
      been seen there, and what would happen at a different dial
