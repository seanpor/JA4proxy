# Phase 821b — The remaining four console panels

> **Status:** PROPOSED (2026-08-15)
> **Size:** MEDIUM
> **Dependencies:** 821a (client, catalogue, cache, and the four regression tests)
> **Branch:** `phase-821b-console-panels`

---

## Goal

Complete the console as the single operational face by adding the four
remaining panels on the 821a foundation. After this phase, no routine
operational question requires opening Grafana, Prometheus, or `docker logs`.

Every expression below is written in the corrected idiom established by 821a:
verified label names, `or vector(0)` on counters, and no `+` across
possibly-absent series.

---

## Panel 1 — Am I hurting real users?

CLAUDE.md's governing rule is that a blocked real user costs far more than a
missed bot. **No console page or dashboard reflects that today.** This panel is
the phase's moral centre — which is why the review's finding against it matters
so much.

### The headline tile — DECIDED: option (b), the Redis event stream

The withdrawn plan led with *"block rate against browser-shaped traffic"* as a
Prometheus tile. **No metric in `internal/` carries an ALPN, browser, or
user-agent label** — verified across every `[]string{…}` label set. The only
browser-adjacent series is `ja4proxy_bypass_total{rule="alpn_browser"}`, and
that path requires `cfg.ALPNBrowserBypass`, which CLAUDE.md documents as **off
by default** (JA4PROXY-2026-0004). With shipped defaults it is permanently zero.

**Decision (2026-08-15): build it from the `events:connection` Redis stream,
cross-referenced against the JA4 corpus.** This is a second data source with its
own failure modes, so it is specified here rather than improvised.

#### The data exists and carries both halves

`cmd/ja4pd/main.go:689-703` writes an ECS event per connection containing the
fingerprint **and** the decision in the same record:

```go
"event.action":             result.Action     // the decision
"event.risk_score":         result.Score
"ja4proxy.fingerprint.ja4": connCtx.JA4       // the fingerprint
"ja4proxy.sni":             connCtx.SNI
"source.ip":                connCtx.ClientIP
```

XADDed as a single field `event` holding the JSON string
(`cmd/ja4pd/main.go:1310`). `management/api/ja4_corpus.py:52` already exposes
`is_known_browser(ja4) -> bool`, backed by
`fixtures/ti_feeds/ja4_fp_corpus.txt`, and `partials.py:38` already imports from
that module.

**The write is not gated on webhooks being enabled.** `webhooks.enabled` is
`false` by default (`config/proxy.yml:884`), but `main.go:337` assigns
`dispatcher: disp` unconditionally — only the *delivery loop* is gated
(`main.go:148`). The `p.dispatcher != nil` guard at `main.go:688` is therefore
satisfied in normal operation, so the stream is populated with stock config.
This was verified specifically because the tile is worthless if it silently
requires enabling webhooks.

#### The tile

Of recent events whose JA4 is a **positively identified browser**, the fraction
whose `event.action` is punitive (`block`, `ban`, `tarpit`, `rate_limit`).

That is the closest thing this system can compute to "am I hurting real users",
and it has no home anywhere in the product today.

#### Four honesty constraints — all mandatory

**1. It is a lossy sample, and the loss is biased.** Stream writes are dropped
by design when the bounded queue fills (`main.go:1261-1266`,
`ja4proxy_stream_event_drops_total`). Drops correlate with load — so the sample
degrades precisely when the number matters most. **The tile must render the
drop rate beside it**, and must be labelled a sample, never a census.

**2. The window is volume-bounded, not time-bounded.** `XAddErr` sets
`MaxLen: 100000, Approx: true` (`internal/redis/client.go:596`). At high traffic
that is minutes; at low traffic, days. A tile captioned "last 5 minutes" would
be a lie. **Derive the actual span from the `@timestamp` of the oldest event
read and display it** — "N events spanning 4m12s".

**3. This is NOT a false-positive rate, and must not be labelled as one.**
`is_known_browser()` returns false for any JA4 absent from the corpus — which
includes both bots *and* real browsers the corpus does not know. The tile
measures **actions against positively-identified browsers**, a lower bound.
Calling it an FP rate would overclaim in exactly the way the first review
caught elsewhere in this plan. `means`/`when_red` must say so plainly.

**4. Bounded reads only — and there is an existing violation to fix.**
`management/api/routes/connections.py:144,213,266` call
`await redis.xrange(_STREAM_KEY)` **with no count bound**, against a stream
capped at 100,000 entries. That is the identical pattern JA4PROXY-2026-0035
fixed and pinned — but the pin at
`management/tests/test_pentest_dsar_bounded_xrange_regression.py:81` covers
`compliance.py` **only**, so the same class of unbounded read survives in
`connections.py`. The new tile uses `xrevrange(count=N)` (N ≤ 5000, matching
the bounded precedent at `connections.py:308,386`), and **this phase extends
the regression pin to `connections.py` and fixes those three call sites.**

#### Implementation notes

Reuse the 821a cache layer and its three-state result — Redis unreachable →
`Unavailable`; stream present but no browser-classified events → `Empty`
rendering a real zero, not an error. Parse cost is bounded by N and paid once
per TTL window, not once per viewer.

**Follow-up worth noting, deliberately not done here:** the analytics node
already consumes `events:connection`, so this rolling figure could be computed
there and written to a Redis key, making the console read O(1) instead of
O(N events) per window. That is the better long-term shape, but it crosses a
service boundary and should move only once the number is proven correct in one
place first.

### Tiles that are computable now

| Tile | Expression |
|---|---|
| JA4 whitelist hit rate | `sum(rate(ja4proxy_bypass_total{rule=~"ja4_whitelist.*"}[5m])) or vector(0)` |
| Bypasses by rule | `sum by (rule) (rate(ja4proxy_bypass_total[5m]))` |
| TLS/JA4 mismatch | `sum(rate(ja4proxy_ja4_tls_mismatch_total[5m])) or vector(0)` |
| Active bans vs escalations | `ban:*` (Redis) + `ja4proxy_offense_escalations_total` |

**`{rule=~"ja4_whitelist.*"}` is required, not cosmetic.** There are two
distinct whitelist series — `ja4_whitelist` and `ja4_whitelist_pattern` — plus
`ja4x_whitelist`, `mtls`, `static_ip` and `alpn_browser`
(`internal/security/pipeline.go`). An exact-match selector silently
under-counts.

### Risk-score distribution — reframed honestly

`ja4proxy_risk_score` is a **Histogram**, buckets `{0,10,25,40,55,70,85,100}`,
no labels (`internal/metrics/metrics.go:16-22`). Thresholds
(`config/proxy.yml:425-430`): flag 20, rate_limit 35, tarpit 55, block 70,
ban 85.

The withdrawn plan claimed this tile would reveal false positives "in the band
just above the cut". **It cannot.** Three problems:

1. The finest resolution above the block threshold is the **15-wide `[70,85)`
   bucket**. That is not an FP band, it is a quarter of the scale.
2. **Thresholds are hot-reloadable config; buckets are compiled into Go.** An
   operator setting `block: 65` silently decouples the tile from the decision
   it claims to visualise.
3. `RiskScore.Observe()` runs on **every** connection including bypasses and
   hard blocks (`cmd/ja4pd/main.go:644`), where the score is 0 or 100 — so the
   extreme buckets are dominated by connections that were never scored.

**Decision required.** Either:
- **(i)** render it as what it is — *"connections scored in [70,85)"* — and
  drop the FP-visibility claim; or
- **(ii)** add finer buckets around the block threshold in `internal/metrics/`,
  which is a Go hot-path change this phase does not currently budget for, and
  which needs its own cardinality review.

Recommend **(i)** here, and open (ii) separately if the band genuinely matters.
Do not ship the claim without the resolution to back it.

---

## Panel 2 — What is it deciding?

| Tile | Note |
|---|---|
| `sum by (action) (rate(ja4proxy_connections_total[5m]))` | the only pre-initialised metric (`metrics.go:493`), so all six actions render from cold |
| `ja4proxy_dial_current` | gauge |
| `sum by (rule) (rate(ja4proxy_bypass_total[5m]))` | connections that never reached the scorer |
| `ja4proxy_tarpit_concurrent` | gauge |

---

## Panel 3 — Is it alive and keeping up?

| Tile | Expression note |
|---|---|
| `ja4proxy_active_connections` | gauge |
| `ja4proxy_pipeline_duration_seconds` | histogram → p50/p95/p99 via `histogram_quantile` |
| `ja4proxy_connection_errors_total` | `or vector(0)` |
| **Panics (24h)** | `sum(increase(ja4proxy_handler_panics_total[24h]) + increase(ja4proxy_health_check_panics_total[24h])) or vector(0)` |
| `ja4proxy_redis_health{status="ok"}` | **selector required** — GaugeVec `{status}` (`metrics.go:303-309`) |
| Redis `evicted_keys` | existing Redis path; evicting a `ban:` key is silent policy loss |
| `ja4proxy_tls_cert_expiry_timestamp_seconds` | render as age |

**The panics tile carries three corrections.** The withdrawn plan said
`handler_panics_total` "must be 0". That is not expressible as written: the
series does not exist on a healthy proxy (no pre-initialisation); **counters
reset on process restart**, so an instantaneous `== 0` reads clean immediately
after the crash it is meant to catch; and `ja4proxy_health_check_panics_total`
(`metrics.go:46-48`) is a second panic counter the plan omitted entirely. The
`increase(...[24h])` form survives restarts. The existing rule at
`deploy/monitoring/alertmanager/rules/security.rules.yml:48-52` already uses a
rate form — reuse that idiom rather than inventing a worse one.

---

## Panel 5 — What changed?

`ja4proxy_dial_current` + `increase(ja4proxy_dial_changes_total[24h])`,
`ja4proxy_config_reloads_total`, `ja4proxy_config_reload_failures_total`,
`ja4proxy_signal_drift_total`, and the existing `management:policy_audit` trail.

---

## Firing alerts — render fields, not payloads

Read Prometheus `/api/v1/alerts` and `/api/v1/rules`. **Alertmanager is only
needed to route alerts outward** (email, Slack, pager); seeing them does not
require it.

**Whitelist the fields rendered** — `labels.alertname`, `state`, `activeAt`,
`annotations.summary`. **Do not surface rule `expr`.** `/api/v1/rules` returns
the complete PromQL of every alerting and recording rule, and `/api/v1/alerts`
returns full label sets including `instance`, `job`, and the `service`/`role`
labels injected at `prometheus.yml:40-42,58-60`. 821a's stated reason for
banning client PromQL is "read access to every series regardless of role";
passing the rule corpus through to the same audience is not that hole, but it
is the same class, and the withdrawn plan did not acknowledge it.

### Fix the alert blind spots in the same idiom

`alerts.yml:132` / `security.rules.yml:26` carry the **identical never-worked
blind spot** as the blocklist tile 821a corrects: a feed that has never
succeeded has no series, so the alert cannot fire. Fix here, in the corrected
form, while the idiom is fresh.

---

## Test strategy

All four 821a regression tests apply unchanged and now cover ~25 tiles instead
of one — in particular, test #1's label-name and label-value checking, which is
what catches the `{reason=}` class of error.

Additional: `histogram_quantile` expressions validated against actual bucket
definitions; `test_pages.py` covers every new route.

**Panel 1 browser tile — its own test set**, since it uses a different data
source with different failure modes:

1. **Bounded-read pin extended to `connections.py`** — assert no
   `redis.xrange(_STREAM_KEY)` without a count bound anywhere in
   `management/api/routes/`, not just `compliance.py`. This must fail against
   today's `connections.py:144,213,266` before those are fixed, proving the
   test works.
2. **Classification correctness** — seeded events with corpus and non-corpus
   JA4s produce the expected numerator and denominator.
3. **Empty vs Unavailable** — a stream with zero browser events renders `0`;
   Redis down renders "unavailable".
4. **Window honesty** — the displayed span is derived from actual event
   `@timestamp`s, not hardcoded.
5. **Drop-rate companion is present** — the tile cannot render without it.

---

## Acceptance criteria

1. All five panels render live; every tile shows a real zero rather than
   "unavailable" when its series is legitimately absent.
2. Every routine operational question is answerable without leaving the console.
3. No tile references a metric, label name, or label value absent from
   `internal/` — enforced by test #1, not by review.
4. Firing alerts appear; no rule `expr` is exposed.
5. The Panel 1 browser tile renders with its drop-rate companion, its derived
   window span, and wording that does not claim to be a false-positive rate.
6. `connections.py`'s three unbounded `xrange` calls are fixed and the
   regression pin covers `management/api/routes/`, not just `compliance.py`.
7. The risk-score framing decision is recorded in the phase notes.
8. `make lint`, `make test`, `make scan` clean.

---

## Out of scope

- Prometheus hardening → **821c**
- The ~64 diagnostic metrics (tap internals, backup/restore, multi-DC sync) —
  a drill-down page, not the front page.
- Removing Grafana / Alertmanager — only after this phase proves coverage.
- Adding finer risk-score buckets in Go (option (ii) above), if chosen.
