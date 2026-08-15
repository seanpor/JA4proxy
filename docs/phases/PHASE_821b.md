# Phase 821b — The remaining console panels (Prometheus tiles only)

> **Status:** PROPOSED (2026-08-15, rewritten after second expert review)
> **Size:** MEDIUM
> **Dependencies:** 821a
> **Branch:** `phase-821b-console-panels`

---

## Goal

Add the remaining console panels on the 821a foundation, so no routine
operational question requires opening Grafana, Prometheus, or `docker logs`.

**Scope narrowed after review.** The previous draft bundled four unrelated
blast radii. Three are now extracted (see §Extracted work) because each changes
behaviour for existing users and needs its own review:

| Kept here | Extracted |
|---|---|
| Four Prometheus panels + the Panel 1 browser tile | `connections.py` unbounded-read fix → **own security PR** |
| | Partials RBAC model → **821d** |
| | Deployed alert-rule fixes → **821e** |

---

## What the second review corrected

The first rewrite still contained defects that would have shipped a console
that misleads. All verified against source:

| Defect | Reality | Evidence |
|---|---|---|
| Panel 5 tile on `ja4proxy_dial_changes_total` | **never incremented anywhere** — renders a confident false "0 changes in 24h" forever | defined `metrics.go:26`, registered `:452`, zero `.Inc()` in the repo |
| Panics tile used `increase(a) + increase(b)` | `+` across an absent operand yields empty → `or vector(0)` → **"0 panics" during a panic storm**. Violates 821a's own stated rule | `metrics.go:47-51`, rule at `821a:167-171` |
| Browser tile as a percentage | corpus holds **12 unique fingerprints** (30 lines, deduped) → denominator ~0 → renders "0% of browsers harmed" | `fixtures/ti_feeds/ja4_fp_corpus.txt` |
| Browser tile at stock config | `Decide()` returns `"allow"` when `dial == 0` — **no score-derived punitive action is reachable at the shipped default** | `internal/security/action_decider.go:67-69` |
| Bare `ja4proxy_dial_current` | `Set()` called at **one site**, inside a 60s ticker — reads 0 for the first minute after every start, and 0 on any Redis error | `cmd/ja4pd/main.go:2023`, `internal/redis/client.go:305-333` |
| `histogram_quantile` for p50/p95 | `prometheus.DefBuckets` with p50 <5 ms — everything sits in `le="0.005"`; quantiles interpolate meaninglessly | `metrics.go:123-129`, `SERVICE_TARGETS.md:38` |
| TLS cert expiry "as age" | gauge stays **0** when `certPath == ""`, which is normal for a passthrough proxy → `time() - 0` = **"expired 56 years ago"** | `cmd/ja4pd/main.go:1953-1956` |
| "No dashboard reflects the asymmetry today" | `threat_posture_partial` already computes a per-action distribution with percentages | `partials.py:657-664` |

**The most important correction is structural:** 821a's regression test #1
validates catalogue entries against metric *definitions*. `dial_changes_total`
is defined, so test #1 would have **passed a permanently-dead tile**. Test #1
is amended below.

---

## Panel 1 — Am I hurting real users?

### Fold into the existing partial — do not add a fourth stream scan

`threat_posture_partial` (`partials.py:549-682`) **already** reads
`events:connection`, parses the same `event` JSON field, computes `ja4_counts`
(`:610`) and `action_pct` (`:657`), and already labels fingerprints via the
corpus (`_corpus_label`, `:648`).

Critically, it bounds the read **better** than the previous draft proposed:

```python
raw = await redis.xrevrange(_STREAM_KEY, max="+", min=min_id, count=5000)   # :584
```

`_window_min_id()` (`:543`) builds a stream ID from wall-clock, so the read is
bounded on **time and volume**. The previous draft's `xrevrange(count=N)` had no
`min` — strictly worse, and it then papered over the resulting ambiguity with a
"derived span" display.

**Add the browser cross-reference inside that existing single scan.** It already
iterates every event and has the JA4 in hand. A separate scan would mean a
fourth 5000-event pass, and with `--workers 1` (`Dockerfile.management:45`) each
pass is a synchronous event-loop stall — ~5000 `json.loads` blocking every other
API request.

Use `_CORPUS.__contains__` directly in the loop rather than the `@lru_cache`d
`is_known_browser` (`ja4_corpus.py:51`, maxsize 10000): attacker-supplied JA4
diversity churns that cache to uselessness across a 5000-event scan.

### The tile renders counts, never a bare percentage

Of events in the window whose JA4 is in the corpus, how many received a punitive
action (`block`, `ban`, `tarpit`, `rate_limit`):

> **3 punitive of 41 corpus-browser connections** · corpus: 12 fingerprints
> (updated 2026-06-29) · dial: 0

Three display rules, all mandatory:

1. **Absolute numerator and denominator, not a ratio.** With a 12-fingerprint
   corpus the denominator is routinely single-digit; `1/1` renders as 100% and
   `0/2` as 0%, both meaningless.
2. **Suppress any ratio below a denominator floor** (n < 30) and say
   *"insufficient browser-classified sample"*.
3. **Show `corpus_size()`** (already exported, `ja4_corpus.py:62`), the corpus
   file mtime, **and the current dial** beside it — with the caption that **at
   dial=0 only dial-independent hard blocks are reachable**, so a low number may
   mean "nothing is being enforced" rather than "no harm done".

Without rule 3 this tile reads backwards: an operator concludes "we are not
hurting real users" from a measurement structurally incapable of detecting it.
That is the exact CLAUDE.md-asymmetry failure the panel exists to prevent.

### Other Panel 1 tiles

| Tile | Expression |
|---|---|
| JA4 whitelist share | `sum(rate(ja4proxy_bypass_total{rule=~"ja4_whitelist.*"}[5m])) / sum(rate(ja4proxy_connections_total[5m]))` |
| Bypasses by rule | `sum by (rule) (rate(ja4proxy_bypass_total[5m]))` |
| TLS/JA4 mismatch | `sum(rate(ja4proxy_ja4_tls_mismatch_total[5m])) or vector(0)` |

`{rule=~"ja4_whitelist.*"}` matches `ja4_whitelist` and `ja4_whitelist_pattern`
(`pipeline.go:895,900`) and correctly does **not** match `ja4x_whitelist` —
PromQL regexes are fully anchored. The whitelist tile is a **ratio**; the
previous draft rendered a bare per-second rate under a "rate" label.

### Risk-score distribution — `(70, 85]`, not `[70, 85)`

Prometheus buckets are `le` upper bounds. With `{0,10,25,40,55,70,85,100}`
(`metrics.go:20`), `bucket{le="85"} - bucket{le="70"}` is **`(70, 85]`** — it
*excludes* score exactly 70, which is the block cut itself (`Decide` uses
`score >= threshold`), and *includes* 85, the ban cut.

Caption: *"above the block cut, at or below the ban cut"*. The FP-visibility
claim stays dropped — the bucket is 15 wide, thresholds are hot-reloadable while
buckets are compiled in, and `Observe()` runs on every connection including
bypasses and hard blocks (`main.go:646`).

---

## Panel 2 — What is it deciding?

| Tile | Expression |
|---|---|
| By action | `sum by (action) (rate(ja4proxy_connections_total[5m]))` |
| Bypasses by rule | `sum by (rule) (rate(ja4proxy_bypass_total[5m]))` |
| Tarpit | `sum(ja4proxy_tarpit_concurrent)` |
| **Dial** | see below |

`connections_total` is the **only** metric safe from cold start — all six action
label values are pre-initialised (`metrics.go:493-495`).

**The dial tile needs three expressions, not one.** It is per-instance, the
architecture is explicitly `JA4proxy ×N`, and a partial rollout must be visible:

```promql
max(ja4proxy_dial_current)                        # highest enforcing replica
min(ja4proxy_dial_current)                        # lowest
count(count by (instance) (ja4proxy_dial_current))  # fleet size
```

Annotate: **value is up to 60s stale** (set only in the integrity worker's
ticker, `main.go:2023`) and **0 may mean "Redis unreachable"** — `GetDial`
returns 0 on missing key, Redis error, or invalid signature
(`client.go:305-333`). Read the authoritative value from Redis via the existing
`_get_dial()` (`partials.py:110`); use the metric only as the fleet cross-check.

`ja4proxy_tarpit_concurrent` duplicates `tarpit:active_count` already rendered
by `infrastructure_partial` (`partials.py:770-776`) — one per-process, one
global. **Pick one** and delete the other, or they will disagree.

---

## Panel 3 — Is it alive and keeping up?

| Tile | Expression |
|---|---|
| Active connections | `sum(ja4proxy_active_connections)` |
| **Panics (24h)** | `sum(increase({__name__=~"ja4proxy_(handler\|health_check)_panics_total"}[24h])) or vector(0)` |
| Connection errors | `sum(rate(ja4proxy_connection_errors_total[5m])) or vector(0)` |
| Redis health | `min(ja4proxy_redis_health{status="ok"})` |
| Redis evictions | existing Redis path — evicting a `ban:` key is silent policy loss |
| Latency p99 | `histogram_quantile(0.99, sum by (le) (rate(ja4proxy_pipeline_duration_seconds_bucket[5m])))` |
| Latency p50 | bucket fraction, **not** a quantile — see below |
| Cert expiry | gated on `> 0` — see below |

**Panics use the `__name__` regex form.** A binary `+` between two selectors
fails *green*: a handler panic with no health-check panic leaves one operand
absent, `+` yields empty, `or vector(0)` renders a confident **0** during the
incident. This is why the lint rule below bans `+` between selectors outright.

**Latency: p99 only as a quantile.** `prometheus.DefBuckets` with a p50 under
5 ms (`SERVICE_TARGETS.md:38`) puts nearly all mass in `le="0.005"`, so p50 and
p95 interpolate to near-identical meaningless values. The repo already knows
this — `slo_recording_rules.yml:76-102` deliberately uses bucket-fraction ratios
and names DefBuckets in a comment. Render p50 as the `le="0.005"` fraction and
caption that the histogram resolves nothing finer than 5 ms. Note `sum by (le)`
is required or an N-replica fleet yields per-instance quantiles.

**Cert expiry must be gated on `> 0`.** `updateTLSCertExpiryGauge` returns early
when `certPath == ""` (`main.go:1953-1956`), which is normal for a passthrough
proxy that does not terminate TLS — so the gauge sits at 0 and `time() - 0`
renders **"expired 56 years ago"** on every stock deployment. Render "not
configured (passthrough)" at exactly 0. Do not compute an age from 0. The
gauge is *also* forced to 0 on read/parse failure by design (`main.go:1959-1971`),
so the tile must not conflate the two — check configured cert path before
declaring "not configured".

---

## Panel 5 — What changed?

**`ja4proxy_dial_changes_total` is deleted from this panel.** It is defined and
registered but **never incremented**, so it exports a permanent `0` — a tile
that answers "did someone change the dial?" with a confident, wrong "no".

Dial-change history comes from `management:policy_audit`, which genuinely
records changes. Remaining tiles: `ja4proxy_config_reloads_total`,
`ja4proxy_config_reload_failures_total`, `ja4proxy_signal_drift_total`.

> Either fix the Go side to increment `DialChangesTotal` at the dial-write path,
> or delete the dead metric. Out of scope here; raise as a follow-up.

---

## Firing alerts

Read `/api/v1/alerts`. Render `labels.alertname`, `state`, `activeAt`,
`annotations.summary`. **Do not surface rule `expr`.**

**Caveat the previous draft got wrong:** a field allowlist is *not* the control
it appears to be, because `annotations.summary` is a server-rendered Go template
that interpolates the very labels being withheld — e.g. `alerts.yml:737`,
*"Dial divergence detected at DC {{ $labels.dc_id }}"*, which is posture data
inside the field called safe. Treat summary text as label-bearing. The alerts
panel therefore inherits whatever role floor 821d sets for posture tiles.

Confirm Jinja autoescape is on for these templates — annotation text reaches an
HTML partial and interpolates scrape-target-derived values.

---

## Test strategy

821a's four regression tests apply, **with three amendments this phase owns**
because it is the phase that exposes each gap:

**Amendment 1 — emission-site check (catches the `dial_changes_total` class).**
Test #1 validates against metric *definitions*, so a defined-but-never-emitted
metric passes. Extend it: every catalogued metric must have ≥1 emission site
(`.Inc()`, `.Set()`, `.Observe()`, `.WithLabelValues(...)`) **outside**
`internal/metrics/`. A grep found exactly one dead metric among those 821b
uses; the check is cheap and its payoff is already proven.

**Amendment 2 — `_bucket`/`_sum`/`_count` suffixes.** Histogram series carry
suffixes generated by the client library and never written in Go source, so
`ja4proxy_pipeline_duration_seconds_bucket` would **fail** test #1 despite being
correct. Strip the suffix before resolution, and require `sum by (le)` on any
`histogram_quantile`.

**Amendment 3 — `or vector(0)` opt-out for by-label tiles.** 821a test #4
requires `or vector(0)` on every counter tile. On `sum by (rule) (...)` that
appends a bogus unlabelled series. Add a catalogue field
(`renders_empty_as_no_rows: true`) and exempt those entries.

**New lint rule:** no tile expression may contain a binary `+` between two
metric selectors. The plan stated this principle and then violated it in the
same document; only a lint rule will hold it.

Plus: Panel 1 browser-classification correctness against seeded corpus and
non-corpus JA4s; denominator-floor suppression; `Empty` vs `Unavailable`;
`test_pages.py` for every new route.

---

## Acceptance criteria

1. All panels render live; absent series render a real zero, not "unavailable".
2. No tile references a metric that is never emitted — enforced by amendment 1.
3. No tile expression contains a binary `+` between selectors.
4. Panel 1 renders counts with corpus size, corpus mtime, and dial beside them,
   and suppresses the ratio below n=30.
5. Cert-expiry renders "not configured" at 0, never an age.
6. Dial renders max/min/fleet-count with the staleness and Redis-fallback
   caveats.
7. Per-instance metrics are explicitly aggregated.
8. 821a tests #1 and #4 are amended and still pass.
9. `make lint`, `make test`, `make scan` clean.

---

## Extracted work — must not be folded back in

**1. `connections.py` unbounded reads → its own security PR, landed first.**
`management/api/routes/connections.py:144,213,266` call
`redis.xrange(_STREAM_KEY)` with no bound against a 100k-entry stream. The
existing pin (`test_pentest_dsar_bounded_xrange_regression.py:81`) asserts one
*literal source string* in `compliance.py` only.

The naive fix is wrong twice over: `xrange` is **ascending**, so adding `count=`
returns the **oldest** N entries — `get_fingerprint_detail` would 404 on live
fingerprints (`connections.py:241-244`). And `:144` is a documented paginated
endpoint with `_MAX_LIMIT = 10_000` (`:52`), which a `count=5000` bound cannot
satisfy; truncation would make `has_more` and `total_in_window` lie on a
compliance-facing export path. The applicable precedent is
`_iter_dsar_stream_batches` — a cursor-advancing batched read — not truncation.
Extend the pin to a regex over `management/api/routes/*.py`.

**2. Partials RBAC → 821d.** `require_role` is a **route** dependency and **no
partial uses it** (0 occurrences in `partials.py`). There is no per-tile
authorisation mechanism. Worse, gating new tiles is cosmetic while
`/api/v1/partials/dial` (`:218`), `/bans` (`:294`) and `/threat-posture`
(`:549`) already serve dial value and full action distribution to any
authenticated user. And a 403 on a polled htmx partial does not render an
error — htmx does not swap non-2xx, so the region silently freezes.
821d must decide the enforcement unit (split partials by role, or per-tile
suppression in Jinja using the `role` already passed into template context at
`:668,785`) **and** gate the three existing routes.

**3. Deployed alert-rule fixes → 821e.** The "never worked" blind spot in
`SpamhausListStale` is real, and the rule is **defined twice in two loaded
files** — `prometheus.yml:20,29` loads both `alerts.yml:127-132` and
`security.rules.yml:22-26`, same group name, same expr. Fixing both without
deleting one duplicate makes `/api/v1/alerts` return it twice. This edits
deployed paging config and belongs with the other alert work.

---

## Out of scope

- The ~64 diagnostic metrics — a drill-down page.
- Removing Grafana / Alertmanager — only after this phase proves coverage.
- Fixing `DialChangesTotal` in Go, or adding finer risk-score buckets.
