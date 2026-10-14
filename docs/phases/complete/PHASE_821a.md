# Phase 821a — Prometheus client, metric catalogue, and one panel end to end

> **Status:** PROPOSED (2026-08-15)
> **Size:** MEDIUM
> **Dependencies:** none (see §Sequencing — the 820 coupling is a shared test, not an ordering)
> **Branch:** `phase-821a-console-metrics-foundation`
> **Supersedes:** the monolithic `PHASE_821.md`, withdrawn after expert review

---

## Goal

Build the foundation that makes the management console the single operational
face over Prometheus: a query client, a declarative metric catalogue, four
regression tests, and **exactly one panel wired end to end**.

One panel — not five — because the first review of the monolithic plan found
**five wrong PromQL expressions and two wrong dependency choices** in a plan
that read as confident. Those faults are only discoverable by rendering real
tiles against a real proxy. This phase is deliberately shaped to surface them
cheaply, before the other four panels are written on top of the same mistakes.

---

## What the review corrected (retained so it is not re-litigated)

The withdrawn plan asserted things that are false against the code:

| Claim | Reality | Evidence |
|---|---|---|
| `ja4proxy_bypass_total{reason=…}` | label is **`rule`** | `internal/metrics/metrics.go:52-55` |
| "94 metrics" | **89** | `grep -ohE '"ja4proxy_[a-z0-9_]+"' internal/ \| sort -u \| wc -l` |
| use `aiohttp` | **unused anywhere** in `management/`; `httpx` is the pattern | `management/api/routes/oidc.py:46`; zero `aiohttp` hits in `management/**/*.py` |
| blocklist staleness is a scalar | **GaugeVec** labelled `feed` | `internal/metrics/metrics.go:145-148` |
| seven drop counters | **eight** | `ja4proxy_audit_jobs_dropped_total`, `metrics.go:262-267` |
| `auditor` role restricts tiles | `auditor` is the role **floor** — a no-op | `management/api/auth.py:512-517` |
| risk-score histogram resolves the FP band | coarsest bucket above the block cut is **15 wide** | `metrics.go:16-22` |

The `{reason=…}` error is the decisive one: it is **the same dead-selector bug
Phase 820 exists to fix**, reproduced inside the plan that claimed to prevent
it. That is the strongest possible argument for regression test #1 below, and
for shipping one panel before five.

---

## Design

### HTTP client — `httpx`, not `aiohttp`

`management/requirements.txt:36` carries `aiohttp==3.14.3`, commented
*"phase-234: Prometheus HTTP API query for infra row"*. **No Python file in
`management/` imports it** — Phase 234 added it for this job and never used it.
The established outbound-HTTP pattern is `httpx` (`oidc.py:46,181,283`).

```python
httpx.AsyncClient(timeout=2.0, follow_redirects=False)
```

`follow_redirects=False` is load-bearing, not stylistic: **aiohttp follows
redirects by default; httpx does not.** A redirect-following client aimed at an
env-configured URL is a blind-SSRF primitive.

**This phase deletes `aiohttp` from `management/requirements.txt`** rather than
entrenching a second production HTTP stack — one less dependency, one less CVE
surface in the image that already carries four of the repo's exceptions.

### Result type — three states, not two

```python
Ok(value, fetched_at) | Empty(fetched_at) | Unavailable(reason, last_ok_at)
```

`Empty` is mandatory and was the withdrawn plan's central hole. Only
`ConnectionsTotal` pre-initialises its label sets (`metrics.go:493`); **every
other counter has no series at all until its first non-zero event.** On a
freshly started, perfectly healthy proxy, `ja4proxy_handler_panics_total`,
`ja4proxy_bypass_total`, `ja4proxy_tarpit_overflow_total` and
`ja4proxy_config_reload_failures_total` all return empty vectors.

With two states those either raise (violating "no exceptions escape") or render
as `Unavailable` — **reporting a healthy system as broken observability.** That
is the console's own false positive, and this project's doctrine says false
positives are the expensive error.

`Empty` renders as a real zero. `Unavailable` means the query did not complete.
They must never collapse into one another.

### Security model

**The console never accepts PromQL from the client.** Requests name a tile ID;
the server resolves it in a static catalogue. Closed allowlist, not a filter.
Proxying a `?query=` parameter would hand any authenticated user an arbitrary
query engine — expensive queries to exhaust Prometheus exactly when it is most
needed, plus read access to every series regardless of role.

| Control | Note |
|---|---|
| Tile IDs only; no client PromQL, range, or step | the primary control |
| `follow_redirects=False`, scheme ∈ {http,https}, no userinfo, validated at startup | see SSRF note below |
| 2s timeout + server-side cache (§below) | one page load ≠ one query storm |
| Do **not** surface rule `expr` | see below |
| `--web.enable-lifecycle` dropped from **both** compose files | 821c |

**RBAC — stated honestly.** `require_role(Role.auditor)` admits every
authenticated user, because `auditor` is `_ROLE_ORDER` 0 (`auth.py:512-517`).
The withdrawn plan listed it as a security control; it restricts nothing. This
phase does not pretend otherwise: **all tiles are visible to any authenticated
user.** Tiles that leak posture — dial value, block rates, whitelist
composition — are attack-planning data, so 821b assigns those a genuinely
higher floor (`analyst`). Shipping the illusion is worse than shipping neither.

**SSRF policy inversion — must be documented.**
`management/api/routes/webhooks.py:41-74` **rejects** URLs resolving to private
addresses as SSRF. `http://prometheus:9090` is exactly such a URL. This phase
deliberately inverts that rule for one hardcoded-by-config target. The ADR must
record why, or a future security review will "fix" it and break the console.

`PROMETHEUS_URL` is **not currently set** in `docker-compose.poc.yml:429-433` —
it works only by falling back to the default at `partials.py:690`. This phase
sets it explicitly and asserts it in `test_container_config.py`, per the
CLAUDE.md web-service rule (that file parses only `REDIS_URL` today).

### Caching — TTL = 10s, bounded by the *fastest* scrape

Scrape intervals are **not uniform**: 15s global default
(`prometheus.yml:4`), 30s for one job (`:35`), and **10s for the proxy job**
(`:46`) that feeds every Panel 4 tile. Phase 820's `haproxy` job is 15s.

**TTL = 10s**, set to the fastest relevant scrape: a shorter TTL cannot produce
fresher data than the scrape feeding it, and a longer one adds console lag on
top of scrape lag. Tiles fed by slower jobs are inherently staler than their
TTL suggests — which is why `fetched_at` is displayed rather than implied, and
why a single global TTL is safe only in the conservative direction.

Single-flight de-duplication so N concurrent viewers cost one query set.

**Coupling to record:** single-flight is per-process and correct only because
`Dockerfile.management:45` runs `--workers 1`. A future `--workers N` silently
yields N caches, N last-good timestamps, and N× query load. Goes in the ADR.

### Age tiles are computed inside Prometheus

`time() - <gauge>` evaluates server-side, so console↔Prometheus clock skew does
not affect it. **Stated explicitly so nobody "improves" it into a Python-side
subtraction**, which would introduce exactly that bug.

---

## The one panel: Panel 4 — "Can I trust what it's telling me?"

Panel 4 ships first, not Panel 1. It is the phase's hardest panel (aggregation
across absent series), it is the one no Grafana dashboard gives for free, and
every correction above shows up in it. If Panel 4 is right, the rest are
mechanical.

### The silent-degradation light — eight counters, one indicator

Every external call fails open by design, and the hot path sheds load rather
than blocking. Correct — and it means the system degrades invisibly.

```promql
sum(rate({__name__=~"ja4proxy_(workchan_dropped|stream_event_drops|write_buffer_dropped|dns_enrichment_queue_drops|abuseipdb_queue_dropped|tap_packets_dropped|audit_jobs_dropped|tarpit_overflow)_total"}[5m])) or vector(0)
```

Two corrections are baked in:

- **A single `__name__` regex, never `sum(rate(a)) + sum(rate(b))`.** In PromQL
  an absent operand makes the whole `+` expression **empty**, not the sum of
  what is present. The phase's most important tile would go dark precisely when
  it should read green — and dark is indistinguishable from "Prometheus
  unreachable".
- **`ja4proxy_tap_packets_dropped_total` is emitted by a different process**
  (`internal/tap/metrics.go:21-23`, job `ja4proxy-tap` → `ja4-tap:9110`), and
  **`ja4-tap` is not a service in `docker-compose.poc.yml`.** That series is
  permanently absent in the POC. The regex form tolerates this; the `+` form
  would not.

### Blocklist staleness — per-feed, and "never worked" must read red

The withdrawn plan's flagship justification was that a week-stale blocklist is
indistinguishable from a healthy one except via this metric. **As specified it
was false**: the gauge is only `Set()` on success
(`internal/security/feed_downloader.go:138,175`), so a feed that has *never*
succeeded has no series, and `time() - <absent>` is empty — never-worked
rendered as no-data.

```promql
# value
max(time() - ja4proxy_blocklist_last_refresh_success_seconds)
# presence — drives red independently
count(ja4proxy_blocklist_last_refresh_success_seconds) or vector(0)
```

It is a **GaugeVec labelled `feed`** (`metrics.go:145-148`) with two feeds
enabled by default (`config/proxy.yml:562,573`), so the presence count is
compared against the configured feed count. The existing alert
(`alerts.yml:132`, `security.rules.yml:26`) has the identical blind spot; 821b
fixes it in the same idiom.

### Remaining Panel 4 tiles

| Tile | Expression note |
|---|---|
| AbuseIPDB / DNS / RDAP errors | `…{result="error"}`, each `or vector(0)` |
| Enrichment queue depths | gauges; present once the subsystem initialises |
| `ja4proxy_redis_health` | **needs a selector** — GaugeVec `{status="ok"\|"error"}` (`metrics.go:303-309`); bare, it renders two series |
| `ja4proxy_sync_clock_drift_seconds` | proxy↔Prometheus skew *does* apply and is already measured; the withdrawn plan omitted it |

---

## Implementation plan

1. `management/api/prometheus_client.py` — httpx, 2s timeout, no redirects,
   three-state result, startup URL validation, no exceptions escaping.
2. `management/api/metric_catalogue.py` — declarative `Tile` entries with
   mandatory `means` / `when_red`. A tile nobody can act on does not ship.
3. Cached query layer, TTL 10s, single-flight.
4. Panel 4 partial + template, following the existing polled-fragment pattern.
5. Set `PROMETHEUS_URL` explicitly in compose; assert it in
   `test_container_config.py`.
6. Delete `aiohttp` from `management/requirements.txt`.
7. Add `ja4proxy_console_prometheus_queries_total{result=}` — **the page whose
   job is detecting silent degradation must report its own.** The withdrawn
   plan had no self-observability at all.
8. ADR: console fails visibly while the proxy fails open; SSRF inversion;
   `--workers 1` coupling.

---

## Test strategy — the four regression tests

These exist to prevent specific, observed failures.

1. **Every metric name, label name, and label value in the catalogue resolves
   against the Go source.** Parse `internal/` for `ja4proxy_*` definitions and
   their `[]string{…}` label sets. *Name-only checking would not have caught
   the `{reason=}` error — this test must cover labels.* This is the
   generalisation of Phase 820's selector-validation test; **build one shared
   validator, not two.**

   > **Definition-resolution is not sufficient — three amendments, specified in
   > `PHASE_821b.md` §Test strategy.** (a) A metric can be *defined and
   > registered but never emitted*: `ja4proxy_dial_changes_total`
   > (`internal/metrics/metrics.go:26`, registered `:452`) has **zero `.Inc()`
   > calls in the repo** and exports a permanent `0`, so this test as written
   > would pass a tile that answers "did the dial change?" with a confident,
   > wrong "no". Require ≥1 emission site outside `internal/metrics/`.
   > (b) Histogram series carry `_bucket`/`_sum`/`_count` suffixes generated by
   > the client library and never present in Go source — strip before
   > resolving, or correct expressions fail. (c) See test #4 below.
2. **Cardinality guard, scoped to all of `internal/`** — not just
   `internal/metrics/`, since metrics are also defined in `internal/tap/`,
   `internal/backup/`, `internal/metrics/netbox.go`, `internal/redis/`. No
   label may be named `ip`, `client_ip`, `ja4`, `sni`, or `fingerprint`.
   Currently true; this makes it permanent. **Also:**
   `metrics.go:528-529` defines `SNIGuard` and `JA4Guard`
   (`NewCardinalityGuard(1000)`) referenced only from `cardinality_test.go` —
   machinery for per-SNI/per-JA4 labelling, built and abandoned. Either delete
   them or assert they stay unused.
3. **No client-supplied PromQL** — fails if any route passes request-derived
   data into a query.
4. **Catalogue lint** — every tile has non-empty `means`/`when_red`, and every
   counter-based tile carries `or vector(0)`.

   > **Plus, per `PHASE_821b.md`:** `or vector(0)` is invalid on `sum by (…)`
   > tiles — it appends a bogus unlabelled series — so those need a
   > `renders_empty_as_no_rows` opt-out. And a hard rule: **no tile expression
   > may contain a binary `+` between two metric selectors.** An absent operand
   > makes `+` yield empty, which `or vector(0)` then converts to a confident
   > `0` — failing *green*. This document states that hazard in §Panel 4 and
   > the first draft still violated it in the panics tile; only a lint rule
   > holds it.

Plus: fail-visibly with Prometheus stopped (tiles "unavailable", page 200, no
stale values); `Empty` vs `Unavailable` distinguished on a healthy fresh proxy;
single-flight under concurrency; `test_pages.py` + `test_container_config.py`.

---

## Acceptance criteria

1. Panel 4 renders live, including a correct zero for absent series.
2. With Prometheus stopped: "unavailable" + last-good timestamp, no 500s, no
   stale value shown as current.
3. On a freshly started healthy proxy, `Empty` tiles show **0**, not
   "unavailable".
4. Ten concurrent viewers → one query set per 10s window.
5. All four regression tests pass, and each fails when deliberately broken.
6. `aiohttp` gone from `management/requirements.txt`; no import remains.
7. `PROMETHEUS_URL` explicit in compose and asserted in
   `test_container_config.py`.
8. ADR merged.
9. `make lint`, `make test`, `make scan` clean.

**Explicitly NOT in this phase:** removing the Prometheus host port. See 821c
and the warning there.

---

## Out of scope

- Panels 1, 2, 3, 5 → **821b**
- Prometheus hardening → **821c**
- Removing Grafana / Alertmanager / cadvisor / promtail — a later phase, only
  after the console demonstrably covers the ground.
- **Assumption:** Grafana stays deployable behind a compose profile; the
  console may link out to it when configured but must be complete without it.
  This keeps "is Grafana gone for good?" deferred and reversible.

### Known gaps this phase does not close

- **The console is not in `docker-compose.prod.yml`** — it is POC-only, so "one
  place to manage the system" is POC-only until that changes. Deliberately not
  fixed here: putting the console into production is an exposure decision, not
  a side effect of a metrics change.
- **`make start` does not start Prometheus.** `Makefile:265,302,346,891` bring
  up only `docker-compose.poc.yml`; the monitoring overlay is a separate
  manually started project (`Makefile:502,884`). In the default developer flow
  every tile renders "unavailable" — correct behaviour, but it means the ACs
  above are verified **with the monitoring overlay running**, and that must be
  documented in the runbook rather than assumed.
- **Multi-lane dev reads the wrong lane.** `monitoring.yml:388-390` hardcodes
  `external: ja4proxy-mgmt` with no lane variable, while `scripts/lane-env.sh`
  offsets host ports only. Every lane's console resolves the same `prometheus`.
  Given this repo's parallel-agent workflow, an operator can read another
  worktree's numbers as their own — worse than no data. **Mitigation in this
  phase:** display the resolved scrape target on the panel so the lane is
  visible. A real fix is a separate phase.

---

## Sequencing

The Phase 820 dependency is **not** "HAProxy metrics must reach Prometheus" —
no 821 tile uses a `haproxy_*` metric. The genuine coupling is that **regression
test #1 is the generalisation of 820's selector-validation test**. Build the
shared validator once, in whichever lands first, and have the other consume it.

Note the reverse coupling: **the withdrawn plan's "Prometheus not reachable
from the host" criterion would have broken Phase 820's own acceptance criteria
4–6**, which verify alerts through `/api/v1/rules` from a host-side script.
That is why hardening is quarantined in 821c.

---

## Rollback

Genuinely additive: new module, new catalogue, new partial, one dependency
removed. Revert restores the Redis-only view. No schema, no persisted state, no
traffic-path code touched, and — unlike the withdrawn plan — no change to the
deployed network surface.
