# Phase 821 — The management console becomes the single operational face

> **Status:** PROPOSED (2026-08-15)
> **Size:** LARGE
> **Dependencies:** 820 (HAProxy metrics must reach Prometheus first)
> **Branch:** `phase-821-console-metrics`

---

## Goal

Make the management console the one place an operator goes to understand the
system. Prometheus becomes a **headless engine**; the console becomes its
**only human face**. No routine operational question should require opening
Grafana, Prometheus, or `docker logs`.

Today the proxy exports **94 `ja4proxy_*` metrics**. The console displays
**five numbers**, all read directly from Redis. The other 89 are visible only
in Grafana, which means they are visible only to whoever thinks to look.

---

## Why this is the right shape

### The intent is two phases old and already half-wired

- `management/api/routes/partials.py:690` defines `_PROMETHEUS_URL` — **never
  referenced anywhere.**
- `management/requirements.txt:36` carries `aiohttp==3.14.3`, commented
  `# phase-234: Prometheus HTTP API query for infra row`.
- `PHASE_234.md §5.2` planned "option (b) — query Prometheus", flagged a
  network-isolation blocker, and deferred it to "Phase 237". It was never done.

**That blocker no longer exists.** `docker-compose.monitoring.yml` puts
Prometheus on `poc_mgmt_net` (external → `ja4proxy-mgmt`), the same network
management is on. `prometheus:9090` is reachable from the console **today**,
with no compose change and no new network exposure. Phase 234's option (b) is
now free.

### Don't rebuild Grafana — the console's job is different

Grafana is good at ad-hoc exploration over history. Rebuilding that is a losing
project. But there are two questions this system needs answered that no generic
dashboard gives you, because they require **aggregation with meaning attached**:

**1. "Am I silently shedding work?"** The proxy must never block the hot path,
so it sheds load instead. There are **seven** independent drop counters:

```
ja4proxy_workchan_dropped_total          ja4proxy_stream_event_drops_total
ja4proxy_write_buffer_dropped_total      ja4proxy_dns_enrichment_queue_drops_total
ja4proxy_abuseipdb_queue_dropped_total   ja4proxy_tap_packets_dropped_total
ja4proxy_tarpit_overflow_total
```

Each is correct in isolation and invisible in aggregate. One console light
should mean *"you are currently discarding work"*.

**2. "Am I scoring blind?"** Every external call fails open by design
(CLAUDE.md). When AbuseIPDB, RDAP or DNS degrade, **nothing breaks** — scoring
quietly gets worse. `ja4proxy_blocklist_last_refresh_success_seconds` is the
sharpest case: a week-stale blocklist is indistinguishable from a healthy one
at every level except this metric.

These two lights are the core justification for a bespoke console.

### The asymmetry has no home today

CLAUDE.md's governing rule is that a blocked real user costs far more than a
missed bot. **No current console page or dashboard reflects that.** Phase 821
makes "am I hurting real users?" a first-class panel rather than something an
operator must assemble from PromQL.

---

## Architecture

```
proxy ─┐
redis ─┼─▶ Prometheus  ──HTTP /api/v1/query──▶  Management console ──▶ operator
haproxy┘   (headless engine)                    (catalogue + cache)
           30d / 10GB                            the ONLY human face
```

Prometheus stays because the console genuinely needs what it provides: history
(a page load only knows "now"), `rate()` over counters, aggregation across N
proxy replicas, and a rules engine. It simply stops being something a human
opens.

### Security model — the load-bearing decision

**The console never accepts PromQL from the client.** Requests name a
**tile ID**; the server looks the expression up in a static catalogue. This is
a closed allowlist, not a filter.

This is the single most important decision in the phase. The obvious
implementation — proxying a `query` parameter through to Prometheus — would
hand any authenticated user an arbitrary query engine: expensive queries to
exhaust Prometheus memory (a DoS against observability during an incident,
precisely when it is needed), and read access to every series regardless of
role. A closed catalogue makes both structurally impossible rather than
mitigated.

Supporting controls:

| Control | Rationale |
|---|---|
| Tile IDs only; no client-supplied PromQL, ranges, or step values | see above |
| Per-tile RBAC (`auditor` read-only baseline) | reuses existing `Role` enum |
| Short query timeout (2s) + server-side result cache | one operator's page load ≠ one Prometheus query storm |
| Prometheus loses its host port binding | under this design nothing outside the Docker network should reach it |
| Drop `--web.enable-lifecycle` **or** justify it in writing | it exposes `/-/reload` and `/-/quit` over HTTP; Prometheus sits on four networks (`monitoring`, `dmz`, `mgmt`, `origin`) — the most network-connected component in the stack |
| Catalogue expressions are reviewed artefacts, diffable in PRs | a new tile is a code review, not a runtime action |

**Metric cardinality is currently safe and must stay that way.** Every label
set in `internal/metrics/` is a small closed enum (`action`, `result`, `type`,
`status`, `signal`, `reason`, …). **No metric is labelled by IP, JA4, or SNI.**
That is what keeps Prometheus memory bounded and an attacker unable to inflate
it by sending traffic. Phase 821 adds a test to enforce this permanently.

### Reliability model

**The console is an observer and must never become load-bearing.** If it is
down, or Prometheus is down, traffic decisions are completely unaffected. No
hot-path code may ever call it. Stated explicitly so nobody wires it in later.

**The console fails *visibly*, not open.** This deliberately differs from the
project's fail-open doctrine, and the distinction matters: fail-open is correct
for the *traffic path*, where a missed signal beats a blocked user. It is wrong
for a *management console*, where an operator makes decisions from what they
see. A tile that cannot reach Prometheus renders **"unavailable"** with the age
of the last successful read. It must never render a stale number as though it
were current, and must never 500 the page.

**Polling must not amplify.** N operators × 25 tiles × a 10s poll is a query
storm against the thing you need most during an incident. Tile results are
cached server-side with a short TTL and single-flight de-duplication, so
concurrent viewers cost one query set, not N.

**Metric-name drift is the predictable failure.** The catalogue references ~25
metric names that live in Go source. A rename silently blanks a tile — exactly
the failure mode Phase 820 found in the HAProxy alerts, where four rules
referenced a label that no exporter ever emitted and nobody noticed for months.
This phase treats that as the primary regression risk and tests for it.

---

## What the console will show — 25 of 94

Organised by the question an operator is actually asking.

### Panel 1 — Am I hurting real users? *(top of page)*

| Tile | Source |
|---|---|
| Block rate against browser-shaped traffic | `ja4proxy_connections_total{action="block"}`, `ja4proxy_bypass_total` |
| JA4 whitelist hit rate | `ja4proxy_bypass_total{reason="ja4_whitelist"}` |
| TLS/JA4 mismatch rate | `ja4proxy_ja4_tls_mismatch_total` |
| Active bans vs. releases | `ban:*` (Redis) + `ja4proxy_offense_escalations_total` |
| Score distribution **near the threshold** | `ja4proxy_risk_score` |

The last is the important one: false positives live in the band just above the
cut, not out at 100.

### Panel 2 — What is it deciding?

`ja4proxy_connections_total` by action (allow/flag/rate_limit/tarpit/block/ban),
`ja4proxy_risk_score` histogram, `ja4proxy_dial_current`,
`ja4proxy_bypass_total` by reason, `ja4proxy_tarpit_concurrent`.

Bypasses deserve prominence: those connections never reached the scorer at all.

### Panel 3 — Is it alive and keeping up?

`ja4proxy_active_connections`, `ja4proxy_pipeline_duration_seconds`
(p50/p95/p99), `ja4proxy_connection_errors_total`,
**`ja4proxy_handler_panics_total` (must be 0 — any value is a bug)**,
`ja4proxy_redis_health`, Redis `evicted_keys`,
`ja4proxy_tls_cert_expiry_timestamp_seconds`.

Redis evictions matter more than they look: evicting a `ban:` key is silent
policy loss.

### Panel 4 — Can I trust what it's telling me? *(the silent-degradation light)*

The seven drop counters rolled into one indicator, plus
`ja4proxy_abuseipdb_lookups_total{result="error"}`,
`ja4proxy_dns_resolver_errors_total`, RDAP/AbuseIPDB queue depths, and
`ja4proxy_blocklist_last_refresh_success_seconds` rendered **as an age**.

### Panel 5 — What changed?

`ja4proxy_dial_current` + `ja4proxy_dial_changes_total`,
`ja4proxy_config_reloads_total` + `ja4proxy_config_reload_failures_total`,
`ja4proxy_signal_drift_total`, and the existing `management:policy_audit` trail.

### Firing alerts

Read from Prometheus `/api/v1/alerts` and `/api/v1/rules` and render in the
console. **Alertmanager is only needed to route alerts outward** (email, Slack,
pager) — seeing them does not require it.

The remaining ~70 metrics (tap internals, backup/restore, multi-DC sync) are
diagnostic. They belong on a drill-down page, not the front page, and are out
of scope here.

---

## Implementation plan

**1 — Prometheus client** (`management/api/prometheus_client.py`): async,
`aiohttp` (already a dependency), 2s timeout, structured errors, no exceptions
escaping to the request handler. Returns `Ok(value, fetched_at)` or
`Unavailable(reason, last_ok_at)` — the type makes "fail visibly" unavoidable
rather than a convention.

**2 — Metric catalogue** (`management/api/metric_catalogue.py`): the key
artefact. One declarative entry per tile:

```python
Tile(
    id="blocklist_staleness",
    expr='time() - ja4proxy_blocklist_last_refresh_success_seconds',
    unit=Unit.SECONDS_AGE,
    role=Role.auditor,
    warn_above=3600, error_above=86400,
    means="How long since the blocklist last refreshed successfully.",
    when_red="Feeds are failing open — the proxy is scoring without them. "
             "Check egress and the feed runbook.",
)
```

`means` / `when_red` are mandatory fields. A tile nobody can act on does not
belong on the page, and making the text mandatory enforces that at review time.

**3 — Cached query layer:** short-TTL cache with single-flight, keyed by tile
ID.

**4 — Partials + templates:** follow the existing
`/api/v1/partials/<panel>` htmx pattern — no new frontend technology. Extend
the dead `infrastructure_partial` to finally use `_PROMETHEUS_URL`.

**5 — Alerts view** from `/api/v1/alerts`.

**6 — Harden Prometheus:** remove the host port binding; resolve
`--web.enable-lifecycle` (drop it, or document why it stays).

**7 — Docs:** runbook for the new panels; ADR for "console fails visibly, the
proxy fails open" — the exception to the project-wide doctrine needs to be
findable, or someone will "fix" it back.

---

## Test strategy

Ordinary unit/integration coverage, plus four tests that exist specifically to
prevent the failure modes above:

1. **Every metric name in the catalogue exists in the Go source.** Parse
   `internal/`, extract `ja4proxy_*`, assert every catalogue reference resolves.
   *This is the test that would have caught Phase 820's four dead alerts.*
2. **Cardinality guard:** no metric in `internal/metrics/` may declare a label
   named `ip`, `client_ip`, `ja4`, `sni`, or `fingerprint`. Currently true;
   this makes it permanent.
3. **No client-supplied PromQL:** assert no route passes request-derived data
   into a query. A test that fails loudly if someone adds a `?query=` parameter.
4. **Every tile has non-empty `means` and `when_red`.**

Plus: fail-visibly behaviour with Prometheus unreachable (tiles render
"unavailable", page returns 200, never a stale value); cache single-flight
under concurrent load; `test_pages.py` and `test_container_config.py` per the
CLAUDE.md web-service rule.

---

## Acceptance criteria

1. All five panels render from live Prometheus data.
2. `_PROMETHEUS_URL` is used; no dead constant remains.
3. Every routine operational question is answerable without leaving the console.
4. With Prometheus stopped: every tile shows "unavailable" with a last-good
   timestamp; no 500s; no stale value presented as current.
5. Ten concurrent viewers produce one query set per TTL window, not ten.
6. All four regression tests pass and fail correctly when deliberately broken.
7. Prometheus is not reachable from the host; lifecycle API resolved.
8. Firing alerts appear in the console.
9. `make lint`, `make test`, `make scan` clean.

---

## Out of scope

- **Removing Grafana, Alertmanager, cadvisor or promtail.** Phase 821 makes
  them redundant; it does not delete them. Removal is a separate phase *after*
  the console has proven it covers the ground.
- **Assumption stated:** Grafana remains deployable behind a compose profile,
  and the console may carry an optional deep-dive link when it is configured.
  The console must be complete without it. This keeps the "is Grafana gone for
  good?" decision deferred and reversible — it does not need answering now.
- The ~70 diagnostic metrics (tap, backup/restore, multi-DC sync).
- Go 1.26.6 bump and `.trivyignore` splitting — separate phase.

### Known gap this phase does not close

**The management console is not in `docker-compose.prod.yml`** — it exists only
in the POC stack. "One place to manage the system" is therefore POC-only until
that is fixed. This phase does not fix it: adding the console to production is
a real deployment-topology and exposure decision that deserves its own review,
not a side effect of a metrics change. Flagged here so it is not mistaken for
an oversight.

---

## Rollback

Additive. New module, new catalogue, new partials; the only edit to existing
behaviour is the infrastructure partial gaining real data. Revert restores the
Redis-only view. No schema, no persisted state, no traffic-path code touched.
