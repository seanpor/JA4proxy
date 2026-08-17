# Phase 820 — Retire `prom/haproxy-exporter`, use HAProxy's native Prometheus exporter

> **Status:** PROPOSED (2026-08-14)
> **Size:** SMALL
> **Dependencies:** none
> **Branch:** `phase-820-haproxy-native-promex`

---

## Goal

Delete the `prom/haproxy-exporter:v0.15.0` sidecar and scrape HAProxy's built-in
Prometheus exporter directly. This removes an abandoned container carrying **58
HIGH/CRITICAL findings** and **20 of the repo's 73 `.trivyignore` exceptions**,
and — as a consequence of doing it properly — repairs four alert rules and two
dashboard panels that **cannot fire or render today**.

---

## Why now

`prom/haproxy-exporter` is a translation shim from before HAProxy could speak
Prometheus. HAProxy 1.x published stats only as a CSV page; Prometheus cannot
read CSV, so the sidecar scraped that page and re-published it. Our compose
still does exactly this:

```yaml
--haproxy.scrape-uri=http://${HAPROXY_STATS_USER}:${HAPROXY_STATS_PASSWORD}@haproxy:8404/stats;csv
```

HAProxy 2.0 absorbed the function. **The image we already pin has it compiled
in and idle** — verified against `haproxy:2.8.26-alpine`:

```
HAProxy version 2.8.26-682859627 2026/07/03
OPTIONS = ... USE_PROMEX=1 ...
Built with the Prometheus exporter as a service
Available services : prometheus-exporter
```

Upstream agrees the sidecar is finished: `prometheus/haproxy_exporter` last
published **v0.15.0 on 2023-02-15** and has not been touched since. It is built
on **Go 1.19.5**. It is the sole carrier of 20 exceptions — every `CVE-2022-*`
and `CVE-2023-*` entry in `.trivyignore` exists only to keep it in the gate.

Phases 810, 812 and 818 each identified this replacement and deferred it.

### The discovery that changes the shape of this phase

Both exporters were run side by side against an identical HAProxy instance and
their output compared. **The current monitoring built on this sidecar is
already broken**, and has been since it was written:

| Consumer | Expression | Status today | Why |
|---|---|---|---|
| `alerts.yml` HAProxyBackendQueueing | `haproxy_backend_current_queue{proxy="ja4proxy"}` | **dead** | old exporter emits **no `proxy` label** — it uses `backend=` |
| `alerts.yml` HAProxySessionLimitApproaching | `haproxy_frontend_current_sessions / …_limit_sessions` | **dead** | same; old exporter uses `frontend=` |
| `alerts.yml` HAProxyBackendDown | `haproxy_server_status{proxy="ja4proxy"} == 0` | **dead** | old exporter has **no `haproxy_server_status`** at all — it emits `haproxy_server_up` |
| `alerts.yml` HAProxyConnectionErrorRate | `rate(haproxy_server_connection_errors_total{proxy="ja4proxy"}[2m])` | **dead** | no `proxy` label |
| `ja4proxy-infrastructure.json` ×2 panels | `rate(haproxy_frontend_connections_rate[1m])` | **empty** | old exporter never emits `haproxy_frontend_connections_rate` |
| `04_capacity.json` | `haproxy_backend_current_queue` (unfiltered) | works | no label selector |

Verified: `grep -c 'proxy="' old_metrics.txt` → **0**.

Two independent faults compound here. The alerts were written against the
**native promex label convention** (`proxy=`) which the sidecar never emitted,
*and* against the value `ja4proxy` while the real backends are named
`ja4proxy_workers` (`config/haproxy.cfg:56`) and `ja4proxy_backend`
(`deploy/haproxy/haproxy.cfg:68`).

So the sidecar currently delivers **one working dashboard panel** in exchange
for 58 CVEs and 20 exceptions. Migrating to native promex fixes the rest —
provided the label values are corrected in the same change, which is why that
correction is in scope here rather than deferred.

### Verified metric-by-metric compatibility

Native `haproxy:2.8.26-alpine` promex exposes 280 metric lines. Of the six
names our dashboards and alerts reference:

| Metric | Native | Note |
|---|---|---|
| `haproxy_backend_current_queue` | ✓ `{proxy=}` | |
| `haproxy_frontend_current_sessions` | ✓ `{proxy=}` | |
| `haproxy_frontend_limit_sessions` | ✓ `{proxy=}` | |
| `haproxy_server_connection_errors_total` | ✓ `{proxy=,server=}` | |
| `haproxy_server_status` | ✓ `{proxy=,server=,state=}` | **semantics differ — see below** |
| `haproxy_frontend_connections_rate` | ✗ absent | replace with `haproxy_frontend_connections_total` |

**`haproxy_server_status` is the one real trap.** Native promex emits it as a
state machine — one series per state, value 1 for the active state and 0 for
the rest:

```
haproxy_server_status{proxy="be_test",server="s1",state="UP"}    1
haproxy_server_status{proxy="be_test",server="s1",state="DOWN"}  0
haproxy_server_status{proxy="be_test",server="s1",state="MAINT"} 0
haproxy_server_status{proxy="be_test",server="s1",state="DRAIN"} 0
haproxy_server_status{proxy="be_test",server="s1",state="NOLB"}  0
```

A naive `haproxy_server_status{proxy="…"} == 0` matches the four inactive
states permanently and would page continuously. It **must** pin `state="UP"`.

**`haproxy_frontend_connections_rate` was a gauge** (HAProxy's own sliding
-window conn/s), so the existing `rate(...)` wrapper was invalid even in
principle — `rate()` is for counters. Native `haproxy_frontend_connections_total`
is a true counter, so `rate(...[1m])` over it is correct and genuinely yields
the "Sessions/s" the panel legend already claims.

---

## Scope — files owned by this phase

| File | Change |
|---|---|
| `config/haproxy.cfg` | enable promex on the stats frontend |
| `deploy/haproxy/haproxy.cfg` | same |
| `deploy/docker/docker-compose.monitoring.yml` | delete the `haproxy-exporter` service |
| `deploy/monitoring/prometheus/prometheus.yml` | retarget job `haproxy` → `haproxy:8404` `/metrics` |
| `deploy/monitoring/prometheus/alerts.yml` | fix 4 rules: label value + `state="UP"` |
| `deploy/monitoring/grafana/dashboards/ja4proxy-infrastructure.json` | 2 panels → `connections_total` |
| `.trivyignore` | delete 20 exceptions; drop haproxy-exporter from 32 justification texts |
| `tests/unit/test_infra_dashboard.py` | update scrape-job assertion |
| `tests/integration/infra-monitoring/check_haproxy_exporter.sh` | rename + retarget |
| `docs/runbooks/deploy_credentials.md` | drop exporter credential plumbing |
| `docs/fragments/phase-820-*.md` | changelog fragment |
| `docs/phases/manifest.yaml` | mark COMPLETE |

---

## Implementation plan

**1 — Enable native promex.** In both `haproxy.cfg` stats frontends:

```haproxy
frontend stats
    bind *:8404
    mode http
    http-request use-service prometheus-exporter if { path /metrics }
    stats enable
    stats uri /stats
    stats auth ${HAPROXY_STATS_USER:?…}:${HAPROXY_STATS_PASSWORD:?…}
```

`use-service` is evaluated before `stats`, so `/metrics` is served by promex
and `/stats` keeps its existing auth. Note `/metrics` is **not** behind
`stats auth` — acceptable because :8404 is bound to loopback
(`127.0.0.1:8404:8404`) and the monitoring network only, and it exposes no
credentials. This is called out explicitly rather than left implicit.

**2 — Retarget the scrape job.**

```yaml
  - job_name: 'haproxy'
    scrape_interval: 15s
    metrics_path: /metrics
    static_configs:
      - targets: ['haproxy:8404']
```

**3 — Repair the four alert rules.** Correct `proxy="ja4proxy"` →
`proxy="ja4proxy_workers"` and pin `haproxy_server_status{…,state="UP"} == 0`.

**4 — Repair the two dashboard panels.** `rate(haproxy_frontend_connections_rate[1m])`
→ `rate(haproxy_frontend_connections_total[1m])`.

**5 — Delete the service** from `docker-compose.monitoring.yml`, including its
`HAPROXY_STATS_USER`/`PASSWORD` injection.

**6 — Prune `.trivyignore`:** delete the 20 sole-carrier entries; edit the 32
shared entries whose comment blocks name haproxy-exporter so the affected-image
list stays truthful. Leave every other entry untouched.

**7 — Update tests and the runbook.**

---

## Test strategy

- **Unit** (`test_infra_dashboard.py`): job `haproxy` present and targeting
  `haproxy:8404` with `metrics_path: /metrics`; assert no `haproxy-exporter`
  reference survives anywhere in `deploy/`.
- **New unit test** — regression guard for the bug this phase found: every
  `haproxy_*` selector in `alerts.yml` and both dashboards must use a `proxy`
  label value that matches a `backend`/`frontend` name actually declared in
  `config/haproxy.cfg`. This is what would have caught four dead alerts.

  > **Build this as a reusable selector validator, not a `haproxy_`-specific
  > one.** `PHASE_821a.md` regression test #1 is the same check generalised to
  > `ja4proxy_*` metrics and the console's metric catalogue — it validates
  > metric names, label names, **and** label values against their source of
  > truth. Whichever phase lands first owns the shared implementation; the
  > other consumes it. Two bespoke copies is the outcome to avoid.
- **New unit test:** any `haproxy_server_status` selector must constrain `state=`.
- **Integration** (`check_haproxy_promex.sh`, renamed): bring up the stack,
  assert the `haproxy` target is `up`, and assert a non-empty result for each
  of the six metrics — i.e. prove the alerts can now match, which is precisely
  what was never verified before.
- **Scan gate:** `make scan` passes with 20 fewer exceptions; `make scan-exceptions`
  reports 53.
- `make lint` and `make test` clean.

---

## Acceptance criteria

1. `prom/haproxy-exporter` appears nowhere in `deploy/`, `config/`, or `tests/`.
2. `make scan` passes; `.trivyignore` holds **53** entries, and the 20 listed
   below are gone.
3. `make scan-images` no longer scans haproxy-exporter (it leaves `TRIVY_IMAGES`
   automatically — the list is derived from the compose files).
4. Prometheus target `haproxy` is `up` against `haproxy:8404`.
5. All six metrics return non-empty series through Prometheus.
6. The four HAProxy alerts evaluate against real series (verified via
   `/api/v1/rules`, not merely by config inspection).
7. Both repaired panels render non-empty data.
8. New regression tests fail if a `haproxy_*` selector names a non-existent
   proxy, or if `haproxy_server_status` is used without `state=`.
9. `make lint` and `make test` pass with zero warnings.

**Exceptions deleted (20):** CVE-2022-41722, -41723, -41724, -41725,
CVE-2023-24534, -24536, -24537, -24538, -24539, -24540, -29400, -29403, -39325,
-45283, -45287, -45288, CVE-2024-24790, -34156, -45337, -45338.

---

## Out of scope

- **Go 1.26.5 → 1.26.6** and splitting `.trivyignore` into first-party /
  third-party files. Separate phase; that one is about CVEs in *our* proxy.
- **cadvisor, promtail, alertmanager removal.** Separate decisions.
- **Making HAProxy itself optional.** Discussed and agreed in principle, but
  it is a deployment-topology change touching the PROXY-protocol path; it
  needs its own phase and its own test coverage.
- Adding new HAProxy dashboards. This phase repairs what exists; it does not
  expand coverage, even though native promex offers 280 metrics vs the
  sidecar's 115.

---

## Rollback

Single revert. The sidecar image remains on Docker Hub, and no state, schema,
or persisted data is touched — the only durable artefacts are Prometheus
samples under the `haproxy` job, whose series labels change from
`backend=`/`frontend=` to `proxy=`. Historical series are retained under the
old labels and simply stop receiving samples; no dashboard depends on them,
because — as established above — only one panel was reading them at all.
