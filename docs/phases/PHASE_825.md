<!--
title: Cut_cAdvisor_And_Promtail
audience: operator
last_reviewed: 2026-08-16
phase: 825
-->

# Phase 825 — Cut cAdvisor and Promtail

> **Status:** PROPOSED (2026-08-16)
> **Size:** MEDIUM
> **Dependencies:** none (deliberately independent of 821a/b)
> **Branch:** `phase-825-cut-cadvisor-promtail`

---

## Goal

Remove `gcr.io/cadvisor/cadvisor`, `tecnativa/docker-socket-proxy` and
`grafana/promtail` from the monitoring stack, taking `.trivyignore` from
**59 → ~30** exceptions and roughly halving the weekly renewal churn that has
produced issues #417, #423 and #432.

Chosen because **neither depends on the console work**. Grafana and Alertmanager
can only go once Phase 821a/b gives the console something to replace them with;
these two can go now.

---

## ⚠ This is not free — read this before approving

Earlier framing in the exception analysis treated these as pure deletion. They
are not. Both carry real observability, and it is better to say so plainly than
to discover it after a merge.

### What cAdvisor removal costs

| Lost | Detail |
|---|---|
| **4 alerts** | `ContainerOOMKilled`, `ContainerRestartLoop`, `ContainerMemoryHigh`, `ContainerCPUThrottleHigh` (`alerts.yml:407,424,441,458`) |
| **2 recording rules** | `ja4proxy:container_mem_pct`, `ja4proxy:container_cpu_throttle_ratio` (`recording_rules.yml:129,135`) |
| **1 dashboard row** | `Container Drill-Down [$container]` and its `$container` template variable — 28 `container_*` references in `ja4proxy-infrastructure.json` |
| **Fleet Status panels** | per-container memory tiles built on the recording rules |

**`ContainerOOMKilled` is the one worth arguing about.** Losing OOM detection on
a security proxy is a genuine downgrade: an OOM-killed proxy fails *closed* for
the connections it was serving, which under CLAUDE.md's core asymmetry is the
expensive direction. Nothing else in the stack reports it — `node-exporter` is
host-level, and the console's heartbeat check (`partials.py`) answers "is it up
*now*", not "was it killed and restarted".

**Mitigation, and the honest limit of it:** the proxy's own
`ja4proxy_handler_panics_total` and the Redis heartbeat cover process death from
the inside, and Docker's restart policy makes a restart loop visible in
`docker ps`. Neither is an alert. So this phase **accepts a real reduction in
alerting** in exchange for 17 exceptions and a 43-CVE image.

If that trade is not acceptable, the alternative is to keep cAdvisor and accept
the renewal churn — which is a legitimate answer. It should be a deliberate
choice, not a side effect.

### What Promtail removal costs

Log shipping to Loki. With no shipper, **Loki has nothing to serve**, so log
search in Grafana goes with it. `docker logs` and the JSON log files remain.

Promtail is EOL upstream and its successor, Grafana Alloy, scans at **6 CVEs vs
promtail's 29** — so "migrate to Alloy" is a real option that keeps log search.
This phase takes the simpler path (remove) because the console work (821a/b) is
where log surfacing should land, but **Alloy is the better answer if log search
is wanted in the meantime.**

Promtail is in **both** `docker-compose.monitoring.yml` and
`docker-compose.prod.yml:438` — production loses log shipping too.

---

## Scope

| File | Change |
|---|---|
| `deploy/docker/docker-compose.monitoring.yml` | remove `cadvisor`, `docker-socket-proxy`, `promtail` |
| `deploy/docker/docker-compose.prod.yml` | remove `promtail` |
| `deploy/monitoring/prometheus/prometheus.yml` | remove the `cadvisor` scrape job |
| `deploy/monitoring/prometheus/alerts.yml` | remove the 4 container alerts |
| `deploy/monitoring/prometheus/recording_rules.yml` | remove the 2 container recording rules |
| `deploy/monitoring/grafana/dashboards/ja4proxy-infrastructure.json` | remove the Container Drill-Down row, the `$container` variable, and container-metric panels |
| `deploy/monitoring/loki/promtail-config.yml` | delete |
| `tests/unit/test_infra_dashboard.py` | drop cadvisor/container assertions; **add** guards that they do not return |
| `tests/integration/infra-monitoring/check_cadvisor_metrics.sh` | delete |
| `.trivyignore.third-party` | remove entries with no remaining carrier |

**Loki is kept** — it is only 2 CVEs, and deleting it would force a re-add when
Alloy or the console lands. It will simply have no data until then, which the
runbook must state so nobody debugs an empty Loki.

---

## Implementation notes

The `.trivyignore` prune must be driven by a **fresh no-ignorefile scan**, not
by the previous analysis. That analysis was computed on 2026-08-14 and still
counted `haproxy-exporter` — an image Phase 820 had already deleted — as a live
carrier, which inflated the projected remainder from ~12 to 32. Re-scan, then
delete only entries whose carrier set becomes empty.

---

## Test strategy

1. **Regression guards, not just deletions.** Removing an assertion leaves
   nothing to stop the image returning. Add: no compose file may reference
   `gcr.io/cadvisor/cadvisor`, `tecnativa/docker-socket-proxy` or
   `grafana/promtail` in an `image:` directive.
2. **No dangling metric references.** Assert no dashboard, alert or recording
   rule references `container_*` or `ja4proxy:container_*` once the source is
   gone — the Phase 820 lesson: a selector with no series never errors, it just
   renders nothing forever.
3. `promtool check rules` passes; every dashboard remains valid JSON; compose
   files still validate.
4. `make scan-images` green with the reduced exception set.

---

## Acceptance criteria

1. The three images appear in no compose file; guards prevent their return.
2. No `container_*` selector survives anywhere in `deploy/monitoring/`.
3. `.trivyignore.third-party` contains no entry whose only carriers were the
   removed images — verified by a fresh scan, not by the stale analysis.
4. Exception count drops to ~30; `make scan` green.
5. The runbook records **what alerting was given up** and that Loki is
   intentionally empty until a shipper returns.
6. `make lint`, `make test`, `make scan` clean.

---

## Out of scope

- Grafana and Alertmanager removal — blocked on Phase 821a/b.
- Migrating Promtail → Alloy (the log-search-preserving alternative).
- Replacing the lost OOM/restart alerting.
