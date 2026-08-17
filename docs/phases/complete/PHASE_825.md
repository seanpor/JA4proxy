<!--
title: Migrate_Promtail_To_Alloy
audience: operator
last_reviewed: 2026-08-17
phase: 825
-->

# Phase 825 — Migrate Promtail to Grafana Alloy (cAdvisor stays)

> **Status:** PROPOSED (2026-08-16, rescoped 2026-08-17 after review)
> **Size:** MEDIUM
> **Dependencies:** none
> **Branch:** `phase-825-cut-cadvisor-promtail`

---

## Decision record — what changed and why

This phase was originally *"cut cAdvisor and Promtail"*, justified as taking
`.trivyignore` from **59 → ~30**. Investigating the blast radius changed both
halves of that.

**cAdvisor stays.** Removing it would have taken four alerts with it —
`ContainerOOMKilled`, `ContainerRestartLoop`, `ContainerMemoryHigh`,
`ContainerCPUThrottleHigh` (`alerts.yml:407,424,441,458`) — plus two recording
rules, the `Container Drill-Down` dashboard row and the Fleet Status memory
tiles. `ContainerOOMKilled` is the decisive one: an OOM-killed proxy fails
**closed** for the connections it was serving, the expensive direction under
CLAUDE.md's core asymmetry, and nothing else in the stack reports it.
node-exporter is host-level; the console heartbeat answers "up now", not "was
killed and restarted". **Decision: keep cAdvisor and accept the renewal churn.**

**Promtail migrates rather than being removed.** It is EOL upstream, and its
supported successor Grafana Alloy scans at **6 HIGH/CRITICAL vs promtail's 29**.
Migrating keeps log search, which removal would have destroyed (no shipper means
Loki has nothing to serve).

---

## ⚠ Be clear about the saving: this is 59 → 58

The original framing — that cutting these would roughly halve the weekly
renewal churn — does not survive contact with the data.

| | |
|---|---|
| Promtail is the **sole carrier** of | **2** exceptions (`CVE-2026-45447`, `CVE-2026-42154`) |
| Promtail *participates* in | 29 — but 27 are shared with cAdvisor and Alertmanager, which stay |
| Alloy **adds** | **1** — `CVE-2026-71556`, not currently exceptioned |
| **Net** | **59 → 58** |

So this phase does **not** meaningfully reduce the trivy renewal churn. That
churn is driven by cAdvisor's 43 participations, which the decision above
deliberately keeps.

It is still worth doing, on different grounds: promtail is EOL and unsupported,
Alloy is its maintained replacement, and the image's own finding count drops
from 29 to 6. But it should be approved as **"replace an EOL component"**, not
as **"reduce exceptions"** — and nobody should expect issue #432's successors to
get quieter as a result.

The honest lever on churn remains Grafana + Alertmanager, both blocked on
Phase 821a/b.

---

## Scope

| File | Change |
|---|---|
| `deploy/docker/docker-compose.monitoring.yml` | `grafana/promtail` → `grafana/alloy`, pinned by digest |
| `deploy/docker/docker-compose.prod.yml:438` | same — promtail is in **prod too** |
| `deploy/monitoring/loki/promtail-config.yml` | → `deploy/monitoring/alloy/config.alloy` (Alloy's River config, not YAML) |
| `.trivyignore.third-party` | drop the 2 promtail-only entries; add `CVE-2026-71556` for Alloy |
| `deploy/monitoring/grafana/dashboards/ja4proxy-infrastructure.json:555,609` | the `promtail` panel and its `ja4proxy:container_mem_pct{name="promtail"}` query |
| `docs/runbooks/` | log-pipeline runbook updated for Alloy |
| `tests/` | guard that promtail cannot return; assert the Alloy target is scraped |

**Unchanged:** cAdvisor, docker-socket-proxy, Loki, all four container alerts,
both recording rules, the Container Drill-Down row.

---

## The real risk: config translation, not the image swap

Promtail is configured in YAML; Alloy uses **River**. `promtail-config.yml`
carries the scrape/relabel rules that decide which container logs reach Loki and
how they are labelled — including 5 `container_*` references. A silent
translation error means logs stop arriving, and **nothing currently alerts on
that**: an empty Loki looks identical to a quiet system.

This is the same failure shape as Phase 820's dead selectors and Phase 824's
`EMPTY` vs `BROKEN` distinction, so it gets the same treatment:

- Assert log *arrival* after migration — query Loki for a known line emitted by
  a known container, not merely that the Alloy container is `Up`.
- Assert the label set survives translation: a log line must still carry the
  labels the dashboards and any saved queries use.

---

## Test strategy

1. **Arrival test** — emit a marker line from a known container, assert it is
   queryable in Loki within N seconds with the expected labels. This is the
   only test that proves the migration worked.
2. **Guard** — no compose file may reference `grafana/promtail` in an `image:`
   directive.
3. **Scrape target** — Prometheus scrapes Alloy's own metrics endpoint.
4. `promtool check rules`, dashboards valid JSON, compose validates.
5. `make scan-images` green at 58.

---

## Acceptance criteria

1. `grafana/promtail` appears in no compose file; a guard prevents its return.
2. A marker log line reaches Loki through Alloy **with its labels intact** —
   demonstrated, not assumed.
3. Exception count is **58**, with `CVE-2026-71556` justified and dated and the
   2 promtail-only entries removed.
4. The runbook documents the Alloy config location and River format, and states
   that an empty Loki after this change means the pipeline is broken, not quiet.
5. cAdvisor, its four alerts and the Container Drill-Down row are untouched —
   asserted, so the rescope cannot be silently undone.
6. `make lint`, `make test`, `make scan` clean.

---

## Out of scope

- Removing cAdvisor — explicitly rejected above.
- Grafana / Alertmanager removal — blocked on Phase 821a/b.
- Surfacing logs in the console — that is 821b's territory.
