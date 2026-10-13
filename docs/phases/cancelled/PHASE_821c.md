# Phase 821c — Prometheus hardening (quarantined)

> **Status:** PROPOSED (2026-08-15)
> **Size:** SMALL (lifecycle flag) + MEDIUM (port migration, if approved)
> **Dependencies:** 820, 821a, 821b — **must land after all three**
> **Branch:** `phase-821c-prometheus-hardening`

---

## Why this is a separate phase

The withdrawn `PHASE_821.md` bundled Prometheus hardening into a large metrics
phase. Expert review found that **one of its acceptance criteria would have
broken Phase 820's acceptance criteria** and at least nine other callers. That
is exactly how a plausible-looking cleanup reaches `main` and takes the
observability plane down with it.

Hardening touches ~12 files **outside** `management/` — a different ownership
set under CLAUDE.md's file-ownership rules — and, unlike 821a/821b, it is **not
revertible by reverting a Python module**. It changes the deployed surface.

---

## Part 1 — Drop `--web.enable-lifecycle` (approved, cheap, do this)

**Evidence:** `deploy/docker/docker-compose.monitoring.yml:9` and
`deploy/docker/docker-compose.prod.yml:352`.

The flag exposes `/-/reload` and `/-/quit` **unauthenticated** over HTTP. A
repo-wide search for `/-/reload` and `enable-lifecycle` returns **only those two
compose lines** — no script, Makefile target, or CI workflow uses it.

The exposure is real: Prometheus sits on **four networks**
(`monitoring.yml:34-38`) including `poc_dmz_net` — the same network as `haproxy`
and `proxy`. A compromised DMZ container can `POST /-/quit` and terminate the
observability plane. It is the most network-connected component in the stack.

**Action:** remove the flag from **both** compose files. The withdrawn plan
mentioned only the monitoring one.

Zero cost, nothing to migrate, no caller to update. This part can land alone.

---

## Part 2 — Removing the Prometheus host port (needs a decision, not a default)

The withdrawn plan asserted "Prometheus is not reachable from the host" as an
acceptance criterion. Two problems.

**The security gain is close to zero.** The port is **already loopback-only** —
`monitoring.yml:13` and `prod.yml:342` bind
`${AGENT_BIND_IP:-127.0.0.1}:9091:9090`. It is not exposed to the network today.

**The breakage is large.** Removing it breaks, at minimum:

| Caller | Reference |
|---|---|
| **Phase 820's own verification** | `tests/integration/infra-monitoring/check_haproxy_exporter.sh:14,20,29,47,85` — 820 AC 4/5/6 verify alerts through `/api/v1/rules` from the host |
| cAdvisor check | `check_cadvisor_metrics.sh:14,20` |
| Status / demo / bootstrap scripts | `scripts/status.sh:130`, `view-metrics.sh:21`, `geoip-monitor.sh:30,64,90`, `demo-poc.sh:25,207,217`, `validate-single-host.sh:84,150`, `bootstrap.sh:159` |
| Makefile | `Makefile:1633-1638` (`make open SVC=prometheus`), `1044-1047` (SSH-tunnel help) |
| Tests / lane tooling | `test_lane_env.py:16`, `test_setup_wizard.py:55`, `scripts/lane-env.sh:28,103,117` |

**Recommendation: do not do this.** Loopback binding already provides the
protection; the remaining benefit is defence-in-depth against a local
unprivileged process, which does not justify migrating a dozen call sites and
losing the ability to verify Prometheus from a shell during an incident.

If it is nonetheless wanted, it is a self-contained migration phase: move every
caller to `docker compose exec prometheus wget -qO- localhost:9090/...`, update
the runbooks, and keep a documented `make` target for opening a tunnel.

---

## Part 3 — Aggregation hygiene (cheap, do it while here)

`prometheus.yml` has no `external_labels` and no replica de-duplication.

Note that **"aggregation across N proxy replicas" is not a live capability** —
`prometheus.yml:56-57` targets a single `proxy:9090`, while
`docker-compose.scale.yml:28-78` defines `proxy-worker-1..4` that **no scrape
job knows about**. 821a's justification for keeping Prometheus rests on history
and `rate()`, which stand on their own; the replica claim was overstated and
has been removed from that plan.

If replicas ever become real, every catalogue expression needs `sum by (…)`
retrofitted. **Cheaper to write them aggregated from day one** — which 821a and
821b now do — and to add `external_labels` here so lane and instance are
distinguishable.

This also mitigates the multi-lane hazard noted in 821a: `monitoring.yml:388-390`
hardcodes `external: ja4proxy-mgmt` with no lane variable, so every lane's
console resolves the same `prometheus`, and an operator can read another
worktree's numbers as their own.

---

## Acceptance criteria

1. `--web.enable-lifecycle` absent from both compose files; Prometheus starts;
   `make scan` and the monitoring integration checks pass unchanged.
2. `external_labels` set and visible in the console's scrape-target display
   (821a).
3. Part 2 is **explicitly accepted or explicitly declined in writing** in the
   phase notes. If accepted, every caller in the table above is migrated and
   verified in the same PR — no partial migration.
4. Phase 820's acceptance criteria still pass after this phase.

---

## Out of scope

- Everything in 821a and 821b.
- Removing Grafana / Alertmanager / cadvisor / promtail.
- Fixing the multi-lane network isolation properly (a real fix needs
  lane-scoped network names; this phase only makes the lane *visible*).
