---
phase: 805
title: Nightly Performance/Load Regression Detection, wired into Prometheus + Grafana
status: COMPLETE
created: 2026-07-22
completed: 2026-07-30
audience: [developer, operations]
---

# Nightly Performance/Load Regression Detection

> **STATUS: PROPOSED — plan for review. No code until approved.**
> Answers a gap found while investigating an unrelated CVE-waiver policy
> question this session: `make bench-all` (perf-test, load-test, go-perf,
> MTTR) exists, is real, and produces real numbers — but nothing in
> `.github/workflows/*.yml` ever runs it. A PR that regresses hot-path
> latency or throughput today passes CI cleanly. Nothing catches it.

## Goal (plain language)

Run the existing benchmark tooling on a schedule (not on every PR — it's
correctly described in the Makefile as "slow, runs alone"), detect
regressions against the documented baseline, and make the results visible
in the **same observability platform already in production**: Prometheus +
Grafana (+ Alertmanager for paging), not a new dashboard/tool/service.

## What "the platform we already use" actually is

Confirmed by reading `deploy/docker/docker-compose.monitoring.yml` and
`docs/reference/OBSERVABILITY_STANDARDS.md` rather than assuming:

| Component | Image (pinned) | Role |
|---|---|---|
| Prometheus | `prom/prometheus:v3.13.1` | Metrics storage + query |
| Alertmanager | `prom/alertmanager:v0.33.1` | Alert routing/paging |
| Grafana | `grafana/grafana:13.0.2-ubuntu` | Dashboards |
| node-exporter | `prom/node-exporter:v1.12.1` | Host metrics |
| redis_exporter | `oliver006/redis_exporter:v1.87.0` | Redis metrics |
| Loki + Promtail | `grafana/loki:3.7.2` / `grafana/promtail:3.6.11` | Log aggregation |

So: **yes, just Grafana for viewing** — but Grafana only ever renders what
Prometheus has scraped. There is no Tempo/Mimir/Jaeger; the OTEL tracing
code from Phase 16 has no configured exporter target in any compose file —
tracing is out of scope here, this phase is metrics-only. This stack is
self-hosted (via `docker-compose.monitoring.yml`, operated over the SSH
tunnel pattern in `make ssh-tunnels`) — it is **not** reachable from
GitHub Actions' cloud runners, which matters for the design below.

## Why this can't just "push metrics from CI"

GitHub Actions jobs in this repo run exclusively on `ubuntu-latest` (checked
across every workflow — no self-hosted runner exists). They are ephemeral
and have no network path to the self-hosted Prometheus. Three ways to close
that gap, in the order I'd rank them:

| Option | Verdict |
|---|---|
| **A. Prometheus `remote_write` open to CI** | Rejected. `prometheus.yml` already has `remote_write:` present but commented out. Enabling it means exposing an ingest endpoint to GitHub's dynamic IP ranges with credentials stored in Actions secrets — new inbound attack surface on infra that `DMZ_READINESS.md` and this repo's whole security posture are built around minimizing. Not worth it for benchmark numbers. |
| **B. Pushgateway** | Adds a whole new always-on service (and its own CVE/patch surface) purely to bridge an ephemeral job to a scrape-based system. Rejected as unnecessary weight. |
| **C. node-exporter textfile collector (recommended)** | node-exporter is already deployed and already scraped. Its [textfile collector](https://github.com/prometheus/node_exporter#textfile-collector) reads `.prom` files from a directory — zero new inbound ports, zero new services. CI publishes results outbound to a public GitHub Release asset; a small puller script *already on the monitoring host* pulls that asset on a timer (outbound HTTPS GET only) and writes the textfile. |

Going with **C**.

## Design

```
GitHub Actions (nightly, ubuntu-latest)          Self-hosted monitoring host
┌─────────────────────────────────┐              ┌──────────────────────────────┐
│ 1. make go-build cli-build       │              │ 4. systemd timer (hourly)     │
│ 2. scripts/start-poc.sh          │   GH Release │    curls the release asset    │
│ 3. ja4p test benchmark --output  │──asset──────▶│    (outbound HTTPS GET only,  │
│    json (bench-macro's own       │  "nightly-   │    no inbound exposure)       │
│    invocation, +json)            │   bench-     │ 5. writes .prom textfile      │
│ 4. scripts/nightly_benchmark_gate│   latest"    │    atomically                 │
│    .py --gate 20 (new script,    │              │ 6. node-exporter picks it up  │
│    see "Design correction" below)│              │    on next scrape (textfile   │
│    On regression: open/comment   │              │    collector, newly enabled)  │
│    a labeled GH issue — same     │              │ 7. Prometheus scrapes as usual│
│    actions/github-script pattern │              │ 8. Grafana renders; Alert-    │
│    as the existing                │              │    manager pages on           │
│    notify-scheduled-failure job  │              │    regression/staleness       │
└─────────────────────────────────┘              └──────────────────────────────┘
```

Metric names **reuse, not invent**: `docs/reference/OBSERVABILITY_STANDARDS.md`
§1d already reserves `ja4proxy_loadtest_connections_attempted_total`,
`_connections_completed_total`, `_errors_total`, `_latency_seconds`
(histogram), `_throughput_cps` (gauge) for exactly this purpose — "Emitted
by the load-test tooling... Present only while a benchmark is running."
This phase makes that documented-but-dormant metric family real and
persistent instead of ephemeral. Two additions needed on top:
`ja4proxy_loadtest_last_ci_run_timestamp_seconds` (gauge, staleness
detection) and `ja4proxy_loadtest_baseline_throughput_cps`/
`_baseline_p95_latency_ms` (gauges, sourced from the new baseline JSON below
so Alertmanager can compute regression ratio without hardcoding thresholds
in PromQL).

### Design correction (found during implementation, 2026-07-30)

D4 as originally written named `docs/reports/benchmark_baseline.txt` and
`scripts/benchmark_comparison.py` as the gate's data source and comparison
tool. Verified against current code before implementing (same discipline
[[PHASE_803]]'s D4 established) and **both premises are wrong**:

- `benchmark_baseline.txt`'s scenario names (`risk_scorer.10_signals`,
  `action_decider.decide`, `cidr_trie.100k_ipv4_lookup`, ...) are Phase 16
  microbenchmarks of `src/security/pipeline.py`'s risk scorer/action
  decider — **Python-proxy modules deleted** when the Python proxy was
  removed (see `CLAUDE.md`'s "Go-only" note). The two test files that
  produced these numbers, `tests/performance/test_bench_pipeline.py` and
  `test_bench_cidr_lookup.py`, no longer exist. The file is an orphaned
  artifact; its field names (`p99_us`, `limit_us` per named scenario) share
  nothing with `ja4p test benchmark --output json`'s actual shape
  (`throughput_cps`, `p50/p95/p99_latency_ms`, one flat aggregate, not
  per-scenario).
- `scripts/benchmark_comparison.py` is not invoked by any Makefile target or
  CI workflow today (grepped both — zero hits). Its whole design is a
  dual-proxy Go-vs-Python comparison (`--python-host`/`--python-port`); the
  Python proxy it would compare against doesn't exist (`proxy.py` is
  deleted). It is dead tooling, not "still used elsewhere" as originally
  assumed.

What's actually live and current, found in `docs/performance/benchmarks.md`
(last updated 2026-06-10, phase-86i — after Phase 16, before this plan was
written, evidently not checked when the plan was drafted) and
`Makefile`'s `bench`/`bench-macro`/`bench-hostnative` targets:

- `make bench-macro` runs exactly `./bin/ja4p test benchmark --host
  127.0.0.1:$HOST_PORT_DIRECT --duration 30`, and is explicitly documented
  as "fine for regression tracking" (as opposed to `bench-hostnative`,
  which needs host networking and is the *capacity* number, not the CI
  regression-tracking one).
- `docs/performance/benchmarks.md` already has a dated, git-SHA-tagged
  "Historical Runs" table — this is the real equivalent of the plan's
  invented `docs/reports/BENCHMARK_HISTORY.md` (which doesn't exist). Its
  bridge-macro row (`76504c8`, 2026-06-10): **600 conn/s, ~290ms p95, 0
  errors** — exactly the metric the nightly job will re-measure, since the
  nightly job also runs through the bridge port, not host-native.

**Revised approach**, keeping D4's actual intent (don't invent a new
number; enforce the one already documented) while pointing it at data that
actually exists: the nightly workflow runs `make bench-macro`'s own
invocation with `--output json` added; a new
`docs/reports/nightly_benchmark_baseline.json` is seeded from the
already-published bridge-macro row above (600 CPS / 290ms p95 / 0 errors,
SHA 76504c8) instead of re-deriving a number from scratch; a new
`scripts/nightly_benchmark_gate.py` (not an extension of
`benchmark_comparison.py`, per this phase's own "or add a small sibling
script if [extending] doesn't fit" escape hatch) does the comparison. Gate
on `throughput_cps` (regression = drop > 20%) and `p95_latency_ms`
(regression = rise > 20%) — the two fields the baseline actually has real
measured data for; `p99_latency_ms` is recorded and trended in Grafana but
not gated until enough nightly runs accumulate real p99 history.
`scripts/benchmark_comparison.py` is left untouched, exactly as this
phase's "Out of scope" section already said — it turned out to need no
touching at all, since the new gate is a sibling script, not an extension.

## Key decisions (for review)

| # | Decision | Why |
|---|---|---|
| D1 | Nightly schedule, not per-PR | `bench-all` is explicitly documented as "slow, runs alone" and excluded from `lint scan test`. Gating every PR on it would be slow and flaky (network/timing variance); nightly + regression alert catches drift without blocking velocity. |
| D2 | Transport = GitHub Release asset (rolling tag `nightly-benchmark-latest`, `--clobber`), not a bot-authored commit/PR | Avoids `main`'s branch protection entirely for pure data — no auto-merge risk, no PR-review noise for a machine-generated JSON blob every night. Publicly fetchable with a plain `curl`, no auth needed either side. |
| D3 | `docs/performance/benchmarks.md`'s "Historical Runs" table stays manually curated | Keep it as-is (milestone log a human writes), not auto-appended nightly — avoids commit spam. The Grafana panel becomes the actual continuous historical record; the markdown table stays for narrative "why" entries at named milestones. (Corrected from the original D3, which named a `docs/reports/BENCHMARK_HISTORY.md` that doesn't exist — see "Design correction" above.) |
| D4 | Regression threshold = 20% (matching the convention already used by the now-orphaned Phase-16 baseline comment), sourced from a freshly-created `docs/reports/nightly_benchmark_baseline.json` seeded from `docs/performance/benchmarks.md`'s already-published, git-SHA-tagged bridge-macro row, not from `benchmark_baseline.txt` | Don't invent a new *threshold* — 20% is the one already established in this repo's perf-gating convention. But the *data source* named in the original D4 (`benchmark_baseline.txt`) turned out to be orphaned Python-proxy tooling (see "Design correction" above) — corrected to point at real, currently-measured data instead. |
| D5 | Puller runs on the monitoring host via systemd timer, not inside any container in `docker-compose.monitoring.yml` | It needs to write to a host path node-exporter bind-mounts read-only; keeping it a host-level cron avoids giving any container write access to the textfile directory. |
| D6 | Regression alert and staleness alert are both `warning`, not `page`-severity | Consistent with the asymmetry principle in `CLAUDE.md` — a perf regression alert is not a live customer-impact page; it's a "look at this before it becomes one." |

## Implementation plan (in order)

1. **`.github/workflows/nightly-benchmark.yml`** — new workflow, `schedule` (nightly, off-peak UTC) + `workflow_dispatch`. `make go-build cli-build`, `./scripts/start-poc.sh` (auto-generates `.env`, brings up `docker-compose.poc.yml`), health-check loop, then `./bin/ja4p test benchmark --host 127.0.0.1:$HOST_PORT_DIRECT --duration 30 --output json` — `bench-macro`'s own invocation with `--output json` added, no new Go code needed for the runner itself.
2. **New `scripts/nightly_benchmark_gate.py`** (sibling script, not an extension of `benchmark_comparison.py` — see "Design correction" above) — `--result result.json --baseline docs/reports/nightly_benchmark_baseline.json --gate 20` mode that exits non-zero on breach; this is the actual regression gate logic.
3. **Regression notification job** in the same workflow: `if: failure()`, reuse the exact `actions/github-script` + labeled-issue pattern from the `notify-scheduled-failure` job added in phase-800 (`.github/workflows/ci.yml`) — new label `perf-regression` so it doesn't collide with `scheduled-ci-failure` issues.
4. **Publish step**: `gh release upload nightly-benchmark-latest result.json --clobber` (create the tag once, idempotent `--clobber` thereafter). Plain `gh` CLI (already on `ubuntu-latest`, authenticated via `GITHUB_TOKEN`) — no new third-party action to pin.
5. **`scripts/export_ci_benchmark_textfile.sh`** (new, host-side) — curls the release asset, converts to Prometheus text exposition format under the metric names above, atomic write (`mv` after successful curl — fail open, never blank out good data on a fetch failure), installed via a systemd timer unit (document install steps in the runbook, step 9).
6. **`deploy/docker/docker-compose.monitoring.yml`**: add `--collector.textfile.directory=/textfile` to node-exporter's `command:`, plus a read-only bind mount for the host path the script writes to.
7. **`deploy/monitoring/alertmanager/rules/performance.rules.yml`** (new file, following the existing `*.rules.yml` naming pattern) — `JA4ProxyNightlyBenchmarkStale` (no update in >36h) and `JA4ProxyNightlyBenchmarkRegression` (throughput/p95 latency past the D4 threshold), both `severity: warning`.
8. **Grafana**: new dashboard `deploy/monitoring/grafana/dashboards/ci_benchmark_trend.json` — throughput/p50/p95/p99 trend over time, error rate, a stat panel for time-since-last-run. Kept separate from `04_capacity.json` deliberately: that dashboard is live production capacity, this is synthetic CI trend — different axes, different audience, shouldn't be conflated on one board.
9. **Docs**: `docs/reference/OBSERVABILITY_STANDARDS.md` §3 (new dashboard) and §4 (two new alert rules); new runbook `docs/runbooks/nightly_benchmark_regression.md` (what to check when either alert fires, how to install/verify the systemd timer); new ADR (`docs/decisions/ADR-207-nightly-benchmark-textfile-collector.md`) capturing the remote_write/Pushgateway/textfile-collector decision from this doc; CHANGELOG fragment; `docs/phases/manifest.yaml` → COMPLETE.
10. **`tests/test_workflow_pinning.py`**: SHA-pin any new third-party actions used in the new workflow (same `KNOWN_ACTION_SHAS` pattern already used for `actions/github-script`) — expected to be a no-op given step 4's `gh`-CLI choice, but verify.

## Test plan

- Existing generic tests (`tests/unit/test_alert_rules.py`, `tests/unit/test_infra_dashboard.py`) — confirmed during implementation: `test_alert_rules.py` uses an explicit `RULE_FILES` list, not a directory glob, and it turned out to already be missing 6 existing rule files (`tap.yml`, `ebpf_attack.yml`, `management_ui_rules.yml`, `slo_alerts.yml`, `ti_feed.yml`, `tls_alerts.yml`) — the new `performance.rules.yml` plus all 6 pre-existing gaps get registered together while touching this list. `test_infra_dashboard.py` is content-specific to two named dashboards, not a generic all-dashboards check — the new dashboard's structural validity is covered by `make lint-json` instead (already extended for `tap_sensor.json` in Phase 803; `ci_benchmark_trend.json` added the same way).
- `scripts/nightly_benchmark_gate.py` gets its own unit test with a synthetic "regressed" and "clean" JSON fixture, asserting exit code.
- `scripts/export_ci_benchmark_textfile.sh` gets a shell/Python test exercising: happy path (writes valid Prometheus text format), fetch-failure path (leaves existing textfile untouched — the fail-open behavior is the point, must be proven, not assumed).
- Dry-run the full workflow via `workflow_dispatch` on the phase branch before merge, confirm a real release asset appears and a real textfile-format sample validates against `promtool check metrics` (or equivalent parse check, since `promtool` isn't available in this test env per existing Phase 14e notes — use a structural/regex check the same way that phase did).
- `docker compose -f deploy/docker/docker-compose.monitoring.yml config` must still validate after the node-exporter command/volume change (existing pattern already used in `docs/runbooks/docker_image_updates.md`).

## Acceptance criteria

- [ ] Nightly workflow runs on schedule, produces a real benchmark JSON, and a manual `workflow_dispatch` run succeeds end-to-end in CI.
- [ ] A regression (synthetic, deliberately-slowed test run) triggers the `perf-regression`-labeled issue via the same notification pattern as `notify-scheduled-failure`.
- [ ] `nightly-benchmark-latest` GitHub Release asset exists and updates on each run.
- [ ] node-exporter textfile collector enabled; `docker compose config` validates; puller script installed on the monitoring host and verified pulling real data.
- [ ] `ja4proxy_loadtest_*` metrics appear in Prometheus (scrape target up, series present) and render in the new Grafana dashboard.
- [ ] Both new Alertmanager rules fire correctly under test (staleness by clock-skew test, regression by synthetic bad data) and stay silent under real green data.
- [ ] OBSERVABILITY_STANDARDS.md, the new runbook, the new ADR, and the CHANGELOG fragment all land.
- [ ] Full CI green; `docs/phases/manifest.yaml` 805 → COMPLETE.

## Out of scope

- **Per-PR blocking perf gates** — explicitly rejected by D1; a future phase could revisit a *much* cheaper synthetic smoke check (e.g. bypass-path latency only, sub-second) as a PR-time gate, but that's a separate, smaller phase if ever pursued.
- **OpenTelemetry trace export** — no trace backend (Tempo/Jaeger) exists in this stack; out of scope, metrics-only per the "same platform" framing.
- **`remote_write` / Pushgateway** — considered and rejected, see design section.
- **`scripts/benchmark_comparison.py`** — untouched. Originally scoped as "extend with a new flag/mode"; turned out to need no touching at all once the gate became a sibling script (see "Design correction"). Its Go-vs-Python dual-proxy comparison mode is itself now dead code (no Python proxy exists to compare against) but reviving or removing it is a separate cleanup, out of scope here.

## Risks

- **Nightly job flakiness** (Docker-in-Actions network variance) could produce false regression alerts — mitigate with a small retry/smoothing window (e.g. alert only after 2 consecutive bad nights) rather than a single-run trigger; finalize the exact rule during implementation, not guessed here.
- **Monitoring-host puller is a new host-level cron artifact outside the docker-compose-managed surface** — needs to be documented clearly (runbook, step 9) so it isn't a mystery to the next operator; this is the one piece of this phase that isn't purely git-tracked config.
