---
phase: 805
title: Nightly Performance/Load Regression Detection, wired into Prometheus + Grafana
status: PROPOSED
created: 2026-07-22
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
│ 1. docker compose up (poc)       │              │ 4. systemd timer (hourly)     │
│ 2. ja4p test benchmark --output  │   GH Release │    curls the release asset    │
│    json  (already exists)        │──asset──────▶│    (outbound HTTPS GET only,  │
│ 3. compare vs benchmark_baseline │  "nightly-   │    no inbound exposure)       │
│    .txt's documented 20% gate    │   bench-     │ 5. writes .prom textfile      │
│    (scripts/benchmark_compar-    │   latest"    │    atomically                 │
│    ison.py — extend, don't       │              │ 6. node-exporter picks it up  │
│    replace)                      │              │    on next scrape (textfile   │
│    On regression: open/comment   │              │    collector, newly enabled)  │
│    a labeled GH issue — same     │              │ 7. Prometheus scrapes as usual│
│    actions/github-script pattern │              │ 8. Grafana renders; Alert-    │
│    as the existing               │              │    manager pages on           │
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
detection) and `ja4proxy_loadtest_baseline_p99_seconds{scenario}` (gauge,
sourced from `benchmark_baseline.txt` so Alertmanager can compute
regression ratio without hardcoding thresholds in PromQL).

## Key decisions (for review)

| # | Decision | Why |
|---|---|---|
| D1 | Nightly schedule, not per-PR | `bench-all` is explicitly documented as "slow, runs alone" and excluded from `lint scan test`. Gating every PR on it would be slow and flaky (network/timing variance); nightly + regression alert catches drift without blocking velocity. |
| D2 | Transport = GitHub Release asset (rolling tag `nightly-benchmark-latest`, `--clobber`), not a bot-authored commit/PR | Avoids `main`'s branch protection entirely for pure data — no auto-merge risk, no PR-review noise for a machine-generated JSON blob every night. Publicly fetchable with a plain `curl`, no auth needed either side. |
| D3 | `docs/reports/BENCHMARK_HISTORY.md` stays manually curated | Keep it as-is (milestone log a human writes), not auto-appended nightly — avoids commit spam. The Grafana panel becomes the actual historical record; the markdown file stays for narrative "why" entries. |
| D4 | Regression threshold = the existing documented 20% (`benchmark_baseline.txt`'s "CI regression gate: fail if any metric is > 20% above baseline p99") | Don't invent a new number — that comment has been sitting there unenforced; enforce the one that's already documented. |
| D5 | Puller runs on the monitoring host via systemd timer, not inside any container in `docker-compose.monitoring.yml` | It needs to write to a host path node-exporter bind-mounts read-only; keeping it a host-level cron avoids giving any container write access to the textfile directory. |
| D6 | Regression alert and staleness alert are both `warning`, not `page`-severity | Consistent with the asymmetry principle in `CLAUDE.md` — a perf regression alert is not a live customer-impact page; it's a "look at this before it becomes one." |

## Implementation plan (in order)

1. **`.github/workflows/nightly-benchmark.yml`** — new workflow, `schedule` (nightly, off-peak UTC) + `workflow_dispatch`. Build the Go proxy, bring up `docker-compose.poc.yml`, run `ja4p test benchmark --output json` (reuse existing binary/subcommand, no new Go code needed for the runner itself).
2. **Extend `scripts/benchmark_comparison.py`** (or add a small sibling script if that file's scope is really "Go vs Python" per its docstring and doesn't fit) with a `--baseline docs/reports/benchmark_baseline.txt --gate 20` mode that exits non-zero on breach — this is the actual regression gate logic.
3. **Regression notification job** in the same workflow: `if: failure()`, reuse the exact `actions/github-script` + labeled-issue pattern from the `notify-scheduled-failure` job added in phase-800 (`.github/workflows/ci.yml`) — new label `perf-regression` so it doesn't collide with `scheduled-ci-failure` issues.
4. **Publish step**: `gh release upload nightly-benchmark-latest result.json --clobber` (create the tag once, idempotent `--clobber` thereafter).
5. **`scripts/export_ci_benchmark_textfile.sh`** (new, host-side) — curls the release asset, converts to Prometheus text exposition format under the metric names above, atomic write (`mv` after successful curl — fail open, never blank out good data on a fetch failure), installed via a systemd timer unit (document install steps in the runbook, step 9).
6. **`deploy/docker/docker-compose.monitoring.yml`**: add `--collector.textfile.directory=/textfile` to node-exporter's `command:`, plus a read-only bind mount for the host path the script writes to.
7. **`deploy/monitoring/alertmanager/rules/performance.rules.yml`** (new file, following the existing `*.rules.yml` naming pattern) — `JA4ProxyNightlyBenchmarkStale` (no update in >36h) and `JA4ProxyNightlyBenchmarkRegression` (p99 latency or throughput past the D4 threshold), both `severity: warning`.
8. **Grafana**: new dashboard `deploy/monitoring/grafana/dashboards/ci_benchmark_trend.json` — throughput/p50/p95/p99 trend over time, error rate, a stat panel for time-since-last-run. Kept separate from `04_capacity.json` deliberately: that dashboard is live production capacity, this is synthetic CI trend — different axes, different audience, shouldn't be conflated on one board.
9. **Docs**: `docs/reference/OBSERVABILITY_STANDARDS.md` §3 (new dashboard) and §4 (two new alert rules); new runbook `docs/runbooks/nightly_benchmark_regression.md` (what to check when either alert fires, how to install/verify the systemd timer); new ADR (`docs/decisions/ADR-207-nightly-benchmark-textfile-collector.md`) capturing the remote_write/Pushgateway/textfile-collector decision from this doc; CHANGELOG fragment; `docs/phases/manifest.yaml` → COMPLETE.
10. **`tests/test_workflow_pinning.py`**: SHA-pin any new third-party actions used in the new workflow (same `KNOWN_ACTION_SHAS` pattern already used for `actions/github-script`).

## Test plan

- Existing generic tests (`tests/unit/test_alert_rules.py`, `tests/unit/test_infra_dashboard.py`) — confirm during implementation whether they glob their directories automatically or need the new files registered explicitly; either way the new rule file and dashboard must pass whatever schema/lint they already enforce for the existing files.
- `scripts/benchmark_comparison.py`'s new gate mode gets its own unit test with a synthetic "regressed" and "clean" JSON fixture, asserting exit code.
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
- **Rewriting `scripts/benchmark_comparison.py`'s existing Go-vs-Python comparison mode** — extend with a new flag/mode, don't touch its current behavior (still used elsewhere per its own docstring).

## Risks

- **Nightly job flakiness** (Docker-in-Actions network variance) could produce false regression alerts — mitigate with a small retry/smoothing window (e.g. alert only after 2 consecutive bad nights) rather than a single-run trigger; finalize the exact rule during implementation, not guessed here.
- **Monitoring-host puller is a new host-level cron artifact outside the docker-compose-managed surface** — needs to be documented clearly (runbook, step 9) so it isn't a mystery to the next operator; this is the one piece of this phase that isn't purely git-tracked config.
