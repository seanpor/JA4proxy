<!--
title: "Nightly Benchmark Regression Runbook"
audience: oncall, sre, platform
last_reviewed: 2026-07-30
phase: 805
-->

# Runbook: JA4ProxyNightlyBenchmarkRegression / JA4ProxyNightlyBenchmarkStale

## Severity
WARNING for both alerts. A perf regression is not a live customer-impact
page — it's a "look at this before it becomes one" (see `CLAUDE.md`'s
asymmetry principle, applied to alert severity in decision D6 of
`docs/phases/complete/PHASE_805.md`).

## What is happening

**`JA4ProxyNightlyBenchmarkRegression`:** the nightly `.github/workflows/nightly-benchmark.yml`
job ran `ja4p test benchmark` against the Go proxy's bridge port and the
result regressed more than 20% against `docs/reports/nightly_benchmark_baseline.json`
— throughput dropped, p95 latency rose, or both.

**`JA4ProxyNightlyBenchmarkStale`:** no fresh benchmark data has reached
Prometheus in over 36 hours. This does **not** necessarily mean a
regression — it means the pipeline itself is broken somewhere between the
nightly GitHub Actions job and this Prometheus instance. See "Architecture"
below; there are three independent links in that chain and any one of them
can break silently.

## Architecture (read this before diagnosing)

```
GitHub Actions (nightly, 03:17 UTC)     Self-hosted monitoring host
┌─────────────────────────────┐         ┌───────────────────────────────┐
│ ja4p test benchmark          │         │ systemd timer (hourly)         │
│  --output json                │ GH      │  scripts/export_ci_benchmark_  │
│ nightly_benchmark_gate.py     │ Release │  textfile.sh curls the        │
│  --gate 20                    │ asset   │  release asset (outbound      │
│ gh release upload             │────────▶│  HTTPS GET only)               │
│  nightly-benchmark-latest     │         │  writes .prom textfile         │
└───────────────────────────────┘         │  node-exporter picks it up     │
                                           │  Prometheus scrapes as usual   │
                                           └───────────────────────────────┘
```

GitHub Actions has **no inbound network path** to the self-hosted
monitoring host — that's why this is a pull (curl on a timer), not a push.
See `docs/phases/complete/PHASE_805.md`'s design section for the full reasoning
(remote_write and Pushgateway were both considered and rejected).

## Impact

- Neither alert indicates a live production incident. The nightly benchmark
  targets the bridge port (`docker-proxy`) path in an isolated CI runner,
  not the production fleet.
- A genuine regression, left uninvestigated, means a real hot-path
  performance regression could ship to production undetected — that's the
  gap this phase closes.

## Diagnosis

### For `JA4ProxyNightlyBenchmarkRegression`

1. Find the failing run: GitHub → Actions → "Nightly Benchmark" workflow.
   The job output includes the full `nightly_benchmark_gate.py` report
   (measured vs. baseline for each gated metric).
2. Check for an open `perf-regression`-labeled issue — the workflow opens
   or comments on one automatically with the same report.
3. Correlate with recent merges: `git log --oneline main` around the
   failing run's commit SHA (embedded in the published `result.json` as
   `git_sha`, and in the issue body via the run URL).
4. Rule out CI flakiness first: Docker-in-Actions network variance is a
   known source of noise (see "Risks" in `docs/phases/complete/PHASE_805.md`). Check
   whether the *previous* night was also regressed. A single bad night with
   a clean night before and after is more likely noise than a real
   regression; consecutive bad nights are not.
5. If it looks real, reproduce locally: `make bench-macro` (requires
   `make start` first) or the exact CI invocation, `./bin/ja4p test
   benchmark --host 127.0.0.1:$HOST_PORT_DIRECT --duration 30 --output json`.

### For `JA4ProxyNightlyBenchmarkStale`

Check each link in the chain in order — the first broken one is your answer:

1. **Did the GitHub Actions job run at all?** Actions → "Nightly Benchmark"
   → check the schedule fired and the run's own status (it fails loudly on
   a real regression — that's `JA4ProxyNightlyBenchmarkRegression`'s job,
   not this one — but a crashed/errored run before the gate step is
   `JA4ProxyNightlyBenchmarkStale`'s territory).
2. **Did the release asset actually update?** `gh release view
   nightly-benchmark-latest --json updatedAt,assets`. Compare `updatedAt`
   against the last successful workflow run.
3. **Is the monitoring host's puller timer running?**
   ```bash
   systemctl status ja4proxy-nightly-benchmark-puller.timer
   systemctl status ja4proxy-nightly-benchmark-puller.service
   journalctl -u ja4proxy-nightly-benchmark-puller.service -n 50
   ```
   Common failure: the puller fetch or JSON parse failed and the script
   fail-opened (left the old textfile in place, logged to stderr, exited
   0) — check the journal for `export_ci_benchmark_textfile:` log lines
   even though the systemd unit itself will show as "success" (fail-open
   is by design; see the script's own docstring).
4. **Did the textfile actually get written?**
   ```bash
   cat /var/lib/node_exporter/textfile_collector/ja4proxy_nightly_benchmark.prom
   ```
   Check the `ja4proxy_loadtest_last_ci_run_timestamp_seconds` value's age.
5. **Is node-exporter's textfile collector enabled and scraping?**
   ```bash
   docker compose -f deploy/docker/docker-compose.monitoring.yml exec node-exporter \
     wget -qO- http://localhost:9100/metrics | grep ja4proxy_loadtest
   ```
   If this returns nothing, check `--collector.textfile.directory=/textfile`
   is present in the node-exporter `command:` block and the bind mount
   (`/var/lib/node_exporter/textfile_collector:/textfile:ro`) resolves to
   the same path the puller writes to.

## Resolution

**Genuine regression, confirmed:**
1. Bisect to the offending commit (revert-and-rerun `workflow_dispatch`, or
   local `make bench-macro` at each candidate SHA).
2. File/attach findings to the auto-opened `perf-regression` issue.
3. Fix the regression, or, if it's an accepted deliberate tradeoff (e.g. a
   security hardening change that costs some throughput), update
   `docs/reports/nightly_benchmark_baseline.json`'s `gated_metrics` values
   with the new measured numbers, a comment explaining why, and get it
   reviewed — this file is a deliberate gate, not auto-updated, precisely so
   a regression can't silently raise its own bar (see D4 in
   `docs/phases/complete/PHASE_805.md`).

**Stale data:**
- Actions job broken → fix the workflow (check `.github/workflows/nightly-benchmark.yml`,
  most likely `scripts/start-poc.sh` failed to bring up the PoC stack in the
  ephemeral runner — check the job log's docker compose output).
- Puller timer stopped → `systemctl restart ja4proxy-nightly-benchmark-puller.timer`;
  investigate why it stopped (host reboot without the timer re-enabled? disk full?).
- node-exporter misconfigured → verify the compose diff against
  `deploy/docker/docker-compose.monitoring.yml`'s current committed state,
  `docker compose -f deploy/docker/docker-compose.monitoring.yml up -d node-exporter`
  to pick up a config change.

## Escalation

Neither alert pages on-call by itself (both `severity: warning`). Escalate
to the platform/SRE lead only if a confirmed regression is large enough
that it would materially change the capacity claims in
`docs/performance/benchmarks.md` or the product brochure — that's a
business-facing number, not just an internal gate.

## Installing the monitoring-host puller (first-time setup)

Run once, on the self-hosted monitoring host (not in CI, not in any
container):

```bash
sudo mkdir -p /var/lib/node_exporter/textfile_collector
sudo cp scripts/export_ci_benchmark_textfile.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/export_ci_benchmark_textfile.sh

sudo tee /etc/systemd/system/ja4proxy-nightly-benchmark-puller.service <<'EOF'
[Unit]
Description=Pull the JA4proxy nightly benchmark result into node-exporter's textfile collector

[Service]
Type=oneshot
ExecStart=/usr/local/bin/export_ci_benchmark_textfile.sh
EOF

sudo tee /etc/systemd/system/ja4proxy-nightly-benchmark-puller.timer <<'EOF'
[Unit]
Description=Hourly pull of the JA4proxy nightly benchmark result

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now ja4proxy-nightly-benchmark-puller.timer

# Verify:
sudo systemctl start ja4proxy-nightly-benchmark-puller.service  # run once immediately
journalctl -u ja4proxy-nightly-benchmark-puller.service -n 20
cat /var/lib/node_exporter/textfile_collector/ja4proxy_nightly_benchmark.prom
```

Prerequisites: `curl` and `python3` on the monitoring host (both are
already baseline dependencies of this project's tooling elsewhere).
`RELEASE_URL` and `TEXTFILE_DIR` in `export_ci_benchmark_textfile.sh` can be
overridden via environment variables in the systemd unit's `[Service]`
section if the defaults don't match a given deployment.
