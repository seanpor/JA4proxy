# Phase 86i: Hardening — Architectural Gaps From Phase 86

**Status:** PROPOSED
**Depends on:** Phase 86h (fixup) merged

---

## Goal

Complete the Phase 86 vision by closing four architectural and deliverable gaps that the shipped implementation missed. The gaps were surfaced by the same critical review that drove Phase 86h.

Unlike 86h (pure defect repair), this phase changes architecture and ships new deliverables. Each sub-section is independently reviewable but they share one plan document for coordination.

---

## Scope

### Gap 1 — Datadog + Dynatrace lose Prometheus label richness

**Problem:** Both integrations poll `/api/v1/health/deep` for numeric metrics and emit single scalars. `ja4proxy.block_rate_pct` as one gauge tells you nothing useful; broken down by `action={block,allow,tarpit,ban}` it's your block-rate dashboard. The same is true for `ja4proxy.connections.total` by `bypass`, `ja4proxy.pipeline_duration_seconds` by `signal`, and every histogram. All of this label richness exists in the Prometheus `/metrics` endpoint and is currently discarded at the integration boundary.

**Fix (Datadog):** Two-layer pattern.
- **Layer 1 — OpenMetrics check** — add `deploy/datadog/conf.d/openmetrics.d/ja4proxy.yaml` that uses Datadog Agent's built-in OpenMetrics integration to scrape `/metrics` directly. No custom Python. Preserves all labels automatically.
- **Layer 2 — narrowed custom check** — `deploy/datadog/checks/ja4proxy/check.py` keeps only: topology entity creation, service checks (`ja4proxy.node_health`, `ja4proxy.redis_health`), and derived gauges not available in Prometheus (e.g., aggregate cross-node state). Remove every `self.gauge()` / `self.rate()` call that duplicates a Prometheus metric.

**Fix (Dynatrace):** `deploy/dynatrace/ja4proxy-extension/plugin.py` switches from polling `/api/v1/health/deep` to scraping `/metrics`. Minimal Prometheus text-format parser (~20 lines). Keep `extension.yaml` topology definition; update the metric declarations to match the richer set.

### Gap 2 — Benchmark file is empty

**Problem:** `docs/performance/benchmarks.md` contains `_(measure)_` placeholders. Phase 86h made the capacity calculator honest about this by printing a warning, but the warning is still present because no benchmark has been run.

**Fix:** Run the benchmark suite on reference hardware and commit the numbers. Update `scripts/capacity_calculator.py` `EstimatedConstants` (from 86h) with the measured values and rename back to `BenchmarkConstants`. Remove the warning path. The `--require-measured` flag becomes effectively a no-op on clean benchmarks.md.

**Reference hardware** must be documented in the file header: hardware model, OS, Redis config, Git SHA, Go version, Python version. If no production-representative hardware is available, document the actual host used (developer laptop is acceptable if labeled clearly — the point is reproducibility, not absolute numbers).

### Gap 3 — Load test has the wrong scenarios

**Problem:** `scripts/load_test.py` currently has `choices=["baseline", "sustained", "ramp"]` — none of these distinguish the bypass path from the full-signal path from the attack path. Any benchmark numbers produced are uninterpretable.

**Fix:** Replace the scenario set with four code-path-specific scenarios and document their fingerprint distributions explicitly:

| Scenario | Browser ALPN | Automation | Known scanners | Known malicious | Purpose |
|----------|-------------:|-----------:|---------------:|----------------:|---------|
| `bypass-only` | 100% | 0% | 0% | 0% | Bypass path throughput ceiling |
| `full-signal` | 0% | 100% | 0% | 0% | Full scoring path (cache miss, Redis reads) |
| `attack-wave` | 0% | 0% | 50% | 50% | Block path + Redis writes |
| `mixed` | 70% | 20% | 5% | 5% | Representative production traffic |

Reuse the existing `scripts/tls-traffic-generator.py` — do not duplicate its TLS client machinery.

**Also add Pushgateway support** via a `--push-gateway URL` flag, emitting 5 new metrics so load tests are observable in Grafana during runs:

```
ja4proxy_loadtest_connections_attempted_total   counter
ja4proxy_loadtest_connections_completed_total   counter
ja4proxy_loadtest_errors_total{reason}          counter
ja4proxy_loadtest_latency_seconds               histogram (buckets [0.0001, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 1.0])
ja4proxy_loadtest_throughput_cps                gauge
```

Register these metrics in `docs/OBSERVABILITY_STANDARDS.md` under a new `Load Testing` subsection.

### Gap 4 — No Grafana capacity planning dashboard

**Problem:** `monitoring/grafana/dashboards/` contains `analytics.json`, `ja4proxy-infrastructure.json`, `ja4proxy-overview.json`, `tap_sensor.json` — nothing for capacity planning. Phase 86's stated goal included "capacity planning with real data" but ships no visualization.

**Fix:** Add `monitoring/grafana/dashboards/04_capacity.json`, provisioned via `monitoring/grafana/provisioning/dashboards/default.yml`. Four rows:

- **Row 1 — Throughput headroom** — Current connections/s vs. published bypass-path ceiling (gauge 0–100%, red >80%); same for full-signal path. Ceiling values come from `benchmarks.md` via dashboard variables `$BYPASS_CEILING_CPS` and `$SIGNAL_CEILING_CPS`.
- **Row 2 — Latency budget** — Pipeline P99 trend (7d), P99 budget lines at 5ms/10ms, Redis-latency-vs-pipeline-latency heatmap (1h).
- **Row 3 — Scaling pressure** — Tarpit pool fill fraction, HAProxy backend queue depth (if scraped), Redis memory utilization.
- **Row 4 — 30-day growth trend** — Connections/s over 30d with linear regression trend line (Grafana built-in transform) + stat panel showing projected date of 80% ceiling crossover.

Audience is platform/capacity team, distinct from the SecOps (`ja4proxy-overview`) and Ops (`ja4proxy-infrastructure`) audiences. Do not merge panels into existing dashboards.

---

## Implementation plan

### Step 1 — Datadog Layer 1 (OpenMetrics config)

- Write `deploy/datadog/conf.d/openmetrics.d/ja4proxy.yaml` — one instance block per proxy node, `namespace: ja4proxy`, explicit metric allowlist.
- Validate with a Datadog Agent config parser test (YAML load + schema check).

### Step 2 — Datadog Layer 2 (narrowed custom check)

- Edit `deploy/datadog/checks/ja4proxy/check.py` — remove every `self.gauge` / `self.rate` that duplicates a Prometheus metric. Keep:
  - `self.service_check("ja4proxy.node_health", ...)`
  - `self.service_check("ja4proxy.redis_health", ...)`
  - Any derived gauge that cannot be expressed as a single Prometheus metric.
- Update docstring to reflect the two-layer pattern.
- Update tests in `tests/unit/test_datadog_integration.py` — the removed `gauge`/`rate` expectations must also be removed. The test should now verify the check emits **only** service checks.

### Step 3 — Dynatrace Prometheus scraping

- Edit `deploy/dynatrace/ja4proxy-extension/plugin.py` — replace `/api/v1/health/deep` polling with `/metrics` scraping. Inline minimal Prometheus text-format parser. Keep `topology` entity definition.
- Update `extension.yaml` metric declarations — new metric set sourced from Prometheus.
- Update tests in `tests/unit/test_dynatrace_extension.py`.

### Step 4 — Run benchmark suite, populate `benchmarks.md`

- Run `make bench` on the reference host. Record hardware / OS / Redis / Git SHA / Go and Python versions in the file header.
- Replace all `_(measure)_` placeholders in `docs/performance/benchmarks.md` with measured values from all 4 scenarios from Gap 3.
- Update `scripts/capacity_calculator.py` — rename `EstimatedConstants` back to `BenchmarkConstants`, set fields to measured values, remove the "ESTIMATED — NOT MEASURED" warning path (leave the `--require-measured` flag in — it's now a positive CI guard).
- **Risk note:** if no benchmark can be run in this environment, document the situation in `PHASE_86i_notes.md` and either (a) use the current `EstimatedConstants` values unchanged but relabeled to match the host, or (b) pause this step until a benchmark run is possible. The Datadog/Dynatrace/dashboard/load-test work can proceed independently.

### Step 5 — Load test scenario rewrite

- Edit `scripts/load_test.py` — replace `choices=["baseline","sustained","ramp"]` with the new four-scenario set. Each scenario maps to an explicit fingerprint distribution via a lookup table defined at module level.
- Import and use `scripts/tls-traffic-generator.py` — do not duplicate TLS connection logic.
- Add `--push-gateway URL` flag with 5 new Prometheus metrics.
- Update tests in `tests/unit/test_load_test.py`.

### Step 6 — Observability standards update

- Add new `Load Testing` subsection to `docs/OBSERVABILITY_STANDARDS.md §1d` registering the 5 `ja4proxy_loadtest_*` metrics.

### Step 7 — Grafana capacity dashboard

- Write `monitoring/grafana/dashboards/04_capacity.json` with the 4 rows described above.
- Add provisioning entry in `monitoring/grafana/provisioning/dashboards/default.yml`.
- Dashboard variables `BYPASS_CEILING_CPS` and `SIGNAL_CEILING_CPS` default to the measured values from Step 4.

### Step 8 — Close-out

Update `CHANGELOG.md`, `docs/phases/manifest.yaml`, run `make sync`, write `PHASE_86i_notes.md`, commit atomically on branch `claude/phase-86i-hardening`.

---

## Test strategy

### Unit tests

**`tests/unit/test_datadog_integration.py`** — updated:
- `test_check_emits_only_service_checks`: runs the check against a mocked `/api/v1/health/deep`, asserts that no `gauge`/`rate` is emitted for metrics that overlap with the Prometheus metric list.
- `test_openmetrics_config_is_valid_yaml_and_has_namespace`: loads the new `openmetrics.d/ja4proxy.yaml`, asserts `namespace: ja4proxy` and at least one metric allowlist entry.
- `test_openmetrics_config_one_instance_per_node`: asserts the `instances:` list has >1 entry (template), each with a `node` tag.

**`tests/unit/test_dynatrace_extension.py`** — updated:
- `test_plugin_parses_prometheus_text_format`: feeds a canonical Prometheus text exposition, asserts the parser yields expected metric key/value pairs.
- `test_plugin_handles_scrape_failure_gracefully`: mocks a failed HTTP scrape, asserts plugin emits a single error log line and no metrics (not a crash).
- `test_extension_yaml_topology_preserved`: loads `extension.yaml`, asserts topology entity type is still defined.

**`tests/unit/test_capacity_calculator.py`** — updated:
- `test_uses_measured_constants_from_benchmarks_md`: loads the post-Step 4 `benchmarks.md`, asserts the calculator's `BenchmarkConstants` match.
- `test_require_measured_succeeds_after_phase_86i`: regression — after 86i Step 4, `--require-measured` must exit 0.
- `test_no_estimated_banner_in_clean_report`: captures stdout on a clean run, asserts "ESTIMATED" banner is absent.

**`tests/unit/test_load_test.py`** — updated:
- `test_scenarios_include_required_four`: asserts `bypass-only`, `full-signal`, `attack-wave`, `mixed` are all accepted.
- `test_scenario_fingerprint_distributions`: asserts each scenario's distribution sums to 100%.
- `test_load_test_imports_tls_traffic_generator`: asserts the import — guards against re-duplication.
- `test_pushgateway_flag_emits_metrics`: runs a short load test against a mock Pushgateway, asserts all 5 metric names appear.

**`tests/unit/test_phase_86i_grafana_dashboard.py`** — new:
- `test_04_capacity_json_parses`: loads the dashboard file, asserts valid Grafana JSON schema.
- `test_dashboard_has_four_rows`: asserts `rows` count.
- `test_dashboard_uses_ceiling_variables`: asserts `BYPASS_CEILING_CPS` and `SIGNAL_CEILING_CPS` templated variables are defined.
- `test_dashboard_provisioned_in_default_yml`: loads `monitoring/grafana/provisioning/dashboards/default.yml`, asserts `04_capacity.json` is listed.

### Integration tests

**`tests/integration/test_phase_86i_benchmarks_populated.py`** — new:
- `test_benchmarks_md_has_no_placeholders`: scans the file, asserts zero `_(measure)_` markers in the Go Proxy Benchmarks section.
- `test_benchmarks_md_has_hardware_header`: asserts hardware / OS / Git SHA / Go version fields are all populated.

**`tests/integration/test_phase_86i_observability_standards.py`** — new:
- `test_observability_standards_registers_loadtest_metrics`: greps `docs/OBSERVABILITY_STANDARDS.md` for each of the 5 new metric names.

### Not testing

- Running the actual benchmark is not a test — it's a one-off implementation step.
- Dashboard rendering in a live Grafana is not automated (would require docker-compose spin-up). Manual verification documented in `PHASE_86i_notes.md`.

---

## Acceptance criteria

### Datadog

- [ ] `deploy/datadog/conf.d/openmetrics.d/ja4proxy.yaml` present and valid.
- [ ] `deploy/datadog/checks/ja4proxy/check.py` emits only service checks and derived gauges — no Prometheus-duplicate metrics.
- [ ] `tests/unit/test_datadog_integration.py` updated and passing.

### Dynatrace

- [ ] `deploy/dynatrace/ja4proxy-extension/plugin.py` scrapes `/metrics` instead of polling `/api/v1/health/deep`.
- [ ] Minimal Prometheus text-format parser handles standard exposition cases (counter, gauge, histogram).
- [ ] `extension.yaml` topology entity preserved.
- [ ] `tests/unit/test_dynatrace_extension.py` updated and passing.

### Benchmarks + calculator

- [ ] `docs/performance/benchmarks.md` contains zero `_(measure)_` placeholders.
- [ ] Hardware / OS / Redis / Git SHA / Go / Python versions documented in file header.
- [ ] `scripts/capacity_calculator.py` `BenchmarkConstants` match measured values.
- [ ] "ESTIMATED — NOT MEASURED" warning path from 86h removed.
- [ ] `--require-measured` flag exits 0 on clean benchmarks.md.

### Load test

- [ ] `scripts/load_test.py` accepts `bypass-only`, `full-signal`, `attack-wave`, `mixed`.
- [ ] Each scenario has a documented fingerprint distribution in code + docstring.
- [ ] `load_test.py` imports `tls-traffic-generator.py` rather than duplicating its logic.
- [ ] `--push-gateway` flag emits all 5 `ja4proxy_loadtest_*` metrics to a configurable Pushgateway URL.

### Observability standards

- [ ] `docs/OBSERVABILITY_STANDARDS.md` has a new Load Testing subsection registering all 5 metrics.

### Grafana dashboard

- [ ] `monitoring/grafana/dashboards/04_capacity.json` exists and is valid Grafana JSON.
- [ ] 4 rows as specified (Throughput Headroom, Latency Budget, Scaling Pressure, 30-Day Growth).
- [ ] Dashboard variables `BYPASS_CEILING_CPS` and `SIGNAL_CEILING_CPS` defined.
- [ ] Dashboard provisioned in `monitoring/grafana/provisioning/dashboards/default.yml`.

### Global

- [ ] All new/updated unit tests pass.
- [ ] All new integration tests pass.
- [ ] `make test` passes with zero failures, zero warnings.
- [ ] `make lint-phases` exits 0.
- [ ] `CHANGELOG.md` has a Phase 86i entry.
- [ ] `docs/phases/manifest.yaml` updated: `86i` status `COMPLETE`.
- [ ] `PHASE_86i_notes.md` written — must document: whether a real benchmark was run, the host used, and any values estimated vs. measured.
- [ ] Branch pushed to `claude/phase-86i-hardening`.

---

## Out of scope

- Writing full content for runbook stubs created in Phase 86h.
- Rewriting any already-correct Nagios, Zabbix, or Splunk/SOAR integrations.
- Adding new alerts, new scoring signals, or new proxy capabilities.
- Rebranding or restructuring existing Grafana dashboards (`ja4proxy-overview.json`, `ja4proxy-infrastructure.json`).
- Go proxy core changes beyond what the load test already exercises.

---

## Risk & rollback

- **Risk:** The two-layer Datadog refactor breaks existing deployments that have the custom check installed. **Mitigation:** Document the migration in `CHANGELOG.md` explicitly — "if upgrading, also install the new OpenMetrics check config, otherwise per-label metrics will disappear from dashboards." Rollback is `git revert` on the check.py + test commit.
- **Risk:** Dynatrace Prometheus parser doesn't handle a histogram exposition correctly. **Mitigation:** Unit tests against canonical exposition examples. If histograms are too complex for the minimal parser, the plan falls back to shipping only counters and gauges in the extension, with a note.
- **Risk:** No reference hardware available for Step 4. **Mitigation:** Documented in Step 4 itself — use the dev host and label it honestly.
- **Risk:** Grafana dashboard JSON drifts from live Grafana's version. **Mitigation:** Grafana JSON is forward-compatible; document the Grafana version used during authoring in `PHASE_86i_notes.md`.
