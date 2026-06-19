# Observability & Capacity Planning — Phase 86

> **Last rewritten:** 2026-04-10 — full rewrite with 7 independent sub-phases.

---

## Goal

Enterprise platform teams need to answer three questions no previous phase directly addresses:

1. **"Is JA4proxy healthy right now?"** — in their monitoring tool (Datadog, Dynatrace, Nagios, Zabbix)
2. **"Will it handle next month's traffic?"** — capacity planning with real data
3. **"How fast is it actually?"** — published, reproducible benchmark numbers

This phase delivers integrations with enterprise monitoring tools, a capacity sizing toolkit, a load testing harness, and 7 alert runbooks.

---

## Scope

| Sub-Phase | Deliverable | New files | Modified files |
|-----------|------------|-----------|----------------|
| **86a** | Management API summary endpoint — Python + Go | `src/management/routes/summary.py` (new route handler) | `src/management/app.py` (+1 route), `cmd/proxy/main.go` (deep health + `/summary` handlers), `docs/reference/REDIS_SCHEMA.md` |
| **86b** | Load testing harness + benchmark run | `scripts/load_test.py`, `scripts/load_test/` (TLS fingerprint fixtures) | `Makefile` (`load-test`, `load-test-report` targets), `docs/performance/benchmarks.md` (published numbers) |
| **86c** | Capacity sizing calculator | `scripts/capacity_calculator.py` | None |
| **86d** | Datadog integration | `deploy/datadog/checks/ja4proxy/check.py`, `deploy/datadog/checks/ja4proxy/__init__.py`, `deploy/datadog/ja4proxy-dashboard.json`, `deploy/datadog/ja4proxy-monitors.json`, `deploy/datadog/conf.d/ja4proxy.d/conf.yaml` | `docs/RELEASE_NOTES.md` (install instructions) |
| **86e** | Dynatrace EF2 extension | `deploy/dynatrace/ja4proxy-extension/extension.yaml` + plugin files | None |
| **86f** | Nagios check + Zabbix template | `deploy/nagios/check_ja4proxy.py`, `deploy/zabbix/ja4proxy-template.xml` | None |
| **86g** | Alert runbooks + `runbook_url` annotations | 7 runbooks in `docs/runbooks/` (see §86g below) | `monitoring/alertmanager/rules/slo_alerts.yml` (add `runbook_url`), `monitoring/alertmanager/rules/tls_alerts.yml` (add `runbook_url`) |

### Out of Scope

- Phase 79 features (RBAC, SSO) — Phase 86 reads from existing endpoints, no auth work.
- New proxy capabilities (signals, scoring, bypass rules) — zero changes to `internal/security/`.
- Go proxy core — only `cmd/proxy/main.go` handlers are touched (sub-86a only).
- Python proxy core — only `src/management/app.py` routes are touched (sub-86a only).

---

## Sub-Phase 86a — Management API Summary Endpoint

**Goal:** Add `/api/v1/health/deep` and `/api/v1/metrics/summary` endpoints to both Python and Go proxies. All monitoring integrations (Datadog, Dynatrace, Nagios, Zabbix) call these endpoints. They must exist before 86d/86e/86f can work.

**Python (`src/management/app.py`):**
- Add `GET /api/v1/health/deep` — extends existing `/api/v1/health` with:
  - `cert_days_remaining` (from existing `TLSCertExpiryTimestampSeconds` gauge value via Redis or Prometheus scrape)
  - `active_connections` (from `ja4proxy_active_connections`)
  - `connections_total` (from `ja4proxy_connections_total`)
  - `block_rate_pct` (computed from `ja4proxy_connections_total{action=block}` / total × 100)
  - `active_bans` (Redis `KEYS ja4proxy:ban:* | wc -l` or from a dedicated counter)
  - `redis_latency_ms` (existing `PING` RTT)
- Add `GET /api/v1/metrics/summary` — returns the above fields as a single JSON object, designed for single-call monitoring polling.

**Go (`cmd/proxy/main.go`):**
- Add `/health/deep` handler — same fields as Python.
  - Reads Prometheus gauge values directly (already registered in `internal/metrics/metrics.go`)
  - Redis latency from `Ping` with timing
  - Cert expiry from existing `TLSCertExpiryTimestampSeconds` gauge
  - Active connections from `ActiveConnections` gauge
  - Connections total from `ConnectionsTotal` counter
  - Block rate: compute from counter snapshot
  - Active bans: Redis `DBSIZE` approximation or `KEYS ja4proxy:ban:* COUNT` (Redis 7+)
- Add `/metrics/summary` handler — same JSON schema as Python.

**Tests:**
- Python: unit test for `/api/v1/health/deep` (mock Redis, mock Prometheus registry) — asserts status codes and JSON schema.
- Python: unit test for `/api/v1/metrics/summary` — same.
- Python: test page rendering test for both routes (per AGENTS.md §Web service TDD).
- Go: unit test for both handlers with `httptest.NewRecorder`.
- Integration test: both endpoints return 200 with valid JSON when stack is running.

**Acceptance criteria:**
- `curl http://localhost:8090/api/v1/health/deep` returns 200 with all 8 fields.
- `curl http://localhost:9090/health/deep` (Go metrics port) returns 200 with all 8 fields.
- `curl http://localhost:8090/api/v1/metrics/summary` returns 200 with same schema.
- `curl http://localhost:9090/metrics/summary` returns 200 with same schema.
- Python unit tests pass: `pytest tests/unit/test_health_summary.py -v`
- Go unit tests pass: `GOROOT=/snap/go/current go test ./cmd/proxy/... -run TestHealthDeep`

---

## Sub-Phase 86b — Load Testing Harness + Benchmark Run

**Goal:** A TLS-aware load generator that produces realistic traffic distributions and measures throughput/latency/error-rate. Reuses existing `scripts/benchmark_comparison.py` engine for the heavy lifting, but adds a standalone harness that works against a single target (no Python vs Python comparison needed).

**Note:** The existing `scripts/benchmark-go-python.sh` + `scripts/benchmark_comparison.py` already implement the benchmark engine. Phase 86b does NOT rewrite it. It adds:
1. A thin wrapper `scripts/load_test.py` that calls `benchmark_comparison.py` with a single-target config.
2. `Makefile` targets: `load-test`, `load-test-baseline`, `load-test-report`.
3. A benchmark results directory `docs/performance/benchmarks.md` populated by running the harness.

**`scripts/load_test.py`:**
```
Usage:
  python3 scripts/load_test.py --target localhost:8080 --duration 60 --rps 1000 --scenario mixed

Scenarios:
  mixed      — 70% browser (h2/h1), 20% automation, 5% scanner, 5% malicious
  browser    — 100% real browser fingerprints
  attack     — 100% malicious fingerprints
  sustained  — ramp to target RPS and hold for duration
  ramp       — linear ramp from 100 to target RPS over 60s
```

- Reuses the TLS client machinery from `benchmark_comparison.py` (synthetic ClientHello generation).
- Outputs: JSON report with throughput, P50/P95/P99 latency, block rate, error rate.
- Optionally reads Prometheus metrics from `/metrics/summary` endpoint (added in 86a) for CPU/memory correlation.

**`Makefile` targets:**
```makefile
## Phase 86 — Load testing
load-test:
	@echo "Running JA4proxy load test..."
	python3 scripts/load_test.py \
		--target $(LOAD_TEST_TARGET) \
		--duration $(LOAD_TEST_DURATION) \
		--rps $(LOAD_TEST_RPS) \
		--scenario $(LOAD_TEST_SCENARIO)

load-test-baseline:
	LOAD_TEST_TARGET=localhost:8080 \
	LOAD_TEST_DURATION=60 \
	LOAD_TEST_RPS=1000 \
	LOAD_TEST_SCENARIO=baseline \
	$(MAKE) load-test

load-test-report:
	@echo "Latest benchmark reports:"
	@ls -lt docs/performance/benchmarks/ 2>/dev/null | head -5 || echo "No reports found"
```

**Benchmark run (`docs/performance/benchmarks.md`):**
- Run the harness against Go proxy on reference hardware (document actual CPU/RAM/OS/Redis).
- Publish results for: bypass path, full signal path, Redis latency sensitivity, memory footprint.
- Numbers must be **measured** — not estimated. Run `make bench -- --proxy go --no-docker --skip-build` as the primary source, plus `make load-test-baseline` for the load test.

**Tests:**
- Unit test for `load_test.py` argument parsing and report generation.
- Integration test: run 10-second load test against mock backend, verify report JSON is valid.
- Test verifies report schema matches expected fields (throughput, latencies, error rate).

**Acceptance criteria:**
- `make load-test-baseline` runs for 60s against a local proxy and produces a JSON report.
- Report contains: throughput (conn/s), P50/P95/P99 latency, block rate, error rate.
- `docs/performance/benchmarks.md` populated with measured Go proxy numbers on reference hardware.
- Unit tests for `load_test.py` pass.

---

## Sub-Phase 86c — Capacity Sizing Calculator

**Goal:** A script that takes traffic parameters and outputs a capacity recommendation. Must be wired to **real benchmark numbers** from 86b, not placeholders.

**`scripts/capacity_calculator.py`:**
```
Usage:
  python3 scripts/capacity_calculator.py \
    --peak-connections-per-second 5000 \
    --p99-latency-budget-ms 10 \
    --redis-node-count 3 \
    --enable-analytics \
    --enable-beaconing-detection \
    --enable-abuseipdb \
    --cloud-provider aws \
    --region us-east-1
```

**Constants sourced from 86b benchmark run (read from `docs/performance/benchmarks.md` or a companion JSON file):**
- `GO_BYPASS_CONN_S` — single node bypass path throughput
- `GO_FULL_CONN_S` — single node full signal path throughput
- `GO_P99_BYPASS_MS` — bypass path P99 latency
- `GO_P99_FULL_MS` — full signal path P99 latency
- `REDIS_MEM_PER_KEY` — average Redis memory per key
- `ANALYTICS_BYTES_PER_CONN` — analytics storage per connection

**Methodology:**
- Proxy node count = `ceil(peak_rps / GO_FULL_CONN_S) + 1` (N+1 redundancy)
- Redis memory = `key_count × REDIS_MEM_PER_KEY × 1.3` (overhead factor)
- Analytics storage = `bytes_per_conn × peak_rps × 86400 × retention_days`
- All calculations include 50% headroom for peak spikes

**Tests:**
- Unit tests for sizing formulas (proxy count, Redis memory, analytics storage).
- Test with known inputs (1000, 5000, 50000 rps) and assert expected node counts.
- Test edge cases: 0 rps, 1M rps, negative inputs (should error gracefully).

**Acceptance criteria:**
- Produces valid recommendations for 100–100,000 conn/s inputs.
- Output includes: proxy node count, CPU/RAM per node, Redis sizing, analytics sizing, cloud cost estimate.
- Constants sourced from real 86b benchmark data (not hardcoded estimates).
- Unit tests pass.

---

## Sub-Phase 86d — Datadog Integration

**Goal:** A first-class Datadog Agent integration that polls the management API and emits metrics, plus a pre-built dashboard and 4 monitors.

**`deploy/datadog/checks/ja4proxy/check.py`:**
- Datadog Agent check subclass (`AgentCheck`).
- Polls `GET /api/v1/health/deep` on each configured node.
- Emits Datadog metrics under `ja4proxy.*` namespace:
  - `ja4proxy.node.healthy` (gauge, 0/1)
  - `ja4proxy.node.redis_latency_ms` (gauge)
  - `ja4proxy.node.dial_setting` (gauge)
  - `ja4proxy.node.cert_days_remaining` (gauge)
  - `ja4proxy.connections.active` (gauge)
  - `ja4proxy.connections.total` (rate)
  - `ja4proxy.blocks.total` (rate)
  - `ja4proxy.block_rate_pct` (gauge)
  - `ja4proxy.bans.active` (gauge)
- Service check: `ja4proxy.node_health` (OK/CRITICAL based on health status).
- Timeout handling: fail-open (log warning, emit UNKNOWN service check) on HTTP error.

**`deploy/datadog/checks/ja4proxy/__init__.py`:** — Package init.

**`deploy/datadog/conf.d/ja4proxy.d/conf.yaml`:**
```yaml
init_config:

instances:
  - management_url: "https://ja4proxy-mgmt.corp.internal"
    api_token: "ENC[datadog_secret:ja4proxy_api_token]"
    nodes:
      - "ja4proxy-prod-01"
      - "ja4proxy-prod-02"
    min_collection_interval: 30
```

**`deploy/datadog/ja4proxy-dashboard.json`:**
- Node health topology map (one widget per node, green/red).
- Connection throughput timeseries.
- Block rate timeseries with threshold annotations (2% warning, 10% critical).
- Active bans gauge.
- Redis latency heatmap across nodes.
- Dial setting history.
- Certificate expiry countdown (critical at ≤30 days).

**`deploy/datadog/ja4proxy-monitors.json`:**
- `JA4proxy node unhealthy` — service check alert, pages SecOps on-call.
- `JA4proxy Redis latency high` — >50ms for 5 minutes.
- `JA4proxy certificate expiring` — <30 days.
- `JA4proxy block rate anomaly` — >5% sustained for 15 minutes.

**Tests:**
- Unit tests for the check class — mock HTTP responses for OK, degraded, error.
- Test that service check status matches health response.
- Test that metrics are emitted with correct names and tags.
- Container configuration parity test: verify `conf.yaml` env vars match Docker Compose structure.

**Acceptance criteria:**
- `check.py` installable as Datadog Agent custom check.
- Emits all 9 metric types with correct names and tags.
- Dashboard JSON is valid Datadog dashboard format.
- Monitors JSON is valid Datadog monitor format.
- Unit tests pass with mocked HTTP.

---

## Sub-Phase 86e — Dynatrace EF2 Extension

**Goal:** A Dynatrace Extension Framework 2 extension that defines a custom topology entity type and emits metrics via REST polling.

**`deploy/dynatrace/ja4proxy-extension/extension.yaml`:**
```yaml
name: custom:ja4proxy
version: "1.0.0"
minDynatraceVersion: "1.270"
author:
  name: JA4proxy

metrics:
  - key: ext:ja4proxy.node.healthy
    metadata:
      displayName: Node Health
      unit: Count
  - key: ext:ja4proxy.connections.active
    metadata:
      displayName: Active Connections
      unit: Count
  - key: ext:ja4proxy.block_rate
    metadata:
      displayName: Block Rate
      unit: Percent
  - key: ext:ja4proxy.redis.latency_ms
    metadata:
      displayName: Redis Latency
      unit: MilliSecond

topology:
  types:
    - name: ja4proxy:node
      displayName: JA4proxy Node
      rules:
        - sources:
            - sourceType: Metrics
              condition: "$prefix(ext:ja4proxy)"
          attributes:
            - pattern: "{node}"
              key: node_name
```

**Implementation notes:**
- EF2 uses REST datasource (not WMI — WMI is Windows-only). The extension polls `GET /api/v1/health/deep`.
- Tag metrics with `environment:production` and `ja4proxy_node:{hostname}` for Davis AI correlation.
- Include `install.sh` script for one-line installation.

**Tests:**
- Validate `extension.yaml` against Dynatrace EF2 schema (structure validation).
- Test metric key naming matches specification.
- Test topology entity type definition is valid YAML.

**Acceptance criteria:**
- `extension.yaml` is valid EF2 format.
- Defines 4 metrics and 1 topology entity type.
- Includes installation instructions in `README.md`.
- Validation tests pass.

---

## Sub-Phase 86f — Nagios Check + Zabbix Template

**Goal:** For enterprises running legacy monitoring, deliver Nagios-compatible check plugin and Zabbix importable template.

### Nagios Check

**`deploy/nagios/check_ja4proxy.py`:**
```
Usage: check_ja4proxy.py --url https://ja4proxy-mgmt --token $TOKEN --check health|dial|redis|cert

Returns:
  0 = OK
  1 = WARNING
  2 = CRITICAL
  3 = UNKNOWN

Perfdata: 'metric_name'=value;warn;crit;min;max
```

- Calls `GET /api/v1/health/deep`.
- Parses JSON response.
- `--check health`: OK if status=="ok", WARNING if degraded, CRITICAL if error.
- `--check redis`: WARNING if redis_latency_ms > 20, CRITICAL if > 50.
- `--check cert`: WARNING if cert_days_remaining < 30, CRITICAL if < 7.
- `--check dial`: WARNING if dial != expected value (configurable via `--expected-dial`).
- Outputs Nagios perfdata format on stdout.

### Zabbix Template

**`deploy/zabbix/ja4proxy-template.xml`:**
- HTTP agent items polling `/api/v1/health/deep` (Zabbix built-in HTTP checks — no custom script needed).
- Dependent items extracting Redis latency, dial setting, active connections via JSONPath.
- Triggers: node unhealthy, Redis latency > 50ms, cert expiry ≤ 30 days.
- Graph prototypes for connection rate and block rate.
- Host macro `{$JA4PROXY_TOKEN}` for API authentication.

**Tests:**
- Nagios: unit test exit codes for each check type with mock responses.
- Nagios: test perfdata format compliance.
- Nagios: container configuration parity test.
- Zabbix: validate XML against Zabbix template XSD (or at minimum, well-formed XML).

**Acceptance criteria:**
- `check_ja4proxy.py` returns correct exit codes (0/1/2/3) for all 4 check types.
- Nagios perfdata output matches Nagios plugin format specification.
- Zabbix template XML is well-formed and importable.
- Unit tests pass.

---

## Sub-Phase 86g — Alert Runbooks + `runbook_url` Annotations

**Goal:** Every Alertmanager rule must link to an actual runbook page. This sub-phase creates the 7 runbooks and adds `runbook_url` annotations to existing alert rules.

### New Runbooks (7 files in `docs/runbooks/`)

| File | Alert it documents |
|------|-------------------|
| `ja4proxy_node_unhealthy.md` | Node health degradation |
| `ja4proxy_redis_latency_high.md` | Redis latency > 50ms |
| `ja4proxy_certificate_expiring.md` | TLS cert < 30 days (warning) / < 7 days (critical) |
| `ja4proxy_block_rate_high.md` | Block rate > 2% (warning) / > 10% (critical) |
| `ja4proxy_campaign_detected.md` | Coordinated attack campaign detected |
| `ja4proxy_dial_change_unexpected.md` | Dial changed without authorized ticket |
| `ja4proxy_tarpit_pool_full.md` | Tarpit connection pool exhausted |

### Standard Runbook Format

Each runbook follows this structure:
```markdown
# Runbook: ja4proxy_<name>

## Severity
WARNING → CRITICAL (with thresholds)

## What is happening
Brief description of the alert condition.

## Impact
- High: Worst-case scenario
- Low: Best-case scenario (expected behaviour)

## Diagnosis
1. Step-by-step diagnostic commands
2. Grafana dashboard checks
3. Management CLI commands

## Resolution
- If campaign: ...
- If FP wave: ...
- If false raise: ...

## Escalation
When and who to page.
```

### Alert Rule Updates

**`monitoring/alertmanager/rules/slo_alerts.yml`** — Add `runbook_url` annotations to all existing SLO alerts. Do NOT modify alert conditions, thresholds, or `for` durations.

**`monitoring/alertmanager/rules/tls_alerts.yml`** — Add `runbook_url` annotations to existing TLS cert expiry alerts.

### New Makefile Target

```makefile
## Phase 86 targets — add runbook_url annotations to existing Alertmanager rules
update-alertmanager-runbook-urls:
	@echo "Adding runbook_url annotations to alertmanager rules..."
	# Script that patches runbook_url annotations into existing rules
	python3 scripts/patch_alerturls.py
```

**Note:** Per CLAUDE.md file ownership rules, this target is ADDITIVE — it adds new Makefile targets, does not modify existing Phase 14e targets. The actual alert rule YAML files can be edited since they are infrastructure files being extended.

### Tests

- Unit test: each runbook file exists and contains all required sections (Severity, Impact, Diagnosis, Resolution, Escalation).
- Integration test: `runbook_url` annotations in alertmanager rules resolve to actual files.
- Shellcheck: if `patch_alerturls.py` calls any shell scripts, they pass shellcheck.

**Acceptance criteria:**
- All 7 runbook files present with correct format (all 5 sections present).
- All existing SLO alerts in `slo_alerts.yml` have `runbook_url` annotations.
- All existing TLS alerts in `tls_alerts.yml` have `runbook_url` annotations.
- `make update-alertmanager-runbook-urls` runs without error.
- Validation tests pass.

---

## Execution Order and Independence

| Sub-Phase | Depends On | Can Run In Parallel With | Engineer Level |
|-----------|-----------|-------------------------|----------------|
| **86a** | None | 86b, 86g | Mid (needs Python + Go) |
| **86b** | None (but benefits from 86a `/metrics/summary` for CPU correlation) | 86a, 86c, 86d, 86e, 86f, 86g | Mid |
| **86c** | 86b (for benchmark constants) | 86d, 86e, 86f, 86g | Junior |
| **86d** | 86a (endpoint must exist) | 86b, 86c, 86e, 86f, 86g | Mid |
| **86e** | 86a (endpoint must exist) | 86b, 86c, 86d, 86f, 86g | Mid |
| **86f** | 86a (endpoint must exist) | 86b, 86c, 86d, 86e, 86g | Junior |
| **86g** | None | 86a, 86b, 86c, 86d, 86e, 86f | Junior |

**Recommended execution order:** 86a → (86d, 86e, 86f in parallel) → 86b → 86c → 86g. Or 86g can run at any time since it has no dependencies.

---

## Test Strategy

Each sub-phase has its own test suite:

| Sub-Phase | Test Categories |
|-----------|----------------|
| 86a | Python unit (mock Redis, mock Prometheus), Go unit (`httptest`), integration (live stack) |
| 86b | Unit (arg parsing, report schema), integration (10s load test against mock backend) |
| 86c | Unit (sizing formulas, edge cases: 0/1M/negative rps) |
| 86d | Unit (mock HTTP responses, service check status, metric emission), container config parity |
| 86e | Validation (YAML schema, metric key naming, topology entity type) |
| 86f | Unit (Nagios exit codes, perfdata format), XML well-formedness (Zabbix) |
| 86g | File existence + section validation, `runbook_url` resolution test |

---

## Acceptance Criteria (All Sub-Phases)

- [ ] 86a: `/api/v1/health/deep` returns 200 with all 8 fields (Python + Go)
- [ ] 86a: `/api/v1/metrics/summary` returns 200 with same schema (Python + Go)
- [ ] 86a: Python unit tests pass
- [ ] 86a: Go unit tests pass (`GOROOT=/snap/go/current go test ./cmd/proxy/... -run TestHealth`)
- [ ] 86b: `make load-test-baseline` runs and produces valid JSON report
- [ ] 86b: `docs/performance/benchmarks.md` populated with measured Go proxy numbers
- [ ] 86b: Unit tests for `load_test.py` pass
- [ ] 86c: Calculator produces valid output for 100–100,000 conn/s
- [ ] 86c: Calculator output includes cloud cost estimates (AWS and Azure)
- [ ] 86c: Unit tests for sizing formulas pass
- [ ] 86d: Datadog check emits all 9 metric types
- [ ] 86d: Dashboard JSON is valid Datadog format
- [ ] 86d: Monitors JSON is valid Datadog format
- [ ] 86d: Unit tests pass (mock HTTP)
- [ ] 86e: `extension.yaml` is valid EF2 format
- [ ] 86e: Defines 4 metrics and 1 topology entity type
- [ ] 86e: Validation tests pass
- [ ] 86f: Nagios check returns correct exit codes for all 4 check types
- [ ] 86f: Nagios perfdata format is compliant
- [ ] 86f: Zabbix template is well-formed XML
- [ ] 86f: Unit tests pass
- [ ] 86g: All 7 runbook files present with all 5 required sections
- [ ] 86g: All SLO alerts have `runbook_url` annotations
- [ ] 86g: All TLS alerts have `runbook_url` annotations
- [ ] 86g: `make update-alertmanager-runbook-urls` runs without error
- [ ] `make test` passes with zero failures, zero warnings
- [ ] `make go-test` passes with zero failures
- [ ] `make lint-phases` exits 0

---

## Phase Close-Out Checklist

1. Tests pass: `make test` — zero failures, zero warnings
2. Go tests pass: `make go-test` — zero failures
3. CHANGELOG.md: Add entry for Phase 86
4. REDIS_SCHEMA.md: Document any new Redis keys (86a may add `ja4proxy:metrics:cache` if caching the summary)
5. Update `docs/phases/manifest.yaml`: status COMPLETE, completed date
6. Run `make sync`: regenerate TODO.md and PROJECT_STATUS.md
7. Run `make lint-phases`: must exit 0
8. Atomic commit of all artifacts
