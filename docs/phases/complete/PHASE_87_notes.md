# Phase 87 — Implementation Notes

**Agent E Critical Review — 2026-04-06**

---

## Summary

The Phase 87 implementation is high quality overall. All 28 tests pass, the 5 new alert
groups are structurally correct, the 6 infra recording rules are valid with proper
division guards, and the runbook anchors align 1:1 with every `runbook_url` in the
alert rules. Two issues were found and fixed: a misplaced thresholds block in the
Grafana dashboard JSON, and a missing auth credential + incorrect CSV suffix in the
HAProxy exporter URI.

---

## Findings

### Check 1: Container name consistency
- **Status: PASS**
- Docker Compose services in `docker/docker-compose.poc.yml`: `haproxy`, `proxy`, `redis`,
  `backend`, `tarpit`, `analytics`, `management` (no explicit `container_name`, so
  names follow `<project>-<service>-<replica>` pattern).
- Monitoring containers in `docker/docker-compose.monitoring.yml`: all prefixed
  `ja4proxy-*` (explicit `container_name`).
- Alert patterns `name=~"ja4proxy.*|proxy|redis|analytics"` correctly match all
  relevant containers via substring matching. The broad `ja4proxy.*` also covers
  monitoring containers (cadvisor, grafana, etc.), which is intentional — those should
  also be covered by OOM and restart-loop alerts.
- The tighter pattern `name=~"proxy|redis|analytics"` on `ContainerCPUThrottleHigh` is
  intentional (only critical data-path containers get the throttle alert).

### Check 2: HAProxy stats endpoint
- **Status: PASS (with fix)**
- `config/haproxy.cfg` exposes the stats frontend on `:8404` with `stats uri /stats`.
  HAProxy 2.8 supports `${VAR:-default}` substitution natively, so the auth defaults
  to `admin:admin123`.
- **Issue found:** The exporter command used `?stats;csv` (query-string form) instead
  of `;csv` (HAProxy path-parameter form). More critically, no auth credentials were
  included in the scrape URI, which would cause 401 responses from HAProxy.
- **Fix applied:** Updated `docker/docker-compose.monitoring.yml` haproxy-exporter
  command to `http://${HAPROXY_STATS_USER:-admin}:${HAPROXY_STATS_PASSWORD:-admin123}@haproxy:8404/stats;csv`.
  This uses the correct `;csv` path suffix and includes credentials matching
  `haproxy.cfg` defaults. Note: the acceptance criteria in `PHASE_87.md` explicitly
  said `?stats;csv` — this is considered a spec bug since the fix is more correct.

### Check 3: Recording rule references
- **Status: PASS**
- All 6 recording rules in `ja4proxy_infra_aggregations`:
  - `ja4proxy:cpu_utilization:pct` — referenced by `NodeHighCPU`, `NodeCriticalCPU`
  - `ja4proxy:load_normalized` — referenced by `NodeHighLoad`, `NodeCriticalLoad`
  - `ja4proxy:filefd_utilization:pct` — referenced by `NodeFileDescriptorsHigh`, `NodeFileDescriptorsCritical`
  - `ja4proxy:container_mem_pct` — referenced by `ContainerMemoryHigh`
  - `ja4proxy:container_cpu_throttle_ratio` — referenced by `ContainerCPUThrottleHigh`
  - `ja4proxy:network_avg_pkt_size_bytes` — referenced by `SYNFloodIndicator`
- All names match exactly. No typos or cross-rule naming inconsistencies.

### Check 4: Division by zero guards
- **Status: PASS**
- `container_spec_memory_limit_bytes` divided with `clamp_min(..., 1)` — correct.
- `container_cpu_usage_seconds_total` rate divided with `clamp_min(..., 1e-6)` — correct.
- `node_network_receive_packets_total` rate divided with `clamp_min(..., 1)` — correct.
- `ConnectionRateSpike` baseline divided with `clamp_min(..., 0.1)` — correct (prevents
  3× zero = zero false positive at proxy startup when no traffic has flowed yet).

### Check 5: Stale recording rules fixed
- **Status: PASS**
- `ja4_requests_total` and `ja4_blocked_requests_total` no longer appear anywhere in
  `recording_rules.yml`. The old `ja4proxy_aggregations` and `ja4proxy_performance`
  groups now correctly reference `ja4proxy_connections_total`.

### Check 6: Dashboard datasource UID
- **Status: PASS**
- `monitoring/grafana/provisioning/datasources/prometheus.yml` defines UID:
  `PBFA97CFB590B2093`.
- All panels and template variables in `ja4proxy-infrastructure.json` use exactly this
  UID. `ja4proxy-overview.json` also uses the same UID. No mismatches found.

### Check 7: No duplicate panel IDs
- **Status: PASS**
- `ja4proxy-overview.json` panel IDs: `[1, 2, 3, 4, 5, 6, 10, 11, 20, 21, 30, 31, 32, 40, 41, 42, 50, 51, 60, 61]`
- `ja4proxy-infrastructure.json` panel IDs: `[101..111, 121..129, 141..144, 161..166, 181..189, 201..205]`
- No overlap. The infra dashboard was deliberately designed with IDs ≥ 100.

### Check 8: Threshold alignment (600 conn/s)
- **Status: PASS (with fix)**
- `ConnectionRateSustainedHigh` alert fires at `> 600` conn/s.
- Dashboard panel 201 ("Connection Rate: Live vs 1h Baseline") contains threshold steps:
  yellow at 200, red at 600.
- **Issue found:** The threshold block was placed at `fieldConfig.thresholds` (incorrect)
  instead of `fieldConfig.defaults.thresholds` (Grafana-correct location). Grafana
  silently ignores thresholds not inside `defaults`.
- **Fix applied:** Moved the threshold block into `fieldConfig.defaults.thresholds` in
  `monitoring/grafana/dashboards/ja4proxy-infrastructure.json`.

### Check 9: Image tags pinned
- **Status: PASS**
- `cadvisor`: `gcr.io/cadvisor/cadvisor:v0.47.2` — pinned, not `:latest`.
- `haproxy-exporter`: `prom/haproxy-exporter:v0.15.0` — pinned, not `:latest`.

### Check 10: Runbook sections
- **Status: PASS** (note: 30 sections, not 29 as stated in phase spec)
- Runbook contains exactly 30 `##` headings, one per alert in the 5 new groups.
- All 30 `runbook_url` values in `alerts.yml` have exact matching anchors in the
  runbook. No broken links, no missing sections.
- The phase spec said "29 sections" but there are 30 alerts (12 + 4 + 4 + 3 + 7 = 30).
  This is a minor discrepancy in the spec; the implementation is correct.

---

## Fixes Applied

1. **`monitoring/grafana/dashboards/ja4proxy-infrastructure.json`** — Moved threshold
   steps (transparent at null, yellow at 200, red at 600) from `fieldConfig.thresholds`
   into `fieldConfig.defaults.thresholds` for panel 201 ("Connection Rate: Live vs 1h
   Baseline"). Without this fix, Grafana would ignore the threshold lines entirely.

2. **`docker/docker-compose.monitoring.yml`** — Updated haproxy-exporter scrape URI
   from `http://haproxy:8404/stats?stats;csv` to
   `http://${HAPROXY_STATS_USER:-admin}:${HAPROXY_STATS_PASSWORD:-admin123}@haproxy:8404/stats;csv`.
   Two improvements: (a) correct HAProxy path-parameter CSV suffix `;csv` instead of
   query-string `?stats;csv`, and (b) basic-auth credentials matching the HAProxy
   defaults defined in `config/haproxy.cfg`.

---

## Test Results

28/28 tests pass (`make test-phase-87`).

---

## Acceptance Criteria Status

- [x] cAdvisor added to `docker/docker-compose.monitoring.yml`, pinned to `v0.47.2`, no external port, blkio metrics dropped
- [x] HAProxy exporter added to `docker/docker-compose.monitoring.yml`, pinned to `v0.15.0` — **URI corrected by Agent E**
- [x] Both new scrape jobs present in `monitoring/prometheus/prometheus.yml`
- [x] `monitoring/prometheus/recording_rules.yml` contains no references to `ja4_requests_total` or `ja4_blocked_requests_total`
- [x] `ja4proxy_infra_aggregations` recording rules group present; all 6 rules have PromQL with division guards
- [x] `monitoring/grafana/dashboards/ja4proxy-infrastructure.json` exists and is valid JSON
- [x] Dashboard has template variable `$container` with numeric-suffix exclusion regex
- [x] Fleet status strip visible in one row (stat panels in Fleet Status row)
- [x] Dashboard has 6 named row sections: Fleet Status, Host Resources, Network & TCP Stack, HAProxy, Container Drill-Down, Attack Detection
- [x] Alert annotations enabled on dashboard
- [x] Container drill-down panels include CPU throttle%, disk I/O, and network errors
- [x] `ja4proxy-overview.json` unchanged except `links` array addition
- [x] 5 new alert groups appended to `alerts.yml`; existing groups preserved
- [x] `ContainerOOMKilled` has `for: 0m`
- [x] `ConnectionRateSpike` uses `clamp_min(..., 0.1)` guard
- [x] `SYNFloodIndicator` references `ja4proxy:network_avg_pkt_size_bytes` recording rule
- [x] `HAProxyBackendQueueing` (> 0) and `HAProxyQueueSignalsCapacityAttack` (> 5) — distinct thresholds
- [x] Host-saturation inhibition rule added to `alertmanager.yml`
- [x] `docs/runbooks/infrastructure.md` present with 30 sections (spec said 29 — see notes)
- [x] `make test-phase-87` passes with zero failures
- [x] Agent E review complete; `docs/phases/complete/PHASE_87_notes.md` written; all critical findings resolved
- [ ] `CHANGELOG.md` updated — pending
- [ ] `docs/phases/manifest.yaml` status set to `COMPLETE` — pending
- [ ] `python3 scripts/sync-roadmap.py` run — pending
- [ ] `make lint-phases` exits 0 — pending

The four pending items are closing-ceremony steps that follow this review commit.
