- **Bump grafana + loki to clear real CVEs (Phase 800)**: re-verified every
  third-party image against its newest upstream tag by comparing raw trivy
  CVE-ID sets. `grafana/loki` 3.7.4 → 3.7.6 (2 HIGH/CRITICAL → **0**) and
  `grafana/grafana` 13.0.4-ubuntu → 13.0.6-ubuntu (9 → 7), both with zero new
  regressions. Confirmed cadvisor v0.54.1/v0.55.1 (44/43 vs 42) and grafana
  13.1.3 (11 vs 7) remain net regressions, and promtail/alertmanager/
  haproxy-exporter have no newer tag published.
- **Fix the weekly `.trivyignore` expiry cliff (Phase 800)**: the renewal
  workflow ran weekly (Wed 05:00 UTC) but renewed to `today+7`, so entries
  expired at 00:00 on the very morning the job ran — a guaranteed red window
  every week and a permanently red gate if one run failed. Renewal now runs
  daily; the Phase 226 seven-day maximum window is unchanged.
