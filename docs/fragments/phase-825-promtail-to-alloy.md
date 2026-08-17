- **Migrate Promtail → Grafana Alloy (Phase 825)**: `grafana/promtail` is EOL
  upstream and carried **29 HIGH/CRITICAL**; Alloy is its supported successor
  and scans **6**. The River config is a direct translation preserving the
  `container` / `service` / `level` / `action` label contract, including the
  `{service="proxy"}` match that gates security-event tagging. **cAdvisor was
  deliberately kept** — removing it would have taken `ContainerOOMKilled` with
  it, and an OOM-killed proxy fails *closed* for the connections it was serving.
  Net exception change is **59 → 58**, not the 59 → 30 originally claimed:
  promtail was the sole carrier of only two exceptions, 27 of its 29 are shared
  with images that stay, and Alloy adds `CVE-2026-71556`.
- **Found: production had been shipping no logs at all (Phase 825)**: prod's
  promtail mounted the *shared* `promtail-config.yml`, whose `docker_sd_configs`
  targets `tcp://docker-socket-proxy:2375` — a service that exists only in
  `docker-compose.monitoring.yml`. In the prod stack that host never resolved,
  so discovery returned nothing and **no logs were shipped**, silently, for as
  long as that config was in place. Nothing surfaced it because an empty Loki is
  indistinguishable from a quiet system. Prod now uses `config.prod.alloy`,
  which discovers by file over the `../../logs` mount it already had.
- **Log delivery is now asserted, not assumed (Phase 825)**:
  `check_alloy_log_delivery.sh` emits a unique marker from a real container and
  asserts it comes back **out of Loki with its labels intact** — "the container
  is Up" proves nothing, which is precisely how the prod gap survived.
  Prometheus also scrapes Alloy now; promtail was never scraped, so a broken
  pipeline had no metric to alert on. The **JA4PROXY-2026-0017** pentest
  regression test (CVSS 7.5, Docker socket exposure) was **ported rather than
  deleted** — retiring a security guarantee as a side effect of an image swap
  is exactly the kind of quiet loss this project keeps finding — and its
  `regression_test` pointer in `docs/security/findings.yaml` updated, which the
  provenance gate caught.
