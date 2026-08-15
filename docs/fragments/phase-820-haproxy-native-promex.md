- **Retire `prom/haproxy-exporter` for HAProxy's native exporter (Phase 820)**:
  the sidecar was a CSV-to-Prometheus translation shim from before HAProxy 2.0
  shipped its own exporter. `haproxy:2.8.26-alpine` — already pinned — is built
  with `USE_PROMEX=1`, so Prometheus now scrapes `haproxy:8404/metrics`
  directly. Upstream abandoned the sidecar (last release **2023-02-15**, built
  on **Go 1.19.5**); it carried **58 HIGH/CRITICAL CVEs** and required **20 of
  the repo's 73 `.trivyignore` exceptions** — every `CVE-2022-*` and
  `CVE-2023-*` entry, now deleted (73 → 53). `use-service` is evaluated before
  `stats`, so `/stats` keeps its credentials while `/metrics` is served
  unauthenticated on a loopback/monitoring-only port; `HAPROXY_STATS_USER` and
  `HAPROXY_STATS_PASSWORD` are no longer injected into a second container.
- **Repair nine HAProxy monitoring selectors that had never worked (Phase 820)**:
  running both exporters side by side against an identical HAProxy revealed the
  monitoring built on the sidecar was already dead. Every consumer filtered on
  `{proxy="ja4proxy"}` — but `proxy=` is the *native* exporter's label
  (`prom/haproxy-exporter` emitted `frontend=`/`backend=`, and never a `proxy`
  label at all), and the value was wrong regardless: the backend is
  `ja4proxy_workers`. Fixed **five alert rules** (`HAProxyBackendQueueing`,
  `HAProxySessionLimitApproaching`, `HAProxyBackendDown`,
  `HAProxyConnectionErrorRate`, `HAProxyQueueSignalsCapacityAttack`) and **four
  dashboard panels**. `HAProxyBackendDown` additionally now pins `state="UP"`:
  native promex emits `haproxy_server_status` as a state machine (one series per
  UP/DOWN/MAINT/DRAIN/NOLB), so an unconstrained `== 0` matches the four
  always-zero states and would page continuously. Two infrastructure panels used
  `rate(haproxy_frontend_connections_rate[1m])` — a metric the native exporter
  does not emit, and a *gauge* under the sidecar, so `rate()` was invalid either
  way; they now use the real counter `haproxy_frontend_connections_total`.
- **Add a reusable metric-selector validator (Phase 820)**:
  `tests/unit/test_metric_selector_validity.py` asserts every `haproxy_*`
  selector in alert rules and dashboards names a frontend/backend actually
  declared in `config/haproxy.cfg`, that `haproxy_server_status` always
  constrains `state=`, and that no retired-sidecar-only metric is referenced.
  A selector matching zero series never fires and never errors, which is why
  this went unnoticed for months. The validator parses dashboard JSON into its
  `expr` strings rather than scanning raw text — quotes are backslash-escaped in
  the file, so a raw-text regex sees an empty label block and passes vacuously;
  fixing that immediately surfaced four further dead selectors. Written as a
  general validator so Phase 821a can extend it to `ja4proxy_*` metrics rather
  than reimplementing it.
