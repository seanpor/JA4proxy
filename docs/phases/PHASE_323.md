# Observability Foundations & Core Metrics

## Goal

Align Prometheus scrape configurations, Grafana dashboards, and Alertmanager rules with the real-world metrics emitted by the Go proxy daemon (`ja4pd`) and the consolidated container infrastructure. This phase removes monitoring for retired containers, corrects alert rules to query existing metrics (like `ja4proxy_tarpit_concurrent` and `ja4proxy_redis_health`), and prevents false-alarm or dead-alert conditions.

---

## A — Scrape Target Consolidation

Review and update the Prometheus configuration (`deploy/monitoring/prometheus/prometheus.yml`):
- Verify the Go proxy scrapers are correctly defined (scraping port 9090 on proxy targets).
- Ensure Prometheus does not attempt to scrape retired/non-existent targets (like `admin-api`).
- Keep cAdvisor and HAProxy scrape configs loopback-bound or internal-only, matching the production compose hardening.

---

## B — Alerting Rules Alignment

Audit and rewrite Prometheus alert rules (`deploy/monitoring/prometheus/alerts.yml`):
- Do **not** use non-existent metrics like `tarpit:active_count` (which was a Redis key name, not a metric).
- Implement Tarpit warnings using `ja4proxy_tarpit_concurrent` (exceeding safety limits) or `ja4proxy_tarpit_overflow_total` (greater than 0).
- Check Redis availability via `ja4proxy_redis_health` (where 0 indicates a connection error, 1 indicates healthy).
- Monitor config reload failures via `ja4proxy_config_reload_failures_total`.
- Monitor certificate expiration using `ja4proxy_tls_cert_expiry_timestamp_seconds`.

---

## C — Observability Validation

Validate that all alert rules compile correctly and can be parsed by Prometheus:
- Run `promtool check rules` (or equivalent check in the CI linter) to ensure there are no syntax or reference errors in `alerts.yml`.
- Add integration tests verifying that active alerts fire as expected under simulated failure conditions (e.g. mock Redis down or cert expiry threshold breached).

---

## Acceptance Criteria

- [ ] `prometheus.yml` contains zero references to the retired `admin-api` or legacy unauthenticated ports.
- [ ] `alerts.yml` uses only metrics registered in `internal/metrics/metrics.go`.
- [ ] Rules pass validation via `promtool check rules` or the build suite's linter.
- [ ] Active metrics (like `ja4proxy_connections_total` and `ja4proxy_redis_health`) render accurately on Prometheus target endpoints.

---

## Files to Modify

| File | Change |
|------|--------|
| `deploy/monitoring/prometheus/prometheus.yml` | Update scrape targets, removing legacy/redundant containers |
| `deploy/monitoring/prometheus/alerts.yml` | Re-author rules to match valid metrics from `internal/metrics/metrics.go` |
| `tests/integration/test_infra_alerts.py` | Add unit/integration tests confirming Alertmanager accepts rule formats |
| `CHANGELOG.md` | Add Phase 323 entry |
