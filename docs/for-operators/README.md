<!--
title: "Operators — Documentation Index"
audience: operators
last_reviewed: 2026-04-25
phase: 105
-->

# JA4proxy for SecOps Operators

> **Production runtime is the Go proxy** (`cmd/proxy/`, `bin/proxy`). The
> Python `proxy.py` is a prototyping surface — it does not run in production.

This is the curated entry point for engineers who **operate** JA4proxy in
production: starting and stopping the fleet, tuning the dial, responding to
incidents, sizing capacity, and rolling out upgrades.

This page **links** rather than duplicates. Each linked doc remains the
canonical source for its topic.

---

## Start here (in order)

| # | Doc | When to read |
|---|-----|-------------|
| 1 | [`docs/QUICK_REFERENCE.md`](../QUICK_REFERENCE.md) | First-day cheat sheet — start, stop, status, common Redis commands |
| 2 | [`docs/SECOPS_OPERATIONS.md`](../SECOPS_OPERATIONS.md) | Day-to-day operations: backend wiring, dial tuning, configuration |
| 3 | [`docs/MONITORING_SETUP.md`](../MONITORING_SETUP.md) | Prometheus, Alertmanager, and Grafana setup; SLO dashboards |
| 4 | [`docs/INCIDENT_RESPONSE.md`](../INCIDENT_RESPONSE.md) | P1–P4 severity matrix and per-symptom response procedures |

---

## Operational topics

### Day-to-day running

- [`SECOPS_OPERATIONS.md`](../SECOPS_OPERATIONS.md) — backend configuration,
  dial management, hot-reload, log inspection.
- [`QUICK_REFERENCE.md`](../QUICK_REFERENCE.md) — one-page command sheet.
- [`OBSERVABILITY_STANDARDS.md`](../OBSERVABILITY_STANDARDS.md) — metrics names,
  log schema, dashboard catalogue.
- [`SERVICE_TARGETS.md`](../SERVICE_TARGETS.md) — SLIs, SLOs, error-budget policy.

### Blocking, allow-listing, and policy

- [`docs/operator/BLOCKING_OPERATIONS.md`](../operator/BLOCKING_OPERATIONS.md)
  *(forward reference — created in Track G of Phase 105)* — consolidated guide
  to JA4 / IP / CIDR blocking, allow-list management, and tarpit operations.

### Incidents and on-call

- [`INCIDENT_RESPONSE.md`](../INCIDENT_RESPONSE.md) — severity matrix and per-symptom playbooks.
- [`docs/runbooks/`](../runbooks/) — full runbook directory, including:
  - [`disaster_recovery.md`](../runbooks/disaster_recovery.md) — coordinated
    multi-system recovery (Redis loss, fleet failure, config corruption).
  - [`security_incident_response.md`](../runbooks/security_incident_response.md)
    — active attacks and intrusions.
  - [`emergency_playbooks.md`](../runbooks/emergency_playbooks.md) — fast-path
    quick-stop procedures.
  - Per-alert runbooks (`ja4proxy_block_rate_high.md`,
    `ja4proxy_node_unhealthy.md`, `ja4proxy_redis_latency_high.md`,
    `ja4proxy_tarpit_pool_full.md`, etc.).
  - [`feed_management.md`](../runbooks/feed_management.md) and
    [`external_api_failures.md`](../runbooks/external_api_failures.md) —
    threat-intel and external-enrichment outages.

### Capacity planning and scaling

- [`SCALING_GUIDE.md`](../SCALING_GUIDE.md) — scaling architecture, worker-count
  sizing, and the `Worked Scenarios` H2 (small site / enterprise / high-volume API).
- [`docs/operator/CAPACITY_PLANNING.md`](../operator/CAPACITY_PLANNING.md) —
  long-form sizing reference (per-instance CPU/memory, Redis sizing).
- [`docs/runbooks/scaling.md`](../runbooks/scaling.md) — operational procedure
  for adding nodes.

### Upgrades and rollback

- [`UPGRADE_PATH.md`](UPGRADE_PATH.md) — version-compatibility matrix and a
  summarised path through the rolling upgrade and disaster recovery runbooks.
- [`docs/runbooks/rolling_upgrade.md`](../runbooks/rolling_upgrade.md) —
  detailed Docker Compose and Kubernetes rolling upgrade procedure.
- [`docs/runbooks/zero_downtime_rollouts.md`](../runbooks/zero_downtime_rollouts.md)
  — config-only rollouts via SIGHUP and Redis pub/sub.
- [`docs/runbooks/credential_rotation.md`](../runbooks/credential_rotation.md)
  and [`tls_certificate_rotation.md`](../runbooks/tls_certificate_rotation.md).

### Backup and DR exercises

- [`docs/runbooks/disaster_recovery.md`](../runbooks/disaster_recovery.md) —
  five DR scenarios with RTO/RPO.
- [`docs/runbooks/cloud_backup_operations.md`](../runbooks/cloud_backup_operations.md)
  — Phase 19 backup/restore for Redis state.
- [`docs/runbooks/gameday_scenarios.md`](../runbooks/gameday_scenarios.md) —
  chaos-drill definitions.

---

## Discipline (read once, internalise)

- **Default dial is 0** (monitor mode). Never block on first deploy. Raise the
  dial deliberately; see `SCALING_GUIDE.md` for the recommended progression.
- **Fail open by design.** External dependencies (Redis, AbuseIPDB, RDAP,
  MaxMind) have explicit fallbacks. The proxy degrades rather than blocks.
- **False positives cost more than false negatives.** Allow-cache TTLs are
  long; block-cache TTLs are short; local cache wins over Redis. See
  `CLAUDE.md` "Core Asymmetry" section.

---

## See also

- [`docs/INDEX.md`](../INDEX.md) — exhaustive doc map for power users.
- [`docs/for-architects/README.md`](../for-architects/README.md) — threat
  model, scope, SIEM integration.
- [`docs/for-developers/README.md`](../for-developers/README.md) — local dev,
  TDD, phase protocol.
