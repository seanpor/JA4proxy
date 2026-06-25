<!--
title: "Upgrade Path & Compatibility"
audience: operator
last_reviewed: 2026-04-25
phase: 105
-->

# JA4proxy — Upgrade Path & Compatibility

> **Production runtime is the Go proxy daemon (`ja4pd`).** All legacy Python
> prototyping components (such as `proxy.py`) have been archived and removed.
> All upgrade procedures below assume the Go binary (`bin/ja4pd`) or the
> corresponding Docker image.

This page is a **summary**. The detailed step-by-step procedures live in:

- [`docs/runbooks/rolling_upgrade.md`](../runbooks/rolling_upgrade.md) —
  zero-downtime rolling upgrade for Docker Compose and Kubernetes.
- [`docs/runbooks/disaster_recovery.md`](../runbooks/disaster_recovery.md) —
  recovery procedures including post-rollback Redis-state restoration.

Read this page first to confirm compatibility, then follow the runbooks.

---

## 1. Versioning model

JA4proxy uses a semantic build versioning system `v2.0.BUILD` (introduced in Phase 152). Releases are built from the Go codebase and tagged accordingly. Release metadata includes:

- **Proxy phase** — the highest COMPLETE phase in the manifest at build time.
- **Config schema phase** — the phase that last introduced or changed a
  required key in `config/proxy.yml`.
- **Redis schema phase** — the phase that last introduced or migrated a Redis
  key family in [`docs/reference/REDIS_SCHEMA.md`](../reference/REDIS_SCHEMA.md).

Each of those phases must be mutually compatible per the matrix below before
you upgrade.

---

## 2. Version-compatibility matrix

The matrix is **forward-only**: a newer proxy can read an older config and an
older Redis schema; the reverse is not supported.

| Proxy phase | Config schema phase | Redis schema phase | Notes |
|-------------|--------------------|--------------------|-------|
| ≤ 14 | ≤ 14 | ≤ 14 | Pre-Go-rewrite era. Not supported in production. |
| 15 – 19 | ≤ 19 | ≤ 19 | Go runtime introduced (Phase 15). Backup/restore added in Phase 19. |
| 20 – 63 | ≤ 63 | ≤ 54 | TAP mode (Phase 20) and Management UI (Phase 13/51/52) usable. SLOs added in Phase 63. |
| 64 – 104 | ≤ 104 | ≤ 54 | Deployment validation, DR runbooks, ti-feed hardening. |
| 200 – 207 | ≥ 200 | ≤ 54 | **Required:** PROXY-protocol v2 (Phase 200), Redis TLS (Phase 201), default-credential removal (Phase 202), Go missing signals (Phase 203). |

**Rules of the matrix:**

1. Never run a proxy at phase *N* against a Redis schema strictly newer than
   *N* — a future migration may have introduced keys the proxy does not write
   but expects to read.
2. Never run a proxy at phase ≥ 200 against a Redis instance that does not
   require authentication. Phase 202 removed the unauthenticated fallback.
3. Phase 200+ proxies require explicit `upstream_trust` configuration when
   PROXY protocol is enabled. An empty trust list is treated as fail-closed
   for PROXY-protocol headers.
4. Configuration written for an earlier phase is forward-compatible: new keys
   adopt their documented defaults, and removed keys are ignored with a `WARN`
   log line on startup.

---

## 3. Pre-upgrade checklist

Before starting any upgrade, confirm all of the following:

- [ ] Target image / binary phase is recorded in the release notes
      (`CHANGELOG.md`) and matches the matrix above for your config and Redis
      schema phases.
- [ ] At least **2 proxy instances** are running (one to upgrade, one to
      serve traffic). Single-node deployments cannot do zero-downtime
      upgrades — see `rolling_upgrade.md` §1.
- [ ] HAProxy health checks are configured per `rolling_upgrade.md` §1
      (`option httpchk GET /api/v1/health/deep`, `inter 2s rise 2 fall 2`).
- [ ] Smoke test passes in staging: `bash scripts/smoke/test_docker_compose.sh`.
- [ ] **Backup is recent.** Redis state should have a Phase-19 backup no older
      than the agreed RPO (default 24 h). If absent, take one before
      proceeding — see `cloud_backup_operations.md`.
- [ ] **Dial is recorded.** Note the current dial value
      (`redis-cli GET config:dial`) so you can restore it after rollback if
      needed.

---

## 4. Upgrade procedure (summary)

The full procedure is in [`rolling_upgrade.md`](../runbooks/rolling_upgrade.md).
At a glance:

### Docker Compose

1. Drain backend via HAProxy admin socket (`set server ja4proxy/<node> state drain`).
2. Wait for active sessions to reach 0 in `show stat`.
3. `docker compose stop <node>`.
4. `docker compose up -d --no-deps <node> --image ghcr.io/org/ja4proxy:NEW_TAG`.
5. Wait for HAProxy to mark the backend UP (typically ≤ 30 s).
6. Verify `/api/v1/health/deep`.
7. Wait 30 s, then move to the next node.

### Kubernetes

1. `helm upgrade ja4proxy deploy/helm/ja4proxy/ --set image.tag=NEW_TAG --wait`.
2. `kubectl rollout status deployment/ja4proxy --timeout=300s`.
3. Confirm all pods carry the new image tag.
4. Verify `/api/v1/health/deep` against one pod.

The Helm chart enforces `maxSurge: 1, maxUnavailable: 0` for Deployments and
`maxUnavailable: 1` for DaemonSets — see `rolling_upgrade.md` §3.

---

## 5. Rollback (summary)

> **Rule:** Roll back first, debug later. The full rollback runbook takes
> < 2 minutes per node — significantly faster than diagnosing an active
> production issue.

Roll back **immediately** — do not troubleshoot first — if any of the
following thresholds (from `rolling_upgrade.md` §"Rollback Decision Criteria")
are breached:

| Metric | Threshold |
|--------|-----------|
| 5xx error rate | > 1% of requests over 1 minute |
| Health-check failures | Any node DOWN for > 30 s |
| Block-rate anomaly | > 50% change from baseline |
| Redis connection errors | Any new errors after upgrade |
| Latency P99 | > 2× baseline |

### Rollback procedure (summary)

- **Docker Compose:** drain → recreate with `PREVIOUS_TAG` → wait for UP →
  verify health → re-enable backend. Detail:
  [`rolling_upgrade.md` §4 "Rollback"](../runbooks/rolling_upgrade.md#4-rollback).
- **Kubernetes:** `kubectl rollout undo deployment/ja4proxy` → `rollout status`
  → verify health. Detail: same section.

### After rollback — Redis state

A normal rollback does **not** touch Redis state. If the upgrade was rolled
back because of corrupted state (e.g. a botched migration), follow
[`disaster_recovery.md` §5 "Redis data loss"](../runbooks/disaster_recovery.md)
to restore from the most recent Phase-19 backup. Set the dial to **0**
(monitor mode) before restoring; restore the intended dial only after the
restored state has been verified.

---

## 6. Post-upgrade verification

Within 15 minutes of completing the rollout:

1. All HAProxy backends UP; no node flapping.
2. `ja4proxy_redis_operations_total{result="error"}` flat (no new errors after upgrade).
3. Block-rate within ±20% of pre-upgrade baseline (Grafana
   `ja4proxy_connections_total{action="block"}`).
4. Latency P99 within 20% of pre-upgrade baseline.
5. Threat-intel feeds green (`ti_feed_health.md` checks).
6. Dial value matches the value recorded in §3 (or has been deliberately
   updated and noted in the change record).

If any of the above is red after 15 minutes, treat as a P2 incident per
[`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md) and consider rollback.

---

## 7. Related runbooks

- [`rolling_upgrade.md`](../runbooks/rolling_upgrade.md) — full upgrade detail.
- [`disaster_recovery.md`](../runbooks/disaster_recovery.md) — DR procedures
  including post-rollback Redis restore.
- [`zero_downtime_rollouts.md`](../runbooks/zero_downtime_rollouts.md) —
  config-only rollouts (no binary swap).
- [`credential_rotation.md`](../runbooks/credential_rotation.md) — Redis
  password and API key rotation; required when adopting Phase 201/202.
- [`go_proxy_migration.md`](../runbooks/go_proxy_migration.md) — historical
  Python-to-Go migration (Phase 15) — retained for reference only.
