# PHASE 313 — Go Backup / Restore Subsystem

> **STATUS: DRAFT — awaiting user sign-off. No code until this plan is approved.**

## Goal

Give the Go production runtime a first-class **backup and restore** capability for
the security state it depends on (all of which lives in Redis), and emit the
`ja4proxy_backup_*` metrics that `deploy/monitoring/alertmanager/rules/backup.rules.yml`
already alerts on. Today there is **no Go backup implementation** — the Python
prototype's backup worker was archived in `5afeba26`, the alerts fire against
metrics nobody emits, and the only thing standing in is whatever `scripts/`
the Phase 231b bootstrap wires for a "daily backup." This phase makes backup a
real, observable, tested part of the product.

## Background — what exists vs what's missing

| Concern | State today |
|---|---|
| What needs backing up | The proxy is stateless; **all durable state is in Redis** — bans (`ban:*`, `ban_cidr:*`), the dial (`config:dial`), JA4/IP allow & block lists, `management:audit_log` / `policy_audit`, beaconing/fingerprint data, etc. (see `docs/REDIS_SCHEMA.md`). |
| Go backup code | **None.** No `internal/backup`, no `cmd/` entrypoint. |
| Alerts | `backup.rules.yml` references `ja4proxy_backup_operations_total{status}`, `ja4proxy_backup_last_success_timestamp`, `ja4proxy_backup_currently_running`, `ja4proxy_backup_duration_seconds_*` — **all unemitted** (dead alerts, same class as phase-309 WP-6). |
| Bootstrap | Phase 231b's `scripts/bootstrap.sh` mentions a "daily backup" — needs reconciling with this subsystem (don't ship two backup paths). |
| Reference | Archived Python worker/restorer/policy recoverable at `git show 5afeba26:archive/python_legacy/src/backup/...`. |

## Design (proposed — for review)

1. **Logical, network-only backup.** The proxy reaches Redis over the network, so
   we back up via `SCAN` + `DUMP` per key (portable, selective, no Redis
   filesystem access), writing a single timestamped artifact. Restore is
   `RESTORE` per key. *(Alternative considered: trigger `BGSAVE` and copy the RDB
   — atomic and fast, but needs co-located filesystem access to the Redis box, so
   it breaks the "proxy is standalone / Redis may be remote" model. Rejected as
   the default; could be an opt-in mode later.)*
2. **Selective key scope.** Back up the security-state key prefixes from
   `REDIS_SCHEMA.md`, not ephemeral counters (rate-limit windows, concurrency
   counters) — those regenerate and only bloat the artifact. Scope is config-driven.
3. **Artifact + retention.** Gzipped artifact to a configured directory; retain
   the last *N* and/or *M* days (config-driven), pruning oldest. Optional restore
   `--dry-run` that reports what would change without writing.
4. **Entrypoint.** A `ja4pd backup` / `ja4pd restore` subcommand (or a small
   `cmd/ja4-backup`) so it can be driven by a systemd timer / cron — replacing
   whatever 231b currently wires. No always-on goroutine required (keeps the hot
   path untouched); a scheduled invocation is simpler and matches ops norms.
5. **Observability — the point of the phase.** Emit exactly the metrics the
   alerts expect: `ja4proxy_backup_operations_total{status="success|failure"}`,
   `ja4proxy_backup_last_success_timestamp`, `ja4proxy_backup_currently_running`,
   `ja4proxy_backup_duration_seconds` (histogram). Push via the pushgateway or
   write a `.prom` textfile for the node-exporter textfile collector (decide at
   review — textfile is simplest for a cron-driven job).
6. **Fail-safe.** A backup failure never touches live traffic; a restore is
   explicit/manual and refuses to run against a non-empty target without
   `--force`.

## Scope (files — indicative)

- `internal/backup/backup.go` — SCAN+DUMP, artifact write, retention prune.
- `internal/backup/restore.go` — artifact read, RESTORE, dry-run, force guard.
- `internal/backup/metrics.go` (or extend `internal/metrics`) — the 4 backup metrics.
- `cmd/ja4pd/…` or `cmd/ja4-backup/main.go` — CLI subcommands.
- `config/proxy.yml` — `backup:` block (dir, retention, key-prefix scope, schedule hint).
- `internal/backup/*_test.go` — unit + restore round-trip (miniredis).
- `docs/runbooks/backup_restore.md`, `docs/REDIS_SCHEMA.md` (note backed-up scope),
  `CHANGELOG.md`, `docs/decisions/ADR-2xx.md` (logical-vs-RDB choice).
- Reconcile `scripts/bootstrap.sh` (Phase 231b) to call this.

## Implementation plan

1. Define config + key-scope; wire the 4 metrics into the registry.
2. Backup: SCAN+DUMP round-trip to a gzipped artifact; retention prune; metrics.
3. Restore: RESTORE with dry-run + non-empty/force guard.
4. CLI subcommands + textfile/pushgateway metric emission.
5. Reconcile the 231b bootstrap backup hook; runbook; ADR; CHANGELOG; manifest.

## Test strategy

- Round-trip: populate miniredis → backup → flush → restore → assert key-for-key equality (incl. TTLs).
- Retention prune keeps exactly N/M and removes the oldest.
- Restore guards: refuses non-empty target without `--force`; `--dry-run` writes nothing.
- Metrics: success/failure counters, `currently_running` toggles, timestamp advances.
- Chaos: Redis unreachable mid-backup → failure metric, no panic, exit non-zero.

## Acceptance criteria

- `ja4pd backup` produces a restorable artifact of the configured key scope.
- `ja4pd restore` round-trips it exactly (keys + TTLs), with dry-run + force guards.
- All four `ja4proxy_backup_*` series are emitted; `backup.rules.yml` alerts can fire/clear.
- Retention enforced; bootstrap uses this path (no duplicate backup mechanism).
- Tests + runbook + ADR + CHANGELOG + manifest updated; `make test` green.

## Out of scope

- RDB/BGSAVE file-level backup (possible later opt-in).
- Off-host artifact shipping (S3/GCS) — leave a clean hook, don't build it here.
- Backup of anything outside Redis (config files are in git already).
