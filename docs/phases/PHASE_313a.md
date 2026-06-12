# PHASE 313a — Go Redis Backup Engine

> **STATUS: PROPOSED — plan for review. No code until approved.**
> Part 1 of 2 (backup). Restore is **PHASE_313b** and depends on this.
> Supersedes the backup half of the withdrawn single-phase PHASE_313 draft.

---

## 1. Goal (plain language)

The Go proxy keeps all its durable security state in Redis — bans, the blocking
"dial", allow/block lists, audit logs, fingerprints, and so on. If that Redis is
lost, the deployment loses its memory. **This phase builds a command that makes a
safe, encrypted, restorable snapshot of that state**, and emits the Prometheus
metrics that the existing (currently dead) backup alerts watch for.

This phase does **backup only**. Restoring a snapshot is the sister phase
**313b** — kept separate because restore is the dangerous half (it can re-block
real users) and deserves its own focused review.

## 2. Why this phase exists / background

- The proxy is **stateless**; everything durable lives in Redis (see
  `docs/REDIS_SCHEMA.md`). So "backup the proxy" really means "back up the right
  Redis keys".
- There is **no Go backup code today** (`internal/backup/` does not exist).
- `deploy/monitoring/alertmanager/rules/backup.rules.yml` already alerts on
  `ja4proxy_backup_*` metrics **that nothing emits** — dead alerts, the same
  problem phase-309 WP-6 fixed for other subsystems.
- A previous **Python** backup worker existed and was archived in commit
  `5afeba26`. It is recoverable for reference at
  `git show 5afeba26:archive/python_legacy/src/backup/…`. It already had
  **AES-256-GCM encryption**, a **PII redactor**, and a **distributed lock** — so
  those are not new ideas; they are the bar we must meet, not fall below.
- The Phase 231b bootstrap (`scripts/bootstrap.sh`) currently makes a nightly
  `tar` of `config/` + `.env` — that protects **secrets in `.env`** but **does
  not touch Redis**. This phase adds the Redis half; it must **not** remove the
  existing `.env` tar (see §8).

## 3. Key decisions (and the reasoning a newcomer needs)

| # | Decision | Why |
|---|---|---|
| D1 | **Use Redis native `DUMP` / `RESTORE`** (per key) to serialise values, not a hand-rolled per-type encoder. | `DUMP` returns Redis's own binary serialisation for *any* type (string, list, set, zset, hash, stream, HLL) and `RESTORE` rebuilds it exactly. Hand-rolling per-type (SMEMBERS/HGETALL/…) is more code and easy to get subtly wrong. The go-redis client exposes `Dump`, `RestoreReplace`, `PTTL` (`internal/redis` uses go-redis v9). |
| D2 | **Test the DUMP/RESTORE round-trip against a *real* Redis** (the repo's existing docker-integration pattern), **not miniredis**. | The test double `miniredis` only supports `DUMP` for *string* keys and does not produce real Redis's wire format — almost every key we back up is a set/hash/zset/list, so a miniredis round-trip test would silently pass while testing nothing. Unit-test the orchestration (scope selection, retention, encryption, metrics) with miniredis; integration-test the actual DUMP/RESTORE with real Redis. |
| D3 | **Encrypt the artifact at rest with AES-256-GCM**; key from an environment variable / secret store (`JA4PROXY_BACKUP_KEY`), never from `config/proxy.yml`. Artifact written `chmod 0600`, parent dir `0700`. | The snapshot contains audit logs (actor IPs/identities), bans, and MFA seed material — a plaintext file is a data breach waiting to happen. The archived Python already did this; we must not regress. GCM also gives us an integrity tag, so a tampered/truncated artifact fails closed on restore. |
| D4 | **Per-key explicit TTL capture.** For each key we store its `PTTL` alongside the dumped value. | `DUMP` carries only the value, not the expiry. `RESTORE key ttl value` needs the ttl passed separately. Without this, restored bans (default 3600s TTL) would come back as *permanent*. |
| D5 | **Config-driven key scope, with a safe default exclude-list.** Back up security-state prefixes; **exclude** ephemeral/regenerable keys (rate-limit windows, concurrency counters) and **session/credential keys** (`mgmt:totp:*`, `mgmt:webauthn:*`, `mgmt:saml:*`, `mgmt:oidc:*`, live session tokens). | Smaller artifact, and we must not export MFA/SSO session material that should regenerate rather than be restored. The exclude-list is the security boundary; it ships with safe defaults and is documented in the runbook. |
| D6 | **Best-effort point-in-time, explicitly.** We walk the keyspace with `SCAN` (non-blocking, non-atomic). | A `SCAN` snapshot is "fuzzy" — a key changed mid-walk may be caught before or after. For security state this is acceptable; we **document** that the artifact is best-effort, not a transactional snapshot. (The atomic alternative, `BGSAVE`, needs filesystem access to the Redis box, which breaks our "Redis may be remote" model.) |
| D7 | **Driven as a CLI subcommand** (`ja4pd backup`), invoked by a systemd timer / cron — no always-on goroutine. | Keeps the proxy hot path untouched; matches how ops already schedule the 231b tar. |
| D8 | **Metrics via the node-exporter textfile collector.** The CLI writes a `*.prom` file; node-exporter scrapes it. | A short-lived CLI registering Prometheus metrics in its own process and exiting would emit to nowhere. The textfile collector is the standard pattern for cron-style jobs. **This phase must also wire the collector into the deployment** (it is not currently enabled — see §6 step 6). |
| D9 | **A distributed lock** (`backup:operation_lock`, already reserved in `REDIS_SCHEMA.md`, `SET NX EX 600`). | Stops a backup and a restore (313b) — or two backups — running at once and producing a torn artifact. |

## 4. Design / how it works

```
ja4pd backup --config config/proxy.yml
  │
  ├─ acquire backup:operation_lock (SET NX EX 600); abort if held
  ├─ set ja4proxy_backup_currently_running = 1
  ├─ for each configured key-prefix:
  │     SCAN MATCH prefix            → key names (skip exclude-list)
  │     PTTL key  +  DUMP key        → (ttl, value) per key
  ├─ assemble a manifest {created_at, key_count, schema_version} + entries
  ├─ gzip → AES-256-GCM encrypt (key from JA4PROXY_BACKUP_KEY)
  ├─ write artifact  <dir>/ja4proxy-backup-<unixtime>.bin   (0600, dir 0700)
  ├─ prune: keep newest N and ≤ M days (config); securely remove older
  ├─ write metrics .prom: operations_total{status}, last_success_seconds,
  │     duration_seconds, currently_running=0
  └─ release lock
```

Failure at any step: log the error, increment
`ja4proxy_backup_operations_total{status="failure"}`, set
`currently_running 0`, release the lock, exit non-zero. **A backup failure never
touches live traffic** (fail-safe).

## 5. Metrics (define ALL of them now)

`backup.rules.yml` alerts on **seven** series — backup **and** restore. To avoid
leaving half the alerts dead, define the whole set in this phase (313a emits the
backup ones; 313b emits the restore ones):

| Metric | Type | Emitted by |
|---|---|---|
| `ja4proxy_backup_operations_total{status="success\|failure"}` | counter | 313a |
| `ja4proxy_backup_last_success_seconds` | gauge (unix ts) | 313a |
| `ja4proxy_backup_currently_running` | gauge 0/1 | 313a |
| `ja4proxy_backup_duration_seconds` | histogram | 313a |
| `ja4proxy_restore_operations_total{status}` | counter | 313b |
| `ja4proxy_restore_currently_running` | gauge 0/1 | 313b |
| `ja4proxy_restore_duration_seconds` | histogram | 313b |

> **Naming note for the reviewer:** the alert file currently uses
> `ja4proxy_backup_last_success_timestamp`, but `OBSERVABILITY_STANDARDS.md §1a`
> bans the `_timestamp` suffix (use `_seconds`). **Decision:** emit
> `…_last_success_seconds` and update the alert expression in `backup.rules.yml`
> to match. Record this rename in the CHANGELOG.

## 6. Implementation plan (do these in order)

1. **Registry first.** Add the four backup metrics to `internal/metrics` and to
   `docs/OBSERVABILITY_STANDARDS.md §1d` (the standard requires registry-before-code).
2. **Config.** Add a `backup:` block to `config/proxy.yml` with **conservative
   defaults** and inline comments: `enabled: false`, `dir`, `key_prefixes:` (the
   scope), `exclude_prefixes:` (the D5 list), `retention_count`, `retention_days`,
   `metrics_textfile`. Document that it is a per-invocation CLI, so SIGHUP
   hot-reload is N/A.
3. **Backup engine** `internal/backup/backup.go`: lock → SCAN/PTTL/DUMP →
   manifest → gzip → AES-256-GCM → write (0600) → prune → metrics → unlock.
4. **CLI** `ja4pd backup` subcommand (wire into `cmd/ja4pd`).
5. **Metric emission** as a `.prom` textfile (atomic temp+rename), incl.
   `currently_running 0` via a deferred cleanup that runs **even on crash**.
6. **Wire the textfile collector** into the deployment: add
   `--collector.textfile.directory=/var/lib/node_exporter/textfile` (+ a shared
   volume) to the `node-exporter` service in
   `deploy/docker/docker-compose.monitoring.yml`; point the backup `dir`/textfile
   at that volume. Without this the metrics are never scraped.
7. **Rename** `…_last_success_timestamp` → `…_last_success_seconds` in
   `backup.rules.yml` (see §5 note).
8. Docs: `docs/runbooks/backup_restore.md`, `docs/REDIS_SCHEMA.md` (update the
   `backup:*` "written by" attribution from the archived Python worker to this Go
   path; document `backup:operation_lock` usage), an **ADR** (logical DUMP vs
   BGSAVE; encryption choice), CHANGELOG, and the manifest `313a` entry.

## 7. Test plan (concrete; aim ≥1.2× test:code, ≥80% Go coverage)

- **Unit (miniredis)** — orchestration only: scope selection honours
  include/exclude lists; retention keeps exactly N and ≤ M days; the encrypt→
  decrypt round-trip recovers identical bytes; a wrong key fails closed; metrics
  toggle (`currently_running` 1→0, success/failure counters, duration observed).
- **Integration (real Redis)** — the real thing: populate a Redis with one key of
  **every type** (string/list/set/zset/hash/stream/HLL) **plus IPv6 `ban:` and
  `ban_cidr:` keys**, run a backup, and assert the artifact + (in 313b) a restore
  round-trips them exactly, TTLs included. This is the test that miniredis cannot
  do (decision D2).
- **Adversarial** — feed `backup` a Redis that errors mid-SCAN → failure metric,
  no panic, non-zero exit, lock released; feed a truncated/garbage artifact to the
  decrypt path → fails closed (GCM tag).
- **Performance** — back up an N-key dataset (e.g. 100k) and assert the duration is
  within a documented budget (the `BackupDurationHigh` alert fires at p95 > 60s, so
  validate the threshold is realistic).
- **Security** — artifact is `0600`, dir `0700`; refuse (or warn + metric) if the
  dir is group/world-readable; the exclude-list keys (`mgmt:totp:*`, …) never
  appear in the artifact.

## 8. Bootstrap reconciliation (do not cause data loss)

`scripts/bootstrap.sh` is owned by Phase 231b (still IN_PROGRESS) and currently
tars `config/` + `.env`. **Keep that** — `.env` holds secrets and is not in git.
This phase **adds** a Redis backup step alongside it; it does not replace it.
Because the file is another phase's, follow the file-ownership rule: coordinate
via a sub-agent / note in `PHASE_313a_notes.md`, declare `dependencies: [231b]`,
or defer the bootstrap wiring to a 231b follow-up.

## 9. Acceptance criteria

- `ja4pd backup` produces an **encrypted** artifact (`0600`) of the configured
  key scope, with per-key TTLs, excluding the credential/session keys.
- All four `ja4proxy_backup_*` series are emitted via the textfile collector and
  are scrapable in the deployment; the rename to `_seconds` is reflected in the
  alert rule.
- Retention enforced; lock prevents concurrent runs.
- Tests (unit + real-Redis integration + adversarial + performance + security)
  pass; `make test` green; coverage ≥ 80% on new Go code.
- Runbook, ADR, REDIS_SCHEMA, CHANGELOG, manifest updated; the 231b `.env` tar is
  preserved.

## 10. Out of scope (explicitly)

- **Restore** — that is PHASE_313b.
- RDB/`BGSAVE` file-level backup (possible later opt-in; needs Redis-local FS).
- Off-host shipping (S3/GCS) — leave a clean hook, don't build it.
- Backing up config files (already in git; `.env` handled by the 231b tar).

## 11. Glossary (for newcomers)

- **`DUMP` / `RESTORE`** — Redis commands that serialise a single key's value to
  an opaque blob and rebuild it. Version-compatible within the same major Redis.
- **`SCAN`** — cursor-based, non-blocking keyspace walk (unlike `KEYS`, which
  blocks). Non-atomic: the keyspace can change under you.
- **`PTTL`** — remaining time-to-live of a key in milliseconds (`-1` = no expiry,
  `-2` = key gone).
- **AES-256-GCM** — authenticated encryption: gives both confidentiality and a
  tamper-detecting integrity tag.
- **textfile collector** — a node-exporter feature that scrapes `*.prom` files a
  job writes to a directory; the standard way cron-style jobs expose metrics.
