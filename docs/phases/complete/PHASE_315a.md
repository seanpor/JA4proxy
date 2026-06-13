# PHASE 315a — Go Redis Backup Engine

> **STATUS: COMPLETE (2026-06-13).** Delivered as the `internal/backup` package +
> `ja4p backup` / `ja4p backup inspect` CLI. Part 1 of 2 (backup); restore is
> **PHASE_315b** and depends on this.
>
> **Grounding corrections made during implementation** (the codebase differed
> from this draft):
> - The subcommand lives in the **`ja4p` cobra CLI**, not `ja4pd` — `ja4pd` is the
>   long-running proxy daemon with no subcommand dispatch. (See ADR-205.)
> - **PBKDF2** is Go-stdlib `crypto/pbkdf2` (Go 1.24+); no `x/crypto` dependency.
> - The metric rename `…_last_success_timestamp` → `…_last_success_seconds` was
>   applied to `backup.rules.yml` as planned.
>
> **Deferred to a follow-up** (not blocking the backup engine): the `--sanitize`
> PII redactor, a `backup:` config block (scope is documented defaults + flags
> today), the forward-compat schema-migrator, and wiring the node-exporter
> textfile collector into `docker-compose.monitoring.yml`. Restore's three metric
> series land in **315b** (this phase registered the four backup series).

---

## 1. Goal (plain language)

The Go proxy keeps all its durable security state in Redis — bans, the blocking
"dial", allow/block lists, audit logs, fingerprints, and so on. If that Redis is
lost, the deployment loses its memory. **This phase builds a command that makes a
safe, encrypted, restorable snapshot of that state**, and emits the Prometheus
metrics that the existing (currently dead) backup alerts watch for.

This phase does **backup only**. Restoring a snapshot is the sister phase
**315b** — kept separate because restore is the dangerous half (it can re-block
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
| D9 | **A distributed lock** (`backup:operation_lock`, already reserved in `REDIS_SCHEMA.md`, `SET NX EX 600`). | Stops a backup and a restore (315b) — or two backups — running at once and producing a torn artifact. |
| D10 | **Do not package configuration files (`proxy.yml`, `.env`) in the database backup; store config fingerprinting metadata instead.** | Packaging `.env` (which contains the key) inside the encrypted backup creates a circular key dependency (you need the key to decrypt the backup to get the key). Keep configuration/secrets separate from dynamic state. To prevent drift, record the active configuration hash and software build version in the manifest, allowing the restore tool to warn the operator on divergence. |
| D11 | **PBKDF2 Key Derivation + Cryptographically Secure 12-byte Random IV.** | GCM requires a unique, secure 12-byte IV per write to prevent nonce-reuse compromise. Raw passphrases cannot be used directly as keys; derive a 32-byte key using PBKDF2 with SHA-256 (100,000 iterations) and a random salt, storing the salt in the unencrypted binary header. |
| D12 | **Paced, Pipelined SCAN/DUMP with Configurable Batch Size and Delay.** | Scanning/dumping sequentially blocks Redis's single execution thread on large databases. Perform keyspace sweeps in pipelined batches (default 100) and yield control via a configurable delay (default 10ms) between batches. |
| D13 | **Atomic Writes using a Temporary File.** | Avoid corruption by writing to a temporary file (`*.bin.tmp`) in the destination directory and executing an atomic `os.Rename` only after a successful, complete write. |
| D14 | **Compliant Backup Sanitization for Non-Prod (`--sanitize`).** | Debugging issues in staging/dev requires real database state, but copying production backups directly violates GDPR/CCPA due to IP logs and session keys. Add a `--sanitize` option that redacts/masks client IP addresses in key names/payloads and strips session tokens/MFA secrets, producing a safe snapshot. |

## 4. Design / how it works

### A — Binary File Format Layout (No-Circular-Dependency & Secure)
To support unique random salts for PBKDF2 and cryptographically secure nonces for AES-GCM, the backup file starts with a plain unencrypted header:
```
┌─────────────────┬─────────────────┬─────────────────┬──────────────────────┬─────────────────┬────────────────────────┐
│ Magic ("JA4P")  │ Format Ver (1B) │  Salt (16B)     │ PBKDF2 Iterations(4B)│ GCM Nonce (12B) │ Encrypted Payload (Var)│
└─────────────────┴─────────────────┴─────────────────┴──────────────────────┴─────────────────┴────────────────────────┘
```
The **Encrypted Payload** contains a gzipped JSON body:
- **Manifest:** `{created_at, key_count, schema_version, proxy_version, config_hash}`
- **Entries:** Array of `{key, ttl_ms, payload_base64}`

### B — Backup Flow
```
ja4pd backup --config config/proxy.yml [--key-file <path>] [--sanitize]
  │
  ├─ acquire backup:operation_lock (SET NX EX 600); abort if held
  ├─ set ja4proxy_backup_currently_running = 1
  ├─ read key from --key-file (or JA4PROXY_BACKUP_KEY env var)
  ├─ compute active config SHA-256 hash & query proxy build version
  ├─ generate random 16-byte PBKDF2 salt & derive 32-byte key (100k iterations)
  ├─ for each configured key-prefix:
  │     SCAN MATCH prefix (batch size: 100)
  │     PTTL + DUMP (pipelined)
  │     sleep 10ms (yield Redis CPU to live traffic)
  ├─ if --sanitize is specified:
  │     └─ run redactor: mask client IP addresses (v4/v6) in key names/payloads, and drop active sessions/MFA secrets
  ├─ assemble manifest + entries JSON
  ├─ gzip payload
  ├─ generate cryptographically secure 12-byte random IV
  ├─ encrypt payload (AES-256-GCM)
  ├─ write binary header + ciphertext to <dir>/ja4proxy-backup-<unixtime>.bin.tmp (0600)
  ├─ atomic rename: tmp file -> final .bin file
  ├─ prune: keep newest N and ≤ M days (config); securely remove older
  ├─ write metrics .prom: operations_total{status}, last_success_seconds,
  │     duration_seconds, currently_running=0
  └─ release lock
```

### C — Offline Backup Inspection
To allow operations teams to verify the integrity and metadata of a backup without running a Redis instance:
```
ja4pd backup inspect <file>
  │
  ├─ read unencrypted binary header (salt, iterations, nonce)
  ├─ prompt for / read passphrase and derive 32-byte key
  ├─ decrypt & verify GCM tag
  ├─ output manifest info (created_at, key_count, schema_version, config_hash, proxy_version)
  └─ print breakdown of key count per prefix (e.g. "ban:*": 45, etc.)
```

Failure at any step: log the error, increment
`ja4proxy_backup_operations_total{status="failure"}`, set
`currently_running 0`, release the lock, exit non-zero. **A backup failure never
touches live traffic** (fail-safe).

## 5. Metrics (define ALL of them now)

`backup.rules.yml` alerts on **seven** series — backup **and** restore. To avoid
leaving half the alerts dead, define the whole set in this phase (315a emits the
backup ones; 315b emits the restore ones):

| Metric | Type | Emitted by |
|---|---|---|
| `ja4proxy_backup_operations_total{status="success\|failure"}` | counter | 315a |
| `ja4proxy_backup_last_success_seconds` | gauge (unix ts) | 315a |
| `ja4proxy_backup_currently_running` | gauge 0/1 | 315a |
| `ja4proxy_backup_duration_seconds` | histogram | 315a |
| `ja4proxy_restore_operations_total{status}` | counter | 315b |
| `ja4proxy_restore_currently_running` | gauge 0/1 | 315b |
| `ja4proxy_restore_duration_seconds` | histogram | 315b |

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
   `metrics_textfile`, `batch_size: 100`, `batch_delay_ms: 10`. Document that it is a per-invocation CLI, so SIGHUP
   hot-reload is N/A.
3. **Crypto Library** `internal/backup/crypto.go`: Implement `EncryptPayload`, `DecryptPayload` using AES-256-GCM with secure random IV prepending, and `DeriveKey` using PBKDF2-SHA256 (100k iterations) with random salt.
4. **Backup engine** `internal/backup/backup.go`: lock → read key-file/env → active config hash + build version → verify backup directory exists (attempt `os.MkdirAll(dir, 0700)`, fail-closed if permission error) → paced, pipelined SCAN/PTTL/DUMP (batching/delay) → optional in-memory PII sanitization redactor (if `--sanitize` is active) → manifest assembly → gzip → AES-256-GCM → write binary header + ciphertext to `*.bin.tmp` (0600) → atomic `os.Rename` → prune → metrics → unlock.
5. **CLI** `ja4pd backup` subcommand (wire into `cmd/ja4pd` with `--key-file`, `--key`, and `--sanitize` flags). Add a separate `ja4pd backup inspect <file>` subcommand to decrypt, verify, and print backup metadata.
6. **Metric emission** as a `.prom` textfile (atomic temp+rename), incl.
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
   BGSAVE; encryption choice), CHANGELOG, and the manifest `315a` entry.

## 7. Test plan (concrete; aim ≥1.2× test:code, ≥80% Go coverage)

- **Unit (miniredis)** — orchestration only: scope selection honours
  include/exclude lists; retention keeps exactly N and ≤ M days; key derivation (PBKDF2) and random IV distribution; the encrypt→
  decrypt round-trip recovers identical bytes and matches binary header structure; a wrong key fails closed; metrics
  toggle (`currently_running` 1→0, success/failure counters, duration observed); `--key-file` reading.
- **Sanitization Redactor Test** — assert that running backup with `--sanitize` correctly masks client IP addresses in logs/keys and filters active session/credential tokens.
- **Inspection Subcommand Test** — verify `backup inspect` reads manifest metadata and displays a breakdown of key prefixes without starting a Redis server.
- **Config Validation Test** — verify that config hashes and build versions are correctly captured in the manifest metadata.
- **Integration (real Redis)** — the real thing: populate a Redis with one key of
  **every type** (string/list/set/zset/hash/stream/HLL) **plus IPv6 `ban:` and
  `ban_cidr:` keys**, run a backup, and assert the artifact + (in 315b) a restore
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
via a sub-agent / note in `PHASE_315a_notes.md`, declare `dependencies: [231b]`,
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

## Files to Modify

| File | Change |
|------|--------|
| `internal/metrics/metrics.go` | Register backup Prometheus metrics |
| `docs/OBSERVABILITY_STANDARDS.md` | Add backup metrics definitions |
| `config/proxy.yml` | Add `backup:` config section |
| `internal/backup/crypto.go` | New file — AES-GCM and PBKDF2 crypto functions |
| `internal/backup/backup.go` | New file — Redis SCAN, DUMP, gzip, write-to-file loop |
| `cmd/ja4pd/main.go` | Wire `backup` and `backup inspect` CLI subcommands |
| `deploy/docker/docker-compose.monitoring.yml` | Mount node-exporter textfile directory |
| `deploy/monitoring/alertmanager/rules/backup.rules.yml` | Rename `_last_success_timestamp` to `_seconds` |
| `docs/runbooks/backup_restore.md` | Update backup execution runbook |
| `docs/REDIS_SCHEMA.md` | Update `backup:*` keys documentation |
| `CHANGELOG.md` | Add Phase 315a changes |

## 10. Out of scope (explicitly)

- **Restore** — that is PHASE_315b.
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
