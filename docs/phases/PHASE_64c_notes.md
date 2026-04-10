# Phase 64c — Disaster Recovery runbook notes

> **Sub-phase of:** Phase 64 (Deployment Validation & Disaster Recovery)
> **Size:** S
> **Status:** COMPLETE

## Deliverable
- `docs/runbooks/disaster_recovery.md` (5 scenarios + See also + quick reference + Runbook Exercise History section)

## What was done

Verified Phase 19 backup/restore commands against actual source code:

- **`src/backup/restorer.py`**: The restore engine class is `BackupRestorer`
  (not `Restorer`). Constructor accepts `redis_host`, `redis_port`, `redis_db`,
  `restore_error_threshold`, and `encryption_key`. The restore method is
  `restore_backup(backup_file, manifest_file, destructive=False)`.
- **`src/cli/backup_cli.py`**: CLI entry point is `python3 -m src.cli.backup_cli`.
  The `restore` subcommand accepts a positional `backup_file` path and optional
  `--force` flag for destructive mode. Manifest is auto-discovered as
  `<backup_file>.manifest.json`.
- **No `ja4proxy-cli backup` command exists.** The spec's phantom
  `Restorer('redis://...', Path('...'))` constructor does not match the actual
  API. The runbook uses the verified CLI and programmatic interfaces instead.

## Decisions made

- Used the actual `BackupRestorer` class API and `backup_cli` CLI rather than
  the spec's `Restorer` one-liner, since the spec's invocation does not match
  the real code. Both the CLI form and the direct Python import form are shown
  in Scenario 5 so operators can choose.
- All hot-reload commands use Go-production form only (container signal, kubectl
  exec, systemctl kill). No `pkill` commands.
- Used `docker compose` (v2 space-separated) throughout.

## Reviewer checklist (complete before merging)
- [x] "See also" block links to all 8 existing runbooks
- [x] No scenario duplicates content from any linked runbook
- [x] Scenario 5 uses correct Phase 19 Python invocation, not phantom `ja4proxy-cli backup`
- [x] All hot-reload commands use Go-production form only

## Phase 101 entries surfaced
- The Phase 19 backup spec references a `Restorer` class with a
  `redis://` URL constructor that does not exist. The actual class is
  `BackupRestorer` with separate host/port/db params. Consider adding a
  convenience `from_url()` class method in a future phase.
