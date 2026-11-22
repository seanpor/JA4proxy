<!--
title: "Daily Local Maintenance & Unified Dependency Updates"
audience: operators
last_reviewed: 2026-11-22
phase: 873
-->

# Daily Local Maintenance & Unified Dependency Updates

This runbook documents the automated multi-ecosystem dependency update pipeline (`make update-all` and `scripts/daily-maintenance.sh`) for enterprise SecOps engineers operating JA4proxy.

## 1. Architecture & Safety Guarantees

All four dependency ecosystems are updated inside non-root containers (without mounting `/var/run/docker.sock`) through deterministic, rollback-safe scripts:

| Ecosystem | Make Target | Execution Environment | Rollback / Verification Gate |
| :--- | :--- | :--- | :--- |
| **Go modules** | `make update-go` | Containerized (`ja4proxy-update-checker`, host UID) | Snapshots all modules' `go.mod`/`go.sum`; runs `go mod tidy` + `go mod verify` |
| **Python requirements** | `make update-python` | Containerized (`ja4proxy-tools`, host UID, no `docker.sock`) | Lockstep updates across all 3 requirement files; runs `scripts/check_deps_resolution.py` |
| **Node / `sql.js`** | `make update-node` | Containerized (`ja4proxy-update-checker`, host UID) | Snapshots `package.json`, `package-lock.json`, and vendor assets; runs `retire.js` (`--scan-js`) |
| **Docker digests** | `make update-docker` | Containerized (`ja4proxy-tools`, host UID, no `docker.sock`) | Resolves OCI/Docker multi-arch `Docker-Content-Digest` (`sha256:...`) across Dockerfiles & compose files |

Running `make update-all` chains all four targets, followed by `make check-updates` and `make preflight` (`make lint` + `make scan` + `make test` + `make test-race`).

---

## 2. Manual Execution

### Dry-Run (Read-Only Audit)

Preview all pending updates inside read-only (`:ro`) container mounts without modifying any files:

```bash
scripts/daily-maintenance.sh --dry-run
```

### Apply Updates & Run Full Preflight

Apply updates across all four ecosystems and execute `make preflight`:

```bash
scripts/daily-maintenance.sh --apply

# Fast local validation without running make preflight:
scripts/daily-maintenance.sh --apply --skip-preflight

# Full Makefile pipeline (also runs `make check-updates` before `make preflight`):
make update-all
```

---

## 3. Scheduling with `crontab -e`

Install a daily 03:00 UTC maintenance run with structured logging:

```cron
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/go/current/bin
GOROOT=/snap/go/current

0 3 * * * /path/to/JA4proxy/scripts/daily-maintenance.sh --dry-run >> /var/log/ja4proxy-maintenance.log 2>&1
```

> **Tip:** Start with `--dry-run` in cron until you have reviewed a week of output, then switch to `--apply` on a dedicated maintenance branch.

---

## 4. Scheduling with `systemd` User Timers

Create `~/.config/systemd/user/ja4proxy-maintenance.service`:

```ini
[Unit]
Description=JA4proxy Daily Dependency Maintenance
After=network-online.target docker.service

[Service]
Type=oneshot
WorkingDirectory=/path/to/JA4proxy
Environment=GOROOT=/snap/go/current
ExecStart=/path/to/JA4proxy/scripts/daily-maintenance.sh --dry-run
```

Create `~/.config/systemd/user/ja4proxy-maintenance.timer`:

```ini
[Unit]
Description=Run JA4proxy Daily Dependency Maintenance at 03:00 UTC

[Timer]
OnCalendar=*-*-* 03:00:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
```

Enable and verify:

```bash
systemctl --user daemon-reload
systemctl --user enable --now ja4proxy-maintenance.timer
systemctl --user list-timers ja4proxy-maintenance.timer
```

---

## 5. Rollback & Troubleshooting

- **Automatic rollback:** Each updater snapshots its target files before writing (via temp file + atomic `os.replace`) and restores all of them automatically if `go mod verify`, `scripts/check_deps_resolution.py` (including timeouts), `retire.js`, or any file write fails. Registry/PyPI lookup failures abort with exit code `1` without modifying files.
- **Manual rollback:** If `make preflight` fails after an update, revert the working tree cleanly:
  ```bash
  git checkout -- go.mod go.sum deploy/terraform-provider/go.mod deploy/terraform-provider/go.sum \
    requirements.txt requirements-analytics.txt management/requirements.txt \
    package.json package-lock.json management/static/vendor/ \
    Dockerfile* deploy/docker/
  ```
- **Registry rate limits:** `scripts/apply_updates_docker.py` uses anonymous Docker Hub pulls (no credentials required). If Docker Hub returns HTTP 429, the script aborts with exit code `1` without mutating files; re-run after the rate-limit window resets.
