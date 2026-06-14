---
phase: 231b
title: Single-Host Bootstrap — Wizard, systemd, Firewall, Backups
status: IN_PROGRESS
created: 2026-06-11
audience: [developer, operator]
---

# Single-Host Bootstrap & Setup Wizard

> Split from the original monolithic Phase 231 proposal. **231b is the
> operator-facing deployment tooling**; it depends on **[[PHASE_231a]]** (the Go
> core — PROXY-write + manual-ban + CountKeys fix) being merged first.

> **Status (this PR — software core delivered):** `scripts/setup_wizard.py`
> (+ 9 unit tests; secrets never echoed; `.env` chmod 600; real port scheme),
> `scripts/bootstrap.sh` (shellcheck-clean: OS detect, zero-compile guard,
> user/dirs, offline-tarball load, firewall gating from `.env`, `--check`,
> `--uninstall`), the generated systemd unit, logrotate, and the daily backup
> cron, plus an `OPERATIONS_GUIDE` section. **Pending real-host validation**
> (cannot run in CI/sandbox): clean-VM boot E2E, offline-tarball `docker load`,
> firewall-from-remote check, and the LaTeX user-guide chapters — these keep
> the phase IN_PROGRESS.

## Goal

One-command, zero-compile deployment of JA4proxy on a clean Linux host, plus an
interactive wizard that generates config + secrets, so an operator can put a
single server in their DMZ (only `443` public) and get immediate relief from a
bot flood — no HAProxy required.

## Corrections applied vs the original Phase 231 proposal (from review)

- **Ports — use the real scheme and read them from `.env`.** Management UI is
  **`8090`** (not `8113`), metrics `9090`, Prometheus `9091`, Grafana `3000`.
  There is **no `3023` "syncagent"**. The firewall step must restrict whatever
  `HOST_PORT_*` resolve to in `.env` (consistent with phase-310's lane scheme
  and the "don't lock ports down" directive), not hard-coded literals.
- **GeoIP is MaxMind GeoLite2** (`GeoLite2-ASN.mmdb`, `GeoLite2-Country.mmdb`) —
  not `IP2LOCATION-LITE-DB1.BIN`.
- **Python TAP node is archived (Phase 128).** There is no longer a separate
  Python TAP service. The Go proxy (`ja4pd`) includes a TAP consumer
  (`internal/security/tap_consumer.go`) that reads `fp:os:ip:{ip}` keys from
  Redis (written by a future Go TAP sensor — Phase 316). The wizard offers only
  **inline topology** (`ja4pd`). TAP sensor deployment is out of scope for this
  phase.
- **No secrets echoed.** The wizard/bootstrapper must never print
  `REDIS_PASSWORD`/`GRAFANA_PASSWORD`/tokens (matches `start-poc.sh`'s
  `JA4PROXY-2026-0040` rule); generated values go to `.env` (chmod 600) only.
- **No `/home/<user>` paths** anywhere; deployment root, log, and backup paths
  are parameterised (`/opt/ja4proxy`, `/var/log/ja4proxy`, `/backup/ja4proxy`).

## Implementation

### A — `scripts/bootstrap.sh` (zero-compile installer)
- Refuse to install/run any compiler/build tooling (`go`/`gcc`/`make`) when
  `mode=production`; copy pre-built `ja4pd`/`ja4p` binaries and/or `docker load`
  a local `ja4proxy-offline.tar.gz` (or pull from a registry).
- Detect OS (Debian/Ubuntu + RHEL/Rocky), install *runtime* deps only
  (`openssl`, `redis-server`, `docker-ce`+`compose-plugin` if containerized).
- Create the `ja4proxy` system user/group; own `/opt/ja4proxy`,
  `/var/log/ja4proxy`, `/backup/ja4proxy`. Parameterised paths, no home dirs.
- `--check` (dry-run diagnostics) and `--uninstall` (halt stack, remove units +
  dirs, prompt before purging volumes).

### B — `scripts/setup_wizard.py` (interactive config)
- **Implemented prompts:** topology (only **inline → `ja4pd`**); protected backend
  host/port; native-systemd vs containerized; admin bind IP (default
  `127.0.0.1`); admin user; admin password (blank = generate).
- **Planned prompts (future):** allowed SNIs; optional upstream TCP LB (→ enable
  `proxy_protocol` + write `upstream_trust.trusted_cidrs`); whether to **write**
  PROXY protocol to the backend (the 231a feature) + version; self-signed vs
  supplied certs.
- Defaults to **monitor mode** (`dial: 0`, `blocking_acknowledged: false`).
- Generates cryptographically strong secrets to `.env` (chmod 600), **never
  echoed**. Lazy `%s` logging, no f-strings (lint).
- All paths relative to the deploy root / standard dirs.

### C — Host integration
- `ja4proxy.service` systemd unit (native binary *or* `docker compose up -d` /
  `down -t 30`).
- Firewall (UFW/FirewallD): public `80`/`443`; bind admin services
  (`HOST_PORT_MANAGEMENT` 8090, `HOST_PORT_METRICS` 9090,
  `HOST_PORT_PROMETHEUS` 9091, `HOST_PORT_GRAFANA` 3000) to loopback — values
  read from `.env`, not literals.
- `/etc/logrotate.d/ja4proxy` (size-based, e.g. 10M×3); `/etc/docker/daemon.json`
  log caps for containerized mode.
- Daily backup cron (`/usr/local/bin/ja4proxy-backup.sh`) of the Redis dump +
  config. (If "encrypted backups" is claimed, specify the mechanism, e.g.
  `age`/`gpg`; otherwise call them plain archives.)

## Test strategy
- VM boot (Ubuntu 22.04 + Rocky 9): `bash scripts/bootstrap.sh` end-to-end from
  zero deps.
- Offline-tarball: `docker save` → transfer → `--offline` load with no egress.
- `setup_wizard.py` unit tests (`tests/unit/test_setup_wizard.py`): reject
  invalid hostnames / empty passwords / bad cert paths; **assert no secret is
  ever printed**; assert `.env` is chmod 600.
- Firewall gating: from a remote client, admin ports unreachable, `443` works.
- Uninstall leaves no orphan volumes/units.

## Acceptance criteria
- [ ] `bash scripts/bootstrap.sh` on a clean host installs runtime deps, runs the
      wizard, generates secrets, and starts the stack — no manual `.env` editing,
      no compiler on the host.
- [ ] Firewall restricts admin ports (resolved from `.env`) to loopback; `443`
      serves; the wizard never prints a secret.
- [ ] systemd restarts the stack on boot; `--uninstall` leaves the host clean.
- [ ] Inline mode drives `ja4pd` (only topology offered).
- [ ] Docs updated: `OPERATIONS_GUIDE.md` (wizard/bootstrap/`--check`/`--uninstall`),
      LaTeX user-guide install + mitigation + integration chapters (compile clean).

## Out of scope
- Multi-node HA / Kubernetes (Helm handles that).
- DNS / domain registration; external IDP (OIDC/SAML) setup.
- `ja4p config upgrade` schema-merge utility (future phase).
- The Go core itself ([[PHASE_231a]]).
- Go TAP sensor deployment (Phase 316).
