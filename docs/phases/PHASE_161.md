---
phase: 161
title: Setup Wizard Enhancements — Multi-Environment, Full Config, UX Polish
status: PROPOSED
created: 2026-06-14
audience: [developer, operator]
---

# Setup Wizard Enhancements

> Builds on **Phase 231b** (core bootstrap delivered) and **Phase 310** (lane-based
> multi-environment isolation). This phase makes the wizard **comprehensive** (all
> config options), **multi-environment aware** (integrates with lanes), and
> **delightful to use** (sensible defaults, validation, preview, idempotency).

## Goal

An operator can run `ja4p init` (or `python3 scripts/setup_wizard.py`) on a clean
host and get a fully-configured, production-ready JA4proxy deployment — including
multi-environment isolation — without reading docs or editing `.env` by hand.

## Current state (from Phase 231b + 310)

| Feature | Status |
|---------|--------|
| Inline topology (ja4pd) | ✅ Done |
| Backend host/port | ✅ Done |
| Deploy mode (native/container) | ✅ Done |
| Admin bind IP / user / password | ✅ Done |
| Secret generation (chmod 600, never echoed) | ✅ Done |
| systemd unit generation | ✅ Done |
| Lane-based isolation (port offsets, COMPOSE_PROJECT_NAME) | ✅ Phase 310 |
| `make lane` / `make open` / `make loadtest` | ✅ Phase 310 |

## Missing / to enhance

### A — Complete configuration surface
- **Allowed SNIs** (comma-separated; default: empty = allow all)
- **Upstream TCP load balancer** (yes/no) → if yes:
  - Enable `proxy_protocol` in config
  - `upstream_trust.trusted_cidrs` (comma-separated CIDRs; default: empty)
- **Write PROXY protocol to backend** (yes/no) → if yes:
  - PROXY protocol version (1 or 2; default: 1)
  - Uses Phase 231a feature (`write_proxy_protocol` + `write_proxy_protocol_version`)
- **TLS certificates**:
  - Self-signed (default, auto-generated) OR
  - User-supplied cert/key paths (validate existence + readability)
  - ACME/Let's Encrypt integration (deferred; document manual flow for now)
- **GeoIP database paths** (auto-detect `/opt/ja4proxy/data/geoip/*.mmdb`; prompt if missing)
- **Threat intelligence API keys** (optional; AbuseIPDB, GreyNoise, AlienVault, MISP, ThreatFox, VirusTotal, Recorded Future, CrowdStrike)
- **Dial value** (0-100; default: 0 = monitor mode; warn if > 50 on first run)
- **Log level** (DEBUG/INFO/WARN/ERROR; default: INFO)

### B — Multi-environment (lane) integration
- **Wizard detects existing lanes** on the host (reads `.env` files from other worktrees via `lane-env.sh --list`).
- **Lane selection menu**:
  - "Create new environment" (auto-assign next free lane)
  - "Reuse existing lane N" (shows its ports + services; confirms intent)
- **Environment naming**: wizard prompts for a human-friendly name (e.g., "prod", "staging", "dev-agent-a") that becomes a label in the lane metadata and appears in `make lane` output.
- **Port preview**: before writing, show the exact 12 `HOST_PORT_*` values that will be used (base + lane×100) and which ones are already taken on the host.
- **Non-destructive**: wizard never clobbers secrets in an existing `.env`; it merges new keys and preserves existing ones.

### C — UX polish & safety
- **Dry-run / preview mode** (`--dry-run`): shows the complete `.env` + systemd unit + config snippets that would be written, without writing anything.
- **Validation summary**: after collecting answers, show a concise "You are about to configure:" table before the final confirm.
- **Idempotent re-run**: running the wizard again on the same lane updates only the keys that changed; secrets are preserved; systemd unit is regenerated.
- **Rollback hint**: on success, print `To undo: ja4p config rollback` (future) or manual steps.
- **Progress indicators**: for long steps (cert generation, offline image load), show a spinner.
- **Coloured output**: use ANSI colours for prompts, warnings, errors, success (respect `NO_COLOR` / `--no-color`).
- **Help text**: every prompt has a `--help` style hint accessible via `?` at the prompt.
- **Shell completion**: generate bash/zsh/fish completion for `ja4p init` subcommands.

### D — Production hardening prompts
- **Firewall backend**: UFW / firewalld / nftables / none (default: detect; if none, warn and print manual rules).
- **Fail2Ban / CrowdSec integration** (optional; default: no).
- **Log forwarding**: Loki / syslog / none (default: Loki if monitoring stack enabled).
- **Backup encryption**: `age` / `gpg` / none (default: none; if chosen, prompt for recipient/key).
- **Monitoring stack** (yes/no; default: yes) → if yes, includes Prometheus, Grafana, Alertmanager, Loki, node-exporter, cadvisor.

### E — Config file generation (beyond `.env`)
- Generate `config/proxy.yml` from wizard answers (template-based).
- Generate `config/haproxy.cfg` if HAProxy enabled.
- Validate generated configs with `ja4p config validate` before writing.

## Implementation plan

### 1. Extend `scripts/setup_wizard.py`
- Add `LaneManager` class (imports `lane-env.sh` logic or reimplements in Python).
- Add `ConfigTemplate` class (Jinja2 templates for `proxy.yml`, `haproxy.cfg`).
- New prompts grouped into sections with clear headers.
- `--dry-run` flag prints full preview.
- `--lane` flag to pre-select lane (non-interactive CI friendly).
- `--output-dir` for config files (default: deploy root `/opt/ja4proxy/config`).

### 2. `scripts/lane-env.sh` enhancements
- `--list` outputs JSON of all detected lanes (path, lane number, ports, project name, env name).
- `--preview <lane>` shows port map without allocating.
- Export Python-importable functions via a small module or JSON stdout.

### 3. `ja4p` CLI integration
- `ja4p init` entry point (wraps `setup_wizard.py`).
- `ja4p lane list` / `ja4p lane preview` / `ja4p lane switch`.
- Completion scripts in `deploy/shell-completion/`.

### 4. Templates
- `templates/proxy.yml.j2` — full proxy config with all signal modules.
- `templates/haproxy.cfg.j2` — HAProxy config parameterised by wizard.
- `templates/systemd.j2` — already in `build_systemd_unit()`, keep in sync.

### 5. Tests
- Unit tests for each new prompt validator.
- Integration test: two worktrees run `ja4p init` concurrently → no collision.
- `test_container_config` style: generated `.env` + `proxy.yml` have all expected keys.
- Idempotency test: re-run wizard on same lane → secrets preserved, only changed keys updated.

## Acceptance criteria

- [ ] `ja4p init` on a clean host produces a working deployment with **zero manual steps**.
- [ ] Two different worktrees run `ja4p init` simultaneously → **no port/container/network/volume collision**.
- [ ] Wizard offers **all config options** (A–E above) with **sensible defaults**.
- [ ] **Dry-run preview** shows exact `.env`, `proxy.yml`, `haproxy.cfg`, systemd unit.
- [ ] **Re-running wizard** on same lane is idempotent and preserves secrets.
- [ ] Generated configs pass `ja4p config validate`.
- [ ] `make lane` shows human-friendly environment names.
- [ ] Shell completion works for `ja4p init` subcommands.
- [ ] Docs updated: `OPERATIONS_GUIDE.md`, `docs/start/POC_QUICKSTART.md`, `MAKEFILE_TARGETS.md`.

## Out of scope

- ACME/Let's Encrypt automation (document manual `certbot` flow; future phase).
- Kubernetes / Helm integration (separate track).
- Remote host deployment via SSH/Ansible (document `bootstrap.sh` + `ansible-playbook`).
- GUI / TUI (CLI wizard is sufficient; `ja4p` is the single binary).

## Dependencies

- Phase 231b (core bootstrap — COMPLETE)
- Phase 310 (lane isolation — COMPLETE)
- Phase 231a (PROXY protocol write — COMPLETE)

## Size

LARGE (multiple sub-tasks across wizard, templates, CLI, tests, docs).