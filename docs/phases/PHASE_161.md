---
phase: 161
title: Setup Wizard Enhancements — Multi-Environment, Full Config, UX Polish
status: IN_PROGRESS
created: 2026-06-14
audience: [developer, operator]
---

# Setup Wizard Enhancements

> Builds on **Phase 231b** (core bootstrap via Python wizard) and **Phase 310** (lane-based
> multi-environment isolation). This phase **ports the wizard into Go** as proper `ja4p init`
> subcommand, extends the full configuration surface, integrates lane awareness, and adds
> production-hardening prompts — all with zero host-Python dependency.

## Goal

An operator can run `ja4p init` on a clean host and get a fully-configured, production-ready
JA4proxy deployment — including multi-environment lane isolation — without reading docs or
editing `.env` by hand. `ja4p` is a single compiled Go binary: no Python, no Docker, no
Jinja2 templates at runtime.

## Architectural Decision: Go-native, not Python

| Concern | Python approach (Phase 231b) | Go approach (Phase 161) |
|---------|------------------------------|--------------------------|
| Runtime | Requires host Python or `ja4proxy-tools` container | Single `ja4p` binary — no deps |
| Template engine | Jinja2 (`pip install`) | `//go:embed` + `text/template` — baked in |
| Shell completion | Hand-written scripts in `deploy/shell-completion/` | Cobra built-in `completion` command |
| Lane detection | `subprocess` calls to `lane-env.sh` or reimplement in Python | Direct `os/exec` of `lane-env.sh` (or port lane math to Go) |
| Security surface | Not exposed to network (admin-only CLI) | Same — `ja4p` is an admin CLI, not the proxy daemon |
| Relationship to 231b | 231b's Python wizard is a reference/prototype | 161 replaces it for production use |

**Rationale:** The existing `ja4p` CLI (`cmd/ja4p/`) already has a stub `init` command.
Extending it in Go adds zero attack surface to the proxy daemon (`ja4pd`) and eliminates
the host-Python compatibility problem entirely. The Python wizard (Phase 231b) stays as a
reference but is not required after 161 is complete.

## Current state

| Feature | Status | Source |
|---------|--------|--------|
| Inline topology (ja4pd) | ✅ Done | `ja4p init` stub + Phase 231b |
| Backend host/port | ✅ Done | `ja4p init` stub |
| Deploy mode (native/container) | ✅ Done | `ja4p init` stub |
| Admin bind IP / user / password | ✅ Done | `ja4p init` stub |
| Secret generation (chmod 600, never echoed) | ✅ Done | `ja4p init` stub |
| Lane-based isolation (port offsets, COMPOSE_PROJECT_NAME) | ✅ Phase 310 | `scripts/lane-env.sh` |
| `make lane` / `make open` / `make loadtest` | ✅ Phase 310 | Makefile targets |
| Python setup wizard (interactive, full secret management) | ✅ Phase 231b | `scripts/setup_wizard.py` |

## Scope — 5 sub-sections (A–E)

### A — Complete configuration surface (Go port + extension)

- **Allowed SNIs** (comma-separated; default: empty = allow all)
- **Upstream TCP load balancer** (yes/no) → if yes:
  - Enable `proxy_protocol` in config
  - `upstream_trust.trusted_cidrs` (comma-separated CIDRs; default: empty)
- **Write PROXY protocol to backend** (yes/no) → if yes:
  - PROXY protocol version (1 or 2; default: 1)
  - Uses Phase 231a feature (`write_proxy_protocol` + `write_proxy_protocol_version`)
- **TLS certificates**:
  - Self-signed (default, auto-generated in Go using `crypto/tls`) OR
  - User-supplied cert/key paths (validate existence + readability)
  - ACME/Let's Encrypt integration (deferred; document manual flow for now)
- **GeoIP database paths** (auto-detect `/opt/ja4proxy/data/geoip/*.mmdb`; prompt if missing)
- **Threat intelligence API keys** (optional; AbuseIPDB, GreyNoise, AlienVault, MISP, ThreatFox, VirusTotal, Recorded Future, CrowdStrike)
- **Dial value** (0-100; default: 0 = monitor mode; warn if > 50 on first run)
- **Log level** (DEBUG/INFO/WARN/ERROR; default: INFO)

### B — Multi-environment (lane) integration

- **Wizard detects existing lanes** on the host (reads `.env` files from other worktrees via `lane-env.sh --list` or direct filesystem scan).
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
- **Shell completion**: cobra's built-in `completion` command for bash/zsh/fish — no hand-written scripts.

### D — Production hardening prompts

- **Firewall backend**: UFW / firewalld / nftables / none (default: detect; if none, warn and print manual rules).
- **Fail2Ban / CrowdSec integration** (optional; default: no).
- **Log forwarding**: Loki / syslog / none (default: Loki if monitoring stack enabled).
- **Backup encryption**: `age` / `gpg` / none (default: none; if chosen, prompt for recipient/key).
- **Monitoring stack** (yes/no; default: yes) → if yes, includes Prometheus, Grafana, Alertmanager, Loki, node-exporter, cadvisor.

### E — Config file generation (Go templates, embedded)

- Generate `config/proxy.yml` from wizard answers using Go `text/template` — templates are `//go:embed`'d into the binary.
- Generate `config/haproxy.cfg` if HAProxy enabled — same approach.
- Validate generated configs with `ja4p config validate` before writing.
- Templates live in `cmd/ja4p/templates/` and are compiled into the binary at build time.

## Implementation plan

### 1. Go wizard engine (`cmd/ja4p/wizard/`)

- `wizard.go` — core types: `Answers`, `LaneInfo`, `GeneratedConfig`
- `prompts.go` — interactive prompts (I/O-injectable for tests, same pattern as Phase 231b Python)
- `validators.go` — input validators (hostname, port, CIDR, path, etc.)
- `secrets.go` — password/token generation (port existing `randomString`/`randomHex` from `main.go`)
- `lanes.go` — lane detection + allocation (calls `lane-env.sh --list` via `os/exec`, parses JSON; fallback to filesystem scan)
- `templates.go` — `//go:embed` template loading + rendering
- `output.go` — coloured terminal output, `--dry-run` summary, progress spinner

### 2. Templates (`cmd/ja4p/templates/`)

- `proxy.yml.tmpl` — full proxy config with all signal modules, parameterised by wizard answers
- `haproxy.cfg.tmpl` — HAProxy config template
- `systemd.service.tmpl` — systemd unit (already in Go `main.go`'s `buildSystemdUnit`, port to template)
- Embedded with `//go:embed templates/*.tmpl`

### 3. `cmd/ja4p/main.go` changes

- Refactor existing `runWizard()` into the new wizard package
- Add cobra flags: `--dry-run`, `--lane`, `--output-dir`, `--non-interactive` (for CI)
- Add `completion` command (cobra built-in)

### 4. `scripts/lane-env.sh` enhancements

- `--list` outputs JSON of all detected lanes (path, lane number, ports, project name, env name)
- `--preview <lane>` shows port map without allocating
- Keep as bash and call from Go via `os/exec`; add JSON contract

### 5. Tests

- Unit tests for each prompt validator (port to Go equivalents)
- Unit tests for template rendering
- Integration test: `go:embed` templates render correctly
- Lane detection test: no true Docker dependency, test against mock `.env` files
- Idempotency test: re-run wizard on same lane → secrets preserved

### Sub-phase ordering (within this branch)

| Order | Sub-phase | Description |
|-------|-----------|-------------|
| 161.1 | Wizard engine + templates | Core Go types, prompt framework, embedded template rendering, `--dry-run` |
| 161.2 | Section A — Full config surface | All config prompts implemented |
| 161.3 | Section B — Lane integration | Lane detection, selection, port preview, non-destructive merge |
| 161.4 | Section C — UX polish | Colours, spinners, help text, cobra completion, idempotency |
| 161.5 | Section D — Hardening prompts | Firewall, fail2ban, log forwarding, backup encryption, monitoring |
| 161.6 | Section E — Config file generation | Wire generated answers into template rendering, `ja4p config validate` |
| 161.7 | Tests + docs | Unit tests, integration test, docs update |

## Acceptance criteria

- [ ] `ja4p init` on a clean host produces a working deployment with **zero manual steps**.
- [ ] Two different worktrees run `ja4p init` simultaneously → **no port/container/network/volume collision**.
- [ ] Wizard offers **all config options** (A–E above) with **sensible defaults**.
- [ ] **Dry-run preview** shows exact `.env`, `proxy.yml`, `haproxy.cfg`, systemd unit — no files written.
- [ ] **Re-running wizard** on same lane is idempotent and preserves secrets.
- [ ] Generated configs pass `ja4p config validate`.
- [ ] `make lane` shows human-friendly environment names.
- [ ] `ja4p completion bash` (and zsh/fish) work.
- [ ] Docs updated: `OPERATIONS_GUIDE.md`, `docs/start/POC_QUICKSTART.md`, `MAKEFILE_TARGETS.md`.
- [ ] Phase 231b Python wizard is documented as superseded (not deleted — kept as reference).
- [ ] `make lint` and `make test` pass with zero warnings.

## Out of scope

- ACME/Let's Encrypt automation (document manual `certbot` flow; future phase).
- Kubernetes / Helm integration (separate track).
- Remote host deployment via SSH/Ansible (document `bootstrap.sh` + `ansible-playbook`).
- GUI / TUI (CLI wizard is sufficient; `ja4p` is the single binary).
- Deleting Phase 231b Python wizard (keep as reference, mark as superseded in manifest).

## Dependencies

- Phase 231b (core bootstrap — COMPLETE) — Python wizard to reference/port
- Phase 310 (lane isolation — COMPLETE) — `lane-env.sh` to integrate
- Phase 231a (PROXY protocol write — COMPLETE) — config keys to expose

## Size

LARGE (7 sub-phases across Go engine, templates, CLI, tests, docs).
