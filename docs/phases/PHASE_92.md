---
phase: 92
title: "Makefile Lint Target Hierarchy"
status: COMPLETE
size: SMALL
created: 2026-04-06
last_reviewed: 2026-04-06
audience: [developer, operator]
---

# Phase 92 — Makefile Lint Target Hierarchy

## Goal

Extend linting from syntax-only to full semantic analysis across every file
type in the repo, and organise all lint targets into a two-level hierarchy
with a single `lint-all` entry point.

---

## What Was Added

### New individual lint targets

| Target | Tool | What it catches |
|---|---|---|
| `lint-pylint` | pylint `--errors-only` | Semantic Python bugs: undefined names, unreachable code, attribute errors not caught by mypy/ruff |
| `lint-semgrep` | semgrep `--config=auto` | Cross-language patterns: dangerous API usage, logic errors, security anti-patterns across Python + Go |
| `lint-checkov` | checkov | IaC misconfigs in Dockerfiles, Compose, Ansible, Helm: running as root, exposed secrets, missing health checks |
| `lint-haproxy` | `haproxy -c` | HAProxy semantic validation: invalid ACLs, bad backend refs, port conflicts |
| `lint-helm` | `helm lint` | Helm chart structure, required values, Go template syntax |
| `lint-ansible` | ansible-lint | Ansible: shell-when-command-works, hardcoded passwords, deprecated modules |
| `lint-markdown` | markdownlint-cli2 | Markdown structure: heading hierarchy, list consistency, code fence language |
| `lint-spelling` | codespell | Typos in docs and code |
| `lint-toml` | python3 tomllib | TOML syntax + parse validation (`pyproject.toml`, `.gitleaks.toml`) |
| `lint-makefiles` | checkmake | Missing `.PHONY`, tabs vs spaces, recursive make anti-patterns |
| `lint-go-mod` | `go mod verify` | Module checksum integrity — detects tampered dependencies |

### New aggregate targets

| Aggregate | Contains |
|---|---|
| `lint-python` | lint-static, lint-security, lint-pylint |
| `lint-go` | go-lint, lint-go-full, lint-go-mod |
| `lint-sast` | lint-semgrep, lint-checkov |
| `lint-infra` | lint-docker, lint-shell, lint-yaml, lint-lua, lint-json, lint-haproxy, lint-makefiles, lint-toml, lint-ansible, lint-helm |
| `lint-observability` | lint-prom, lint-alertmanager |
| `lint-supply-chain` | lint-secrets, lint-deps |
| `lint-docs-all` | lint-docs, lint-phases, link-check, lint-markdown, lint-spelling |
| **`lint-all`** | all seven groups above |

### Other fixes

- `docker/docker-compose.scale.yml` added to `lint-docker` compose validation
- `gosec` and `bodyclose` added to `.golangci.yaml` (enabled in `lint-go-full`)

---

## Acceptance Criteria

- [x] `make lint-python` runs lint-static, lint-security, lint-pylint
- [x] `make lint-go` runs go-lint, lint-go-full, lint-go-mod
- [x] `make lint-sast` runs lint-semgrep, lint-checkov
- [x] `make lint-infra` runs lint-docker, lint-shell, lint-yaml, lint-lua, lint-json, lint-haproxy, lint-makefiles, lint-toml, lint-ansible, lint-helm
- [x] `make lint-observability` runs lint-prom, lint-alertmanager
- [x] `make lint-supply-chain` runs lint-secrets, lint-deps
- [x] `make lint-docs-all` runs lint-docs, lint-phases, link-check, lint-markdown, lint-spelling
- [x] `make lint-all` runs all seven groups
- [x] No existing Makefile targets modified
- [x] All new targets in `.PHONY`
- [x] `make help` documents all new targets
- [x] `make lint-phases` passes
- [x] `docs/phases/manifest.yaml` updated to COMPLETE
- [x] `docs/phases/TODO.md` and `docs/PROJECT_STATUS.md` regenerated

---

## Non-Goals

- Not changing behaviour of any existing lint target
- Deeper quality tooling (mutation testing, complexity gating, schemathesis) deferred to a future phase
