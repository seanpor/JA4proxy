# Phase 128: Python Legacy Proxy Deprecation & Archival

> **Status:** PENDING
> **Size:** SMALL
> **Depends on:** Phase 127
> **Owner:** Gemini CLI

## Goal

Formally deprecate, archive, and cease maintenance/linting for the original Python proxy implementation (`proxy.py` and core modules). This reduces CI/CD overhead and focuses maintenance efforts on the production Go proxy, while preserving the Python code running the Analytics and Management nodes.

## Scope

### Components in Scope
- **Legacy Proxy Root**: `proxy.py`
- **Core Proxy Modules**: `src/tls/`, `src/security/`, `src/cache/`, `src/tap/`, `src/tarpit/`, `src/ebpf/`, `src/telemetry/`, `src/config/`, `src/utils/`, `src/backup/`, `src/governance/`, `src/cli/`, `src/pubsub.py`
- **Linting & CI Configuration**: `Makefile` (`lint-static`, `lint-pylint`, `lint-quality`, `lint-coverage`), `scripts/check_updates.py`.

### Out of Scope
- `src/analytics/` (Required for Go proxy ECS streams).
- `src/management/` & root `management/` (Required for Control Plane).
- `tests/` directory (Tests verify the Go proxy via parity or direct API calls).
- Python test runners and helper scripts (`scripts/`).

---

## Implementation Plan

### Wave 1: Code Movement & Deprecation
| ID | Task | Description | Size |
|---|---|---|---|
| **128.1** | **Create Archive** | Create `archive/python_legacy/src/`. | XS |
| **128.2** | **Move Core Proxy** | Move `proxy.py` and the core `src/` modules (tls, security, cache, tap, tarpit, ebpf, telemetry, config, utils, backup, governance, cli, pubsub.py) into the archive. | S |
| **128.3** | **Deprecation Notice** | Add `archive/python_legacy/DEPRECATED.md` clearly stating the code is unmaintained, unscanned, and retained for historical reference only. | XS |

### Wave 2: CI & Toolchain Cleanup
| ID | Task | Description | Size |
|---|---|---|---|
| **128.4** | **Makefile Pruning** | Update `lint-static`, `lint-pylint`, `lint-quality`, and `lint-coverage` targets to exclude `archive/python_legacy/` and remove `proxy.py` references. | S |
| **128.5** | **Update Checker** | Ensure `scripts/check_updates.py` ignores requirements within the archive directory. | XS |
| **128.6** | **Dependency Trim** | (Optional/Advisory) Note any dependencies in `requirements.txt` that were exclusively used by the Python proxy, though removal may break tests if they share them. | S |

---

## Verification & Acceptance Criteria

- [ ] `proxy.py` and core modules reside in `archive/python_legacy/`.
- [ ] `src/analytics/` and `src/management/` remain untouched.
- [ ] `make lint-all` runs successfully and ignores the archived code.
- [ ] `DEPRECATED.md` exists in the archive folder.
