# Phase 132: Build Stabilization & CI/CD Hygiene

> **Status:** IN_PROGRESS
> **Size:** MEDIUM
> **Depends on:** Phase 131
> **Owner:** Gemini CLI

## Goal

Resolve broken build targets and CI failures introduced by the archival of legacy Python components. This phase ensures that the "modern" Go-centric codebase has a fully functional build system and that all remaining tests (Go and Python) pass with a "clean whistle" on GitHub.

## Scope

### Components in Scope
- **Build System**: Repairing `Makefile` targets and Docker contexts.
- **Test Infrastructure**: Archiving legacy Python tests that depend on deleted source code.
- **CI/CD**: Ensuring GitHub Actions are green and reflect the current architecture.
- **Consolidation**: Moving remaining active Python components into a consistent structure.

---

## Implementation Plan

### Wave 1: Path & Build Restoration
| ID | Task | Description | Size |
|---|---|---|---|
| **132.1** | **Restore Tarpit Context** | (Done) Move `tarpit` back to `src/tarpit` for Docker builds. | XS |
| **132.2** | **Restore SSL Artifacts** | (Done) Consolidate `ssl/` into `deploy/ssl/` for Docker builds. | XS |
| **132.3** | **Fix Makefile Paths** | Update all `make` targets to use current directory structure. | S |

### Wave 2: Test Suite Sanitization
| ID | Task | Description | Size |
|---|---|---|---|
| **132.4** | **Archive Legacy Tests** | Move `tests/unit/` files that depend on archived Python code to `archive/python_legacy/tests/`. | M |
| **132.5** | **Update Pytest Config** | Adjust `pyproject.toml` to only discover active tests. | XS |

### Wave 3: Final Verification
| ID | Task | Description | Size |
|---|---|---|---|
| **132.6** | **Local Full-Suite Run** | Run `make build lint test-go test-unit` and ensure 100% success. | S |
| **132.7** | **GitHub Action Check** | Push changes and monitor GHA status. | S |

---

## Acceptance Criteria

- [ ] `make build` completes successfully for all POC services.
- [ ] Go tests pass 100% (`make test-go`).
- [ ] Remaining Python tests pass 100% (`make test-unit`).
- [ ] No `ModuleNotFoundError` exceptions observed during test discovery.
- [ ] All GitHub Actions on the `main` branch are GREEN.
