<!--
title: Configuration Schema Auto-Documentation & Operator Drift Detection
audience: developer
last_reviewed: 2026-10-29
phase: 858
-->

# Configuration Schema Auto-Documentation & Operator Drift Detection

> **Size:** SMALL
> **Dependencies:** [857]
> **Branch:** `phase-858-config-drift-detection`

---

## Goal

Prevent silent configuration drift by providing an automated verification test and generator that ensures proxy runtime configuration schema (`internal/config/config.go`), CLI arguments (`cmd/ja4pd/main.go`), and operator documentation (`docs/reference/CONFIGURATION.md`) stay synchronized.

---

## Junior Dev Feasibility & Sizing

- **Verdict:** **SMALL & Straightforward**.
- **Junior Dev Friendliness:** High. Involves standard struct tag reflection in Go and markdown table validation in Python, matching existing drift guards in `tests/unit/`.

---

## Scope

### In Scope
1. **Config Key Reflection & Markdown Drift Test (`tests/unit/test_config_doc_sync.py`)**:
   - Extract all YAML/JSON field tags from `internal/config/config.go`.
   - Parse configuration tables in `docs/reference/CONFIGURATION.md`.
   - Assert 100% mutual inclusion: every struct field is documented, and every documented setting exists in the Go struct.
2. **Smoke Gate Integration**:
   - Integrated into `make test-unit` to catch documentation drift on PRs touching `internal/config/config.go`.

### Out of Scope
- Modifying proxy configuration parser logic.

---

## Acceptance Criteria
- [ ] `tests/unit/test_config_doc_sync.py` verifies zero drift between `internal/config/config.go` struct fields and `docs/reference/CONFIGURATION.md`.
- [ ] Any undocumented config key fails CI with an actionable error message.
- [ ] `make test-unit` and `make preflight` pass 100% green.
