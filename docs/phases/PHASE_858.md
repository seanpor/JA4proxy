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

Prevent silent configuration and environment drift by providing an automated verification test that ensures proxy runtime configuration loaders (`internal/config/loader.go`, `cmd/ja4pd/main.go`, `cmd/ja4-tap/main.go`), environment variables, and operator reference documentation (`docs/reference/ENV_VARS.md`) stay strictly synchronized.

---

## Junior Dev Feasibility & Sizing

- **Verdict:** **SMALL & Straightforward**.
- **Junior Dev Friendliness:** High. Involves standard AST / regex inspection in Python and markdown table validation, matching existing drift guards in `tests/unit/test_sync_reference_docs.py`.
- **Clear Bounds:** Excludes test files (`*_test.go`) and test harnesses (`internal/test/nullbackend/`). Matches on file paths rather than brittle line numbers.

---

## Scope

### In Scope
1. **Config & Env Var Drift Test (`tests/unit/test_config_doc_sync.py`)**:
   - Extract environment variable accesses (`os.Getenv`, `os.LookupEnv`) from production Go files (`cmd/`, `internal/`).
   - Explicitly filter out test files (`*_test.go`) and test mocks (`internal/test/`).
   - Parse configuration tables in `docs/reference/ENV_VARS.md`.
   - Assert 100% mutual inclusion: every production Go environment variable is documented, and every documented Go variable matches codebase reality.
   - Validate file paths without requiring volatile line number anchors.
2. **Reconcile Existing Unlisted Go Environment Variables in `docs/reference/ENV_VARS.md`**:
   - Add missing production variables (`JA4PROXY_SECURITY_POLICY_FAIL_OPEN`, `JA4PROXY_TEST_ALLOW_INSECURE_NETBOX`, `QUIC_SECRET_LOG`, `REDIS_PASSWORD`, `REDIS_URL`, `JA4T_BLOCKLIST`, `EXCLUDE_IPS`).
3. **Smoke Gate Integration**:
   - Integrated into `make test-unit` to catch configuration drift on PRs touching Go runtime configuration or environment variable loaders.

### Out of Scope
- Modifying proxy configuration parser logic.

---

## Acceptance Criteria
- [ ] `tests/unit/test_config_doc_sync.py` verifies zero drift between Go environment variable accesses and `docs/reference/ENV_VARS.md`.
- [ ] `docs/reference/ENV_VARS.md` accurately documents all production Go proxy environment variables.
- [ ] Any undocumented production environment variable fails CI with an actionable error message.
- [ ] `make test-unit` and `make preflight` pass 100% green.
