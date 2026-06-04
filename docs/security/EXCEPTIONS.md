<!--
title: Exceptions
audience: Security Teams, Auditors
last_reviewed: 2026-03-27
phase: 21
-->

# JA4proxy — Approved Security & Testing Exceptions

This document tracks all manual approvals for deviations from the project's Zero-Tolerance policy (skips, warnings, or deferred security fixes). Every entry represents an acknowledged risk with a documented justification.

---

## 📜 Approval Protocol

1.  **Request:** The agent must present a clear technical justification for why a test must be skipped or a warning ignored.
2.  **Manual Approval:** Approval must be granted explicitly by the user in the session history.
3.  **Logging:** Every approved exception is assigned an ID (e.g., `#001`) and logged below.
4.  **Reference:** Code-level suppressions must reference the ID in a comment.
5.  **Audit:** This file is part of the security audit trail.

---

## 🏗️ Active Exceptions

| ID | Type | Target | Justification | Approved By | Expiry Date |
|----|------|--------|---------------|-------------|-------------|
| #001 | Warning suppression | `pyproject.toml`: `ignore::pytest.PytestUnraisableExceptionWarning` | pycares async DNS callbacks arrive after the asyncio loop closes during test teardown. This is a known upstream bug in pycares's interaction with Python 3.10+ asyncio and pytest-asyncio. No actionable fix exists in our code — pycares teardown is entirely outside our control. | User approval 2026-03-21 | 2026-12-31 |
| #002 | Conditional skip | `tests/integration/test_multi_process_enforcement.py` | Skip when not running inside Docker Compose with multiple proxy workers. These tests verify cross-worker block enforcement via shared Redis and require real infrastructure (Redis cluster, multiple proxy instances). Skip is conditional on `_IN_DOCKER` flag — not unconditional. | User approval 2026-06-04 | None (indefinite, infra-gated) |
| #003 | Conditional skip | `tests/integration/test_phase_86h_alertmanager_runbook_urls.py` | Skip when `promtool` is not on `$PATH`. The test validates Alertmanager rule file syntax via promtool; if the tool is absent the test skips gracefully rather than failing. | User approval 2026-06-04 | None (indefinite, tool-gated) |

---

## 🗃️ Archive (Closed Exceptions)

| ID | Status | Resolution |
|----|--------|------------|
| | | |
