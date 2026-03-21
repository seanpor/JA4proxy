# JA4proxy Phase TODO List

This document tracks the remaining work for both historical phases (gaps identified post-completion) and upcoming planned phases. Each item links to a detailed, actionable TDD work plan.

## 🔴 Critical Gaps in Completed Phases (<= 15)

### Phase 12 — Analytics Node
*   **Gap (12a):** `requirements-analytics.txt` is referenced in the Dockerfile but does not exist. Docker build for the analytics container will fail.
*   **Gap (12b):** Signals from `src/analytics/detection.py` (Campaign/SlowScan) are written to Redis but the proxy scorer never reads them.
*   **Gap (12c):** Grafana dashboard for score drift monitoring is missing.
*   **Status:** **PARTIAL** (Core logic done, integration and packaging missing).
*   **Action Plan:** [Phase 12 Work Plan](PHASE_12_WORK_PLAN.md)

### Phase 13 — Management UI
*   **Gap:** The entire Management UI was removed in v13.2.0 due to implementation bloat and instability. It is deferred until after the Go rewrite is fully settled.
*   **Status:** **DEFERRED** (Requires complete rewrite from scratch).
*   **Action Plan:** [Phase 13 Work Plan](PHASE_13_WORK_PLAN.md)

### Phase 15 — Go Rewrite
*   **Gap (15c):** Several additive improvements are still open in `docs/phases/PHASE_15c.md`, including:
    *   Replacing runtime file-reads with `//go:embed` for Lua scripts.
    *   Implementing JA4X in Go (Phase 16 added it to Python, but it's missing in the Go pipeline).
*   **Status:** **COMPLETE (CORE)** / **OPEN (IMPROVEMENTS)**.
*   **Action Plan:** [Phase 15 Work Plan](PHASE_15_WORK_PLAN.md)

---

## 🟡 Phases In Progress (> 15)

### Phase 17 — Docker Test Container Hang
*   **Tasks Remaining:** 
    *   Patch `_tor_refresh_loop` in `tests/conftest.py`.
    *   Change `pytest_sessionfinish` to `tryfirst=True` in `tests/conftest.py`.
*   **Status:** **NEARLY DONE** (Only small edits to `conftest.py` remain).
*   **Action Plan:** [Phase 17 Work Plan](PHASE_17_WORK_PLAN.md)

### Phase 19 — Backup & Restore Framework
*   **Tasks Remaining:** Implementation is currently underway.
*   **Status:** **NEARLY DONE** (Implementation in progress).
*   **Action Plan:** [Phase 19 Execution Plan](PHASE_19_EXECUTION_PLAN.md) *(existing)*

---

## 🔵 Planned Phases (> 15)

### Phase 18 (formerly 17b) — Security Audit Remediation
*   **Problem:** Recent audit identified critical security anti-patterns that must be fixed.
*   **Tasks:**
    *   **Secure Exception Handling:** Replace broad `except Exception` blocks in `pipeline.py`, `security_manager.py`, etc.
    *   **Secure Logging:** Replace f-string logging with lazy formatting (`%s`) across the entire codebase to prevent information disclosure and performance overhead.
    *   **Architecture:** Implement dependency injection to reduce tight coupling in the security pipeline.
*   **Status:** **OPEN** (Plan exists in `docs/phases/PHASE_18.md`).
*   **Action Plan:** [Phase 18 Work Plan](PHASE_18_WORK_PLAN.md)

### Phase 20 — Passive TAP/SPAN Mode
*   **Goal:** Add a passive capture mode that doesn't sit inline.
*   **Tasks:** 
    *   Implement packet capture engine (`AF_PACKET`).
    *   Implement TCP stream reassembler.
    *   Add JA4S, JA4H, JA4L, JA4SSH extraction.
    *   Build enforcement bridge (iptables/BGP).
*   **Status:** **OPEN** (Large architectural phase).
*   **Action Plan:** [Phase 20 Work Plan](PHASE_20_WORK_PLAN.md)

### Phase 21 — Documentation Excellence
*   **Goal:** Reach 5/5 documentation quality.
*   **Tasks:** 
    *   Fix broken/stale references.
    *   Fill missing ADRs (ADR-004 to ADR-012).
    *   Consolidate overlapping content.
    *   Create persona-based navigation.
*   **Status:** **OPEN**.
*   **Action Plan:** [Phase 21 Work Plan](PHASE_21_WORK_PLAN.md)
