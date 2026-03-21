# JA4proxy Phase TODO List

This document tracks the remaining work for both historical phases (gaps identified post-completion) and upcoming planned phases. Each item links to a detailed, actionable TDD work plan.

## 🔴 Critical Gaps in Completed Phases (<= 15)

### Phase 12 — Analytics Node
*   **Gap:** requirements-analytics.txt missing in Dockerfile
*   **Gap:** Campaign/SlowScan signals not read by proxy scorer
*   **Gap:** Grafana drift dashboard missing
*   **Status:** **PARTIAL** (Cross-instance statistical analysis via Redis Streams.)
*   **Action Plan:** [PHASE_12_WORK_PLAN.md](PHASE_12_WORK_PLAN.md)

### Phase 15 — Go Rewrite
*   **Gap:** Lua scripts not using //go:embed
*   **Gap:** JA4X missing in Go pipeline
*   **Status:** **PARTIAL** (10-50x throughput improvement via CPython/Go transition.)
*   **Action Plan:** [PHASE_15_WORK_PLAN.md](PHASE_15_WORK_PLAN.md)

---

## 🟡 Phases In Progress

### Phase 17 — Docker Test Optimization
*   **Task:** Patch _tor_refresh_loop in tests/conftest.py
*   **Task:** Change pytest_sessionfinish to tryfirst=True
*   **Status:** **NEARLY DONE** (Fix Docker test container hang during teardown.)
*   **Action Plan:** [PHASE_17_WORK_PLAN.md](PHASE_17_WORK_PLAN.md)

### Phase 19 — Backup & Restore
*   **Status:** **NEARLY DONE** (Automated Redis state migration and recovery.)
*   **Action Plan:** [PHASE_19_EXECUTION_PLAN.md](PHASE_19_EXECUTION_PLAN.md)

---

## 🔵 Planned & Open Phases

### Phase 13 — Management UI
*   **Status:** **DEFERRED** (FastAPI + React dashboard for real-time monitoring.)
*   **Action Plan:** [PHASE_13_WORK_PLAN.md](PHASE_13_WORK_PLAN.md)

### Phase 18 — Security Audit Remediation
*   **Status:** **OPEN** (Fix broad exception handling and f-string logging.)
*   **Action Plan:** [PHASE_18_WORK_PLAN.md](PHASE_18_WORK_PLAN.md)

### Phase 20 — Passive TAP Mode
*   **Status:** **OPEN** (AF_PACKET capture and out-of-band enforcement.)
*   **Action Plan:** [PHASE_20_WORK_PLAN.md](PHASE_20_WORK_PLAN.md)

### Phase 21 — Documentation Excellence
*   **Status:** **OPEN** (5/5 documentation quality and persona-based navigation.)
*   **Action Plan:** [PHASE_21_WORK_PLAN.md](PHASE_21_WORK_PLAN.md)
