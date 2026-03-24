# JA4proxy Phase TODO List

This document tracks the remaining work for both historical phases (gaps identified post-completion) and upcoming planned phases. Each item links to a detailed, actionable TDD work plan.

## 🔴 Critical Gaps in Completed Phases (<= 15)

### Phase 15 — Go Rewrite
*   **Gap:** Lua scripts not using //go:embed
*   **Gap:** JA4X missing in Go pipeline
*   **Status:** **PARTIAL** (10-50x throughput improvement via CPython/Go transition.)
*   **Action Plan:** [PHASE_15_WORK_PLAN.md](PHASE_15_WORK_PLAN.md)

---

## 🟡 Phases In Progress

---

## 🔵 Planned & Open Phases

### Phase 13 — Management UI
*   **Status:** **DEFERRED** (FastAPI + React dashboard for real-time monitoring.)
*   **Action Plan:** [PHASE_13_WORK_PLAN.md](PHASE_13_WORK_PLAN.md)

### Phase 20 — Passive TAP Mode
*   **Status:** **OPEN** (AF_PACKET capture and out-of-band enforcement.)
*   **Action Plan:** [PHASE_20_WORK_PLAN.md](PHASE_20_WORK_PLAN.md)

### Phase 21 — Documentation Excellence
*   **Status:** **OPEN** (5/5 documentation quality and persona-based navigation.)
*   **Action Plan:** [PHASE_21_WORK_PLAN.md](PHASE_21_WORK_PLAN.md)

### Phase 22 — Backup System Enhancements
*   **Status:** **PROPOSED** (Encryption, cloud storage, incremental backups, and performance optimizations.)
*   **Action Plan:** [PHASE_22.md](PHASE_22.md)

### Phase 23 — Advanced Traffic Intelligence
*   **Status:** **PROPOSED** (Attacker attribution, geographical intelligence, and threat intelligence integration.)
*   **Action Plan:** [PHASE_23.md](PHASE_23.md)

### Phase 24 — Go Strategy Assessment
*   **Status:** **PROPOSED** (Assessment of minimal Go component vs comprehensive rewrite approach.)
*   **Action Plan:** [PHASE_24_STRATEGY_ASSESSMENT.md](PHASE_24_STRATEGY_ASSESSMENT.md)

### Phase 25 — Docker Container Management
*   **Status:** **OPEN** (Pin image versions, fix CVE scan gaps, first-party image scanning, image update policy.)
*   **Action Plan:** [PHASE_25.md](PHASE_25.md)
