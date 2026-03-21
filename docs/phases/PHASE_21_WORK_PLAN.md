# Phase 21 Detailed Work Plan: Documentation Excellence

## 1. Overview
The goal of this phase is to elevate the project documentation to a 5/5 standard, enabling users of all personas (Operators, Devs, Security) to self-serve without ambiguity.

## 2. Implementation Sequence

### Step 1: Critical Fixes & Cleanup
*   **Task:** Audit the `docs/` directory for stale files.
*   **Action:** 
    *   Remove or heavily deprecate `docs/runbooks/management_ui.md` to reflect the v13.2.0 removal.
    *   Update `docs/TEST_ORGANIZATION.md` to reflect current test counts (1550+ tests).
    *   Fix the Phase 15 status contradictions across `CLAUDE.md`, `CHANGELOG.md`, and `PHASE_15.md`.

### Step 2: Persona-Based Navigation
*   **Task:** Redesign the documentation entry points.
*   **Action:** Create or update `docs/README.md` (or `INDEX.md`) with explicit, distinct sections:
    *   **New Operator (P1)**: Quickstart, PoC deployment.
    *   **Security Architect (P2)**: Threat models, Phase 20 TAP mode, Data flows.
    *   **Contributor (P3)**: TDD standards, Go/Python split, local testing.
    *   **Auditor (P5)**: GDPR compliance, Access logs.

### Step 3: ADR Backfill
*   **Task:** Fill the missing Architectural Decision Records.
*   **Action:** Write ADR-004 through ADR-012 as required by `DOCUMENTATION_STANDARDS.md`. Ensure existing ADRs (like ADR-015 for Go vs Rust) are linked correctly.

### Step 4: Documentation CI Guard
*   **Task:** Ensure docs don't rot.
*   **Action:** Add a lightweight Markdown link checker (e.g., `markdown-link-check`) to the Makefile and GitHub Actions CI pipeline.
*   **Validation:** `make lint-docs` should pass with zero broken internal links.