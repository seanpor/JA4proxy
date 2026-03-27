# Phase 21 Detailed Work Plan: Documentation Excellence

## 1. Overview
The goal of this phase is to elevate the project documentation to a 5/5 standard, enabling users of all personas (Operators, Devs, Security) to self-serve without ambiguity.

## 2. Implementation Sequence

### Step 1: Critical Fixes & Cleanup
*   **Task:** Audit the `docs/` directory for stale files.
*   **Action:** 
    *   Add DEPRECATED header to `docs/runbooks/management_ui.md` (removed in v13.2.0).
    *   Update `docs/TEST_ORGANIZATION.md` to use dynamic test count query.
    *   Fix Phase 15 status contradictions across `CLAUDE.md`, `CHANGELOG.md`, and `PHASE_15.md`.
    *   Update `docs/OBSERVABILITY_STANDARDS.md` to reference all three alert rule files.
    *   Add audience stamps to all major documentation files.
    *   Create `docs/INDEX.md` for persona-based navigation.
    *   Write missing ADRs (ADR-004 through ADR-012).
    *   Expand `docs/compliance/GDPR_COMPLIANCE.md` to enterprise standard.
    *   Update system architecture diagrams to include Go components.
    *   Document mock servers in `docs/developer/MOCK_SERVERS.md`.

### Step 2: Persona-Based Navigation
*   **Task:** Redesign the documentation entry points.
*   **Action:** 
    *   Add "Start here by role" table to `docs/README.md`.
    *   Create comprehensive `docs/INDEX.md` structured by persona.
    *   Add audience stamps to all documentation files.
    *   Create `docs/decisions/INDEX.md` for ADR navigation.

### Step 3: ADR Backfill
*   **Task:** Fill the missing Architectural Decision Records.
*   **Action:** 
    *   Write ADR-004 through ADR-012 following the standard template.
    *   Review and update existing ADRs (001, 002, 003, 013, 015) for post-Phase 15 accuracy.
    *   Create `docs/decisions/INDEX.md` listing all ADRs.

### Step 4: Documentation CI Guard
*   **Task:** Ensure docs don't rot.
*   **Action:** 
    *   Add `markdown-link-check` to Makefile and CI pipeline.
    *   Create `scripts/check_doc_frontmatter.py` for frontmatter validation.
    *   Add `make lint-docs`, `make link-check`, and `make doc-health` targets.
    *   Update phase completion gate to include documentation checks.
*   **Validation:** All documentation CI checks pass with zero warnings.

### Step 5: Diagram Standardization
*   **Task:** Replace all diagrams with Mermaid diagrams.
*   **Action:** 
    *   Audit all documentation files for existing diagrams.
    *   Convert diagrams to Mermaid syntax where appropriate.
    *   Update `docs/architecture/system-architecture.md` with Go architecture diagram.
    *   Ensure all new diagrams follow consistent style.
*   **Validation:** All architecture diagrams are in Mermaid format and current.
