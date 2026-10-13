# Documentation Information Architecture

## Goal
Reorganize and synchronize the project documentation to ensure a clear "Information Architecture" (IA) that aligns with the Go-v2 codebase and the needs of different personas (Architects, Operators, Developers).

## Background
Phase 309 (Documentation Content Audit) identified "residual" work including a formal IA restructure. While individual docs are accurate, the navigation and cross-referencing between the Reference Manual, Operator Guides, and Developer docs can be improved to reduce cognitive load.

## Scope
1.  **IA Mapping**: Define a formal mapping between the repository structure (`cmd/`, `internal/`, `docs/`) and the documentation hierarchy.
2.  **Cross-Reference Audit**: Ensure every `internal/` package has a corresponding entry in the Reference Manual and that all `docs/` links resolve correctly.
3.  **Persona Navigation**: Refine the "Landing Pages" for each persona (Architects, Operators, etc.) to ensure they point to the most relevant sections.
4.  **Runbooks Batch 2+**: Complete the remaining operator runbooks (Phase 309 "Runbooks Batch 2+").

## Implementation Plan
1.  **Step 1: IA Design**
    *   Create `docs/architecture/INFORMATION_ARCHITECTURE.md`.
    *   Map `cmd/ja4pd` -> "Proxy Daemon", `cmd/ja4p` -> "CLI Reference", etc.
2.  **Step 2: Link Remediation**
    *   Run `lychee` across the entire `docs/` directory and fix any remaining broken links.
    *   Update the `Makefile` lint target to include a link-check step.
3.  **Step 3: Persona Landing Pages**
    *   Update `docs/for-architects/README.md`, `docs/for-operators/README.md`, and `docs/for-developers/README.md` with updated "Quick Start" and "Deep Dive" links.
4.  **Step 4: Runbooks**
    *   Identify and write the remaining high-priority runbooks from the Phase 309 list.

## Acceptance Criteria
1.  `docs/architecture/INFORMATION_ARCHITECTURE.md` exists and is signed off.
2.  `make lint-docs-all` passes with zero link errors.
3.  Every persona landing page has a valid "Next Steps" path.
4.  All high-priority runbooks from Phase 309 are present.

## Dependencies
*   Phase 309 (Documentation Content Audit) - **COMPLETE**
*   Phase 127 (Documentation Rationalization) - **COMPLETE**
