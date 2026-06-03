# Phase 127: Documentation Rationalization & Consolidation

> **Status:** PENDING
> **Size:** MEDIUM
> **Depends on:** Phase 126
> **Owner:** Gemini CLI

## Goal

Significantly reduce the cognitive load, verbosity, and maintenance overhead of the project's documentation. This phase will eliminate the fragmented "persona" directories, aggressively prune oversized documents (like the 1,700-line testing strategy), delete redundant stub files, and consolidate scattered operational guidance into a single, cohesive source of truth.

## Scope

### Components in Scope
- **Persona Directories**: `docs/for-architects/`, `docs/for-website-owners/`, `docs/for-operators/`, `docs/for-compliance/`, `docs/for-developers/`
- **Testing Docs**: `docs/TESTING_STRATEGY.md` and its associated stub files.
- **Operational Docs**: `docs/operator/`, `docs/runbooks/`, `docs/SECOPS_OPERATIONS.md`
- **Root Indexes**: `docs/README.md`, `docs/INDEX.md`

### Out of Scope
- Modifying `docs/phases/` (Phase documentation remains historical truth).
- Modifying compliance/regulatory mapping matrices.

---

## Implementation Plan

### Wave 1: Eradicate Personas & Flatten Root
*Focus: Simplifying the entry point.*

| ID | Task | Description | Size |
|---|---|---|---|
| **127.1** | **Flatten Personas** | Delete all 5 `docs/for-*/` directories. Move any uniquely valuable content (e.g., specific architectural diagrams) into the root `docs/` folder. | S |
| **127.2** | **Unify Root Index** | Merge `docs/INDEX.md` and `docs/README.md`. Create a single, concise `README.md` that uses simple H2 sections for different roles instead of separate folders. | S |

### Wave 2: Consolidate Operations & Runbooks
*Focus: Creating a single source of truth for operators.*

| ID | Task | Description | Size |
|---|---|---|---|
| **127.3** | **Unify Operations Guide** | Merge `docs/SECOPS_OPERATIONS.md`, the contents of `docs/operator/`, and `docs/runbooks/` into a single, well-structured `docs/OPERATIONS.md`. | M |
| **127.4** | **Prune Operational Fat** | Rewrite the new `OPERATIONS.md` to be checklist- and command-oriented. Remove conversational filler and excessive rationale (rationale belongs in ADRs). | M |
| **127.5** | **Cleanup Dirs** | Delete the now-empty `docs/operator/` and `docs/runbooks/` directories. | XS |

### Wave 3: Prune the Testing Strategy & Stubs
*Focus: Reducing verbosity and removing technical debt.*

| ID | Task | Description | Size |
|---|---|---|---|
| **127.6** | **Delete Stubs** | Delete `TESTING.md`, `TESTING_GO.md`, `TEST_ORGANIZATION.md`, and `TEST_SUITE.md`. | XS |
| **127.7** | **Prune Strategy** | Edit `TESTING_STRATEGY.md` (currently ~1,700 lines). Remove redundant philosophy, excessive Python-era legacy text, and over-prescriptive guidelines. Aim for < 500 lines focusing on *what* to test and *where* the CI gates are. | L |

---

## Verification & Acceptance Criteria

- [ ] All 5 `docs/for-*/` directories are deleted.
- [ ] `docs/README.md` is the sole entry point and contains the role-based routing.
- [ ] `docs/INDEX.md` is deleted.
- [ ] `docs/operator/` and `docs/runbooks/` are deleted.
- [ ] A single `docs/OPERATIONS.md` exists.
- [ ] `docs/TESTING_STRATEGY.md` is significantly reduced in line count.
- [ ] All redirect stub files for testing are deleted.
- [ ] `make lint-markdown` or equivalent documentation linters pass.
