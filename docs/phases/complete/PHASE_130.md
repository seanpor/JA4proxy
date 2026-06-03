# Phase 130: Repository Housekeeping & Hygiene

> **Status:** IN_PROGRESS
> **Size:** SMALL
> **Depends on:** Phase 129
> **Owner:** Gemini CLI

## Goal

Clean up the repository root, consolidate temporary artifacts into dedicated directories, and establish a robust mechanism to keep the project "pristine" for developers. This reduces clutter, prevents accidental commits of transient data, and improves the overall developer experience.

## Scope

### Components in Scope
- **Repository Root**: Removal or relocation of stray files (`.zip`, `.txt`, `.env.gemini*`).
- **Artifact Directories**: Consolidation of test results into `test-results/`.
- **Git Hygiene**: Reinforcing `.gitignore` for modern tool caches (Ruff, MyPy, etc.).
- **Build System**: Enhancing the `make clean` target to be more comprehensive.

### Out of Scope
- Changing the core directory structure of the Go/Python source code.
- Modifying historical Phase documentation.

---

## Implementation Plan

### Wave 1: Root Directory Cleanup
| ID | Task | Description | Size |
|---|---|---|---|
| **130.1** | **Move Test Results** | Move all `test_results_*.txt` and `connections-export-*.jsonl` files from the root to `test-results/`. | XS |
| **130.2** | **Remove Stray Archives** | Delete stray `.zip` and `.tar.gz` files from the root (e.g., `ja4proxy_plan.zip`). | XS |
| **130.3** | **Cleanup .env Clutter** | Remove temporary environment files like `.env.gemini2`, `.env.Gemini2`, etc. | XS |

### Wave 2: Git & Toolchain Reinforcement
| ID | Task | Description | Size |
|---|---|---|---|
| **130.4** | **Reinforce .gitignore** | Add `.ruff_cache/`, `.mypy_cache/`, `.qwen/`, and other tool-specific caches to `.gitignore`. | XS |
| **130.5** | **Comprehensive Clean** | Update the `make clean` target to remove ALL temporary artifacts: binaries, caches, test results, and Docker artifacts. | S |

### Wave 3: Verification
| ID | Task | Description | Size |
|---|---|---|---|
| **130.6** | **Pristine Verification** | Run `make clean`, verify the root is empty of transient files, and run `git status` to ensure nothing is tracked that shouldn't be. | S |

---

## Acceptance Criteria

- [ ] Repository root contains only essential project files and directories.
- [ ] No `test_results_*.txt` files exist in the root.
- [ ] `.gitignore` explicitly excludes all modern dev caches (Ruff, MyPy, Aider, Qwen).
- [ ] `make clean` successfully resets the local environment to a "pristine" state.
- [ ] A summary of the cleanup is added to `MEMORY.md`.
