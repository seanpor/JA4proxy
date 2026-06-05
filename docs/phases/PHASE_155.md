# Phase 155: Strategic Consolidation & Release Preparation

> **Status:** PROPOSED
> **Size:** MEDIUM
> **Depends on:** Phase 153, Phase 154
> **Owner:** Gemini CLI

## Goal
Finalize the repository for its "Brochure Moment" by consolidating all operational tools into a single binary, purging development artifacts, and preparing structured performance data for automated marketing exports.

## Scope

### 1. The "Single Tool" Operational Model
- **Tool Merging**: Integrate the following into the `ja4p` CLI as subcommands:
    - `ja4bench` -> `ja4p test benchmark` (Go-native load tester)
    - `ja4ps` -> `ja4p cluster sync` (The sync mesh agent)
- **Binary Minimalism**: Ensure the final distribution contains exactly two binaries: `ja4pd` (Engine) and `ja4p` (Operational Toolset).

### 2. Structured Performance Data
- **Brochure JSON**: Generate a machine-readable `docs/reports/PERFORMANCE_SNAPSHOT.json` containing:
    - Micro-benchmark latencies (p99).
    - Macro-benchmark throughput (conn/s).
    - Resource efficiency metrics (RAM/CPU).
- **Metadata Alignment**: Ensure versioning and build dates in the JSON match the `v2.0.x` release state.

### 3. Repository Purge (The "Clean Room" Initiative)
- **Root Cleanup**: Delete the following obsolete/transient files:
    - `Dockerfile` (root-level, redundant to `deploy/docker/`)
    - `QWEN.md`
    - `opencode.json`
    - `.aider.chat.history.md`
    - Any lingering `proxy` or `ja4proxy` root binaries.
- **Git Hygiene**: Update `.gitignore` to permanently block root-level binaries.

### 4. Enterprise Compliance Audit
- **License Sweep**: Verify that all Go source files (`internal/`, `cmd/`) have standard MIT/BSD-style license headers.
- **Security Check**: Final sweep for hardcoded secrets or local paths.

## Acceptance Criteria
- [ ] Binaries `ja4ps` and `ja4bench` are removed and their logic lives inside `ja4p`.
- [ ] `ja4p test benchmark` successfully executes a 10k connection burst.
- [ ] `docs/reports/PERFORMANCE_SNAPSHOT.json` is valid and ready for the PDF generator.
- [ ] Repository root is visually clean, containing only essential project entry points.

---

## Strategic Intent
This phase transforms the workspace from a "development forge" into a "polished product". It ensures that when an enterprise evaluator downloads the repo, they see a clean, professional, and highly capable system with a single clear entry point for all operations.
