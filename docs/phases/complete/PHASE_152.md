# Phase 152: Automated Build Versioning & Metadata Injection

> **Status:** PROPOSED
> **Size:** SMALL
> **Depends on:** Phase 150
> **Owner:** Gemini CLI

## Goal
Implement a deterministic build-numbering system that increments with every build and injects this metadata into all project binaries (`ja4pd`, `ja4p`, `ja4ps`) via Go linker flags.

## Context
Standardizing on a `v2.0.BUILD` format provides better traceability for SecOps teams, allowing them to verify exactly which build iteration is running in production.

## Scope

### 1. Build Number Persistence
- Create a `BUILD_NUMBER` file in the repository root to store the monotonic counter.
- Create a `VERSION` file (e.g., `2.0`) to store the major/minor baseline.

### 2. Makefile Automation
- Implement a `bump-build` target that increments the `BUILD_NUMBER` file.
- Update `go-build`, `sync-build`, and `cli-build` to:
    1.  Call `bump-build`.
    2.  Read the final version string (e.g., `v2.0.42`).
    3.  Inject this string into the Go binaries using `-ldflags="-X main.version=..."`.

### 3. Binary Instrumentation
- **`ja4pd`**: Log the version string on startup.
- **`ja4p`**: Update `ja4p version` to display the dynamic version string.
- **`ja4ps`**: Log the version on startup.

### 4. Build Metadata
- Inject additional build-time metadata:
    - `BuildDate`: RFC3339 timestamp.
    - `GitCommit`: Current HEAD SHA.

## Acceptance Criteria
- [ ] Every execution of `make build` increments the build number.
- [ ] `ja4p version` displays the correct `v2.0.X` string.
- [ ] `ja4pd` logs its version and Git SHA on startup.
- [ ] All binaries are tagged with the same build metadata.

---

## Strategic Intent
This phase moves the project toward a "Reproducible Build" philosophy. By capturing the exact build iteration and source state in the binary, we eliminate "which version is this?" ambiguity during incident response or performance audits.
