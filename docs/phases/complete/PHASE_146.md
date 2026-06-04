# Phase 146: Makefile Ergonomics & Standardization

> **Status:** IN_PROGRESS
> **Size:** SMALL
> **Depends on:** Phase 145
> **Owner:** Gemini CLI

## Goal
Streamline the developer and operator experience by standardizing high-level Makefile targets. Ensure that `make lint`, `make scan`, and `make test` perform exhaustive checks by default.

## Scope

### 1. Target Aliasing
- **`lint`**: Update to point to the comprehensive `lint-all` hierarchy.
- **`scan`**: Update to point to the exhaustive `scan-all` suite (Containers, Dockerfiles, First-party code, Images).
- **`test`**: Refactor to run the full test suite (Go native tests, Python unit tests, and smoke integration tests).

### 2. New Aggregates
- **`test-go-native`**: Add a dedicated target for `go test ./...` to ensure core logic is verified without Python parity overhead.
- **`test-all`**: Create a master test target that aggregates Go, Python, and Integration suites.

### 3. Cleanup
- Remove redundant or confusing "proxy only" docker-based linters in favor of the standardized hierarchy.

## Acceptance Criteria
- [ ] `make lint` runs all Python, Go, and Infra linters.
- [ ] `make scan` runs all security and container scans.
- [ ] `make test` runs all Go and Python tests.
- [ ] `make lint scan test` provides a 100% "green" signal for the repository state.
