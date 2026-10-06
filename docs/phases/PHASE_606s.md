# Proxy Server Package Extraction (cmd/ja4pd -> internal/server)

## Goal
Extract the core proxy server struct and handling loop from `cmd/ja4pd/main.go` (2,236 lines, `package main`) into a clean, reusable `internal/server` package. Establish component isolation for testability.

---

## Scope
1. **Source Package**: `cmd/ja4pd/main.go`.
2. **Target Package**: `internal/server/`.

---

## Test Strategy
- `make preflight`

---

## Acceptance Criteria
- [ ] `internal/server` extracted with zero breaking changes or behavioral regressions.
- [ ] `make test-unit` and `make preflight` pass 100% green.
