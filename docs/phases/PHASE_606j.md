# CLI Engine & Command Tests

## Goal
Implement unit and execution flow tests for JA4proxy's command-line interface (`cmd/ja4p` and `internal/cli/engine`). Elevate statement coverage from 0.0% to $\ge 80\%$.

---

## Scope
1. **Target Packages**: `cmd/ja4p`, `internal/cli/engine`.
2. **New Test Files**: `cmd/ja4p/cli_test.go`, `internal/cli/engine/engine_test.go`.

---

## Test Strategy
- `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./cmd/ja4p ./internal/cli/engine`

---

## Acceptance Criteria
- [ ] `cmd/ja4p` and `internal/cli/engine` test suites implemented and passing.
- [ ] Statement coverage $\ge 80\%$.
