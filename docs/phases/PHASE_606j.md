# CLI Engine & Command Tests

## Goal
Implement unit and execution flow tests for JA4proxy's command-line tool `ja4p` (`cmd/ja4p` and `internal/cli/engine`). Elevate package statement coverage from 0.0% to $\ge 80.0\%$.

---

## Read These First
- `cmd/ja4p/main.go` (CLI entrypoint and subcommand dispatch)
- `internal/cli/engine/` (CLI engine execution logic)

---

## Verified API Surface
- `cmd/ja4p` — `cmd/ja4p/main.go`
- `internal/cli/engine` — `internal/cli/engine/`

---

## Invariants

| ID | Plain-English Statement | Formal Statement | SecOps Rationale |
|---|---|---|---|
| `INV-CLI-001` | Unknown Flag Non-Zero Exit | $\forall \text{flag} \notin \text{Allowed}, \quad \text{Exec}(\text{flag}) \implies \text{ExitCode} \neq 0$ | Ensures invalid command invocations exit with an error code rather than executing silent default behavior. |
| `INV-CLI-002` | Output Format Determinism | $\forall \text{cmd}, \quad \text{Format}(\text{json}) \in \mathcal{L}(\text{ValidJSON})$ | Guarantees machine-readable CLI outputs strictly conform to JSON schemas for SecOps automation pipelines. |

---

## Step-by-Step Implementation Guide

### Step 1: Create `cmd/ja4p/cli_invariant_test.go`
```go
package main

import (
	"testing"
)

func TestInvariant_CLI_UnknownFlagExit(t *testing.T) {
	// Test subcommand flag validation...
}
```

---

## Make It Fail First

| Invariant ID | Temporary Code Mutation | Expected Test Failure |
|---|---|---|
| `INV-CLI-001` | Ignore flag parsing errors in `main.go` | Unknown flag test fails non-zero exit check |
| `INV-CLI-002` | Omit closing bracket in JSON output formatter | Output format test fails JSON schema parse |

---

## Test Commands

- **Run CLI Invariants:**
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./cmd/ja4p ./internal/cli/engine -run '^TestInvariant_CLI_'`
- **Run Invariant Suite:**
  `make test-invariants`

---

## Coverage Target

- **Packages `cmd/ja4p` & `internal/cli/engine` Baseline:** 0.0%
- **Target Coverage:** $\ge 80.0\%$

---

## Acceptance Criteria

- [ ] `cmd/ja4p/cli_invariant_test.go` created and passing.
- [ ] Invariants registered in `docs/testing/invariants.yaml`.
- [ ] `make test-invariants` count increased by 2.
- [ ] Package coverage verified $\ge 80.0\%$.
- [ ] News fragment created in `docs/fragments/phase-606j-cli-invariants.md`.
- [ ] `make preflight` passes 100% green.

---

## Out of Scope
- Management REST API (covered in Phase 606g).
