# CLI Engine Invariants

## Goal
Implement property-based invariant test suites for JA4proxy's command-line interface output formatting and rendering engine (`internal/cli/output`). Establish formal guarantees that JSON rendering outputs valid, parseable JSON data structures, that CSV output headers deterministically match exported struct field names, that non-slice input payloads trigger typed errors without runtime panics, and that terminal stream writes consistently append exact single trailing newlines.

---

## Read These First
- `internal/cli/output/output.go` (RenderTable, RenderJSON, RenderCSV, and WriteTo implementations)
- `internal/cli/output/output_test.go` (existing output unit tests)

---

## Verified API Surface
- `RenderTable(data)` — `internal/cli/output/output.go`
- `RenderJSON(data)` — `internal/cli/output/output.go`
- `RenderCSV(data)` — `internal/cli/output/output.go`
- `WriteTo(w, s)` — `internal/cli/output/output.go`

---

## Invariants

| ID | Plain-English Statement | Formal Statement | SecOps Rationale |
|---|---|---|---|
| `INV-CLI-001` | RenderJSON Valid JSON | $\text{json.Valid}(\text{RenderJSON}(D)) == \text{true}$ | Prevents malformed JSON output from breaking downstream CLI pipelines or automation scripts. |
| `INV-CLI-002` | RenderCSV Header Match | $\text{CSVHeader}(\text{RenderCSV}(D)) \equiv \text{StructFieldNames}(D)$ | Ensures CSV columns remain stable across schema versions for spreadsheet and SIEM ingestion. |
| `INV-CLI-003` | Non-Slice Error Handling | $\text{Kind}(D) \ne \text{Slice} \implies \text{Error} \ne \text{nil}$ | Prevents reflection panics when non-slice structures are passed to table/CSV renderers. |
| `INV-CLI-004` | WriteTo Trailing Newline | $\text{HasSuffix}(\text{WriteTo}(S), \text{"\n"}) \land \neg \text{HasSuffix}(\text{"\n\n"})$ | Ensures clean POSIX terminal line formatting across all CLI outputs. |

---

## Step-by-Step Implementation Guide

### Step 1: Create `internal/cli/output/output_invariant_test.go`
```go
package output_test

import (
	"encoding/json"
	"testing"

	"github.com/seanpor/ja4proxy/internal/cli/output"
	"pgregory.net/rapid"
)

func TestInvariant_CLI_RenderJSONValidJSON(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Test JSON valid output invariant
	})
}
```

---

## Acceptance Criteria

- [x] `internal/cli/output/output_invariant_test.go` created and all 4 invariants passing.
- [x] Invariants registered in `docs/testing/invariants.yaml`.
- [x] Package `internal/cli/output` coverage verified $\ge 91.2\%$.
- [x] News fragment created in `docs/fragments/phase-606j-cli-invariants.md`.
- [x] `make preflight` passes 100% green.

---

## Out of Scope
- Interactive shell prompt UI components (covered in Phase 230).
- Subcommand Cobra flag parsing.
