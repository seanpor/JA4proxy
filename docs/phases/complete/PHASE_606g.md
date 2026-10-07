# Configuration Engine & Atomic Reload Invariants

## Goal
Implement property-based invariant test suites for JA4proxy's configuration loading, environment variable expansion, and policy validation engine (`internal/config`). Establish formal guarantees that `DefaultConfig()` is strictly valid under schema validation, that invalid TCP bind and target ports outside $[1, 65535]$ are rejected deterministically, that environment variable expansion matches `${VAR:-default}` rules without mutating unrelated text, and that risk scorer threshold ordering violations are caught before runtime startup.

---

## Read These First
- `internal/config/loader.go` (YAML loading, FlexInt unmarshaling, and Validate methods)
- `internal/config/validate_test.go` (existing config validation unit tests)

---

## Verified API Surface
- `DefaultConfig()` — `internal/config/loader.go`
- `Load(path)` — `internal/config/loader.go`
- `(*Config).Validate()` — `internal/config/loader.go`

---

## Invariants

| ID | Plain-English Statement | Formal Statement | SecOps Rationale |
|---|---|---|---|
| `INV-CONFIG-001` | Default Config Validity | $\text{DefaultConfig}().\text{Validate}() == \text{nil}$ | Ensures default out-of-the-box configuration is guaranteed to pass validation. |
| `INV-CONFIG-002` | Invalid Port Rejection | $\forall p \notin [1, 65535], \quad \text{Validate}() \text{ returns error}$ | Prevents invalid network socket bindings or backend proxy targets from causing runtime crashes. |
| `INV-CONFIG-003` | Env Var Expansion Integrity | $\text{Load}(\text{YAML}) \implies \text{ExpandEnvVars}(\text{value})$ | Guarantees standard container environment variable injection semantics without corruption. |
| `INV-CONFIG-004` | Risk Scorer Threshold Monotonicity | $\neg (\text{flag} \le \text{rate\_limit} \le \text{tarpit} \le \text{block} \le \text{ban}) \implies \text{Error}$ | Prevents inverted threshold policies from triggering unintended enforcement actions. |

---

## Step-by-Step Implementation Guide

### Step 1: Create `internal/config/config_invariant_test.go`
```go
package config_test

import (
	"os"
	"testing"

	"github.com/seanpor/ja4proxy/internal/config"
	"pgregory.net/rapid"
)

func TestInvariant_Config_DefaultConfigValid(t *testing.T) {
	cfg := config.DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultConfig failed validation: %v", err)
	}
}
```

---

## Acceptance Criteria

- [x] `internal/config/config_invariant_test.go` created and all 4 invariants passing.
- [x] Invariants registered in `docs/testing/invariants.yaml`.
- [x] Package `internal/config` coverage verified $\ge 87.6\%$.
- [x] News fragment created in `docs/fragments/phase-606g-config-invariants.md`.
- [x] `make preflight` passes 100% green.

---

## Out of Scope
- Management REST API endpoints (covered in Phase 606i).
- SIGHUP signal handling in proxy binary (covered in Phase 606b).
