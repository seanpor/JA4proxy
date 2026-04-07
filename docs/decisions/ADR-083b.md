# ADR-083b: Go Policy Validator Implementation

**Status:** Accepted
**Date:** 2026-04-07
**Phase:** 83 (`ja4proxy-cli` Go Binary)

---

## Context

`ja4proxy-cli policy validate --file ja4proxy-policy.yaml` must work fully offline —
no API access and no Python runtime required. This is an explicit requirement for
air-gapped enterprise deployments where the CLI is used to pre-validate policies
before they are transferred to a connected system for application.

Phase 82 implemented the authoritative policy validator in Python using the cerberus
validation library (`src/governance/policy_validator.py`). The Python validator
enforces 7 distinct rules and is invoked by the Python stopgap script
(`scripts/ja4proxy-policy.py`).

The Go CLI needs its own policy validator. Three options were evaluated.

---

## Options

### Option A: Re-implement validation rules natively in Go

Implement the same 7 rules in Go using only standard library and already-present
dependencies:

- `go.yaml.in/yaml/v3` for YAML parsing (already in `go.mod`)
- `net/netip` stdlib for CIDR prefix validation
- `regexp` stdlib for JA4 fingerprint pattern matching
- `time` stdlib for TTL/expiry date validation

Estimated implementation: ~200 lines in `internal/cli/commands/policy.go`.

The validator is fully offline and has no runtime dependencies beyond the Go binary.
Error types returned: `PolicySyntaxError`, `PolicySchemaError`, `PolicyTTLError`,
`PolicyValidationError`, `PolicyDuplicateError`.

**Complexity:** Low. The 7 rules are straightforward to express in Go.
**Runtime dependencies:** None.
**Air-gapped compatible:** Yes.

### Option B: Add `POST /api/v1/config/validate` to Phase 79 and call the API

Add a new validation endpoint to the Phase 79 Management API. The CLI sends the
policy file content to the API, which validates it server-side (using the Python
cerberus validator) and returns a pass/fail response.

**Complexity:** Medium. Requires a Phase 79 change plus the CLI client code.
**Runtime dependencies:** Network access to the Management API.
**Air-gapped compatible:** No. Breaks the explicit air-gapped use case.

### Option C: Shell out to Python

The CLI invokes the Python interpreter at runtime to execute the validation rules in
`src/governance/policy_validator.py`.

**Complexity:** Low to implement, but the approach is not viable for a standalone
binary. It requires a Python runtime (with the correct version and dependencies) to be
installed on the operator's machine.
**Runtime dependencies:** Python 3.x + cerberus + PyYAML on the operator's machine.
**Air-gapped compatible:** Only if Python and all dependencies are available offline.

---

## Decision

**Option A (native Go re-implementation).**

The 7 validation rules are simple enough to implement in Go with no additional
dependencies. The result is a single binary that validates policies offline on any
platform without requiring a Python runtime or network access.

Option B breaks the air-gapped use case explicitly stated in Phase 83 requirements.
Option C introduces a runtime dependency that cannot be guaranteed on the target
machines for a standalone binary CLI.

---

## Validation Rules

The Go validator implements the following 8 rules, which must match the Python
cerberus implementation exactly for exit code parity:

| # | Rule | Error type |
|---|------|-----------|
| 1 | YAML must parse without error | `PolicySyntaxError` |
| 2 | No unknown top-level keys (allowed: `meta`, `dial`, `allowlist`, `blocklist`, `watchlist`, `bypass_toggles`) | `PolicySchemaError` |
| 3 | `dial.setting` must be in range 0–100 | `PolicySchemaError` |
| 4 | `expires` fields must be future dates (ISO 8601) | `PolicyTTLError` |
| 5 | Dial increase > 20 without `shadow_mode_approved: true` → validation failure | `PolicyValidationError` |
| 6 | CIDR notation must be valid (`net/netip.ParsePrefix`) | `PolicySchemaError` |
| 7 | JA4 fingerprints must match `[a-z0-9]{10}_[a-f0-9]{12}_[a-f0-9]{12}` | `PolicySchemaError` |
| 8 | No duplicate JA4 fingerprints within the same list | `PolicyDuplicateError` |

Note: rule 5 requires a `--current-dial N` flag so the CLI knows the current live
dial value to compare against the proposed setting.

## Exit Code Contract

The exit code contract is what parity tests verify. Error message text may differ
between the Python and Go implementations (cerberus produces different message formats
from hand-written Go error strings).

| Outcome | Exit code |
|---------|-----------|
| Policy is valid | 0 |
| Any validation error | 1 |

This contract matches the Python script behaviour for all 8 known-input parity test
cases in `tests/integration/test_cli_parity.py`.

---

## Consequences

- The Go policy validator lives in `internal/cli/commands/policy.go` alongside the
  other command implementations.
- The Python validator in `src/governance/policy_validator.py` remains unchanged. It
  is authoritative for the Python script path. The Go validator is authoritative for
  the CLI binary path.
- If the two validators diverge (for example, a new rule is added to the Python
  validator), the parity tests in `tests/integration/test_cli_parity.py` will catch
  the divergence. When divergence is detected, the Go validator must be updated to
  match.
- The `--current-dial N` flag is required for rule 5. When not provided and the policy
  increases the dial by more than 20, the validator emits a warning rather than a hard
  failure (it cannot know the current live dial without the flag).
- `scripts/ja4proxy-policy.py` is marked deprecated once the Go CLI passes all 8
  parity test cases.
