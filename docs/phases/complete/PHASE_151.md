# Phase 151: End-to-End Binary Validation & System Testing

> **Status:** PROPOSED
> **Size:** MEDIUM
> **Depends on:** Phase 150
> **Owner:** Gemini CLI

## Goal
Verify the functional correctness and logical parity of the new two-binary architecture (`bin/ja4pd` and `bin/ja4p`) through comprehensive system and integration testing.

## Scope

### 1. Test Refactoring
- **Legacy Updates**: Globally update all integration, chaos, and performance tests to use the new binary names:
    - `bin/ja4proxy` -> `bin/ja4pd`
    - `ja4proxy-cli` -> `ja4p management`
- **Environment Mapping**: Ensure test harnesses correctly point to the standardized `bin/` directory.

### 2. CLI Validation Suite (`ja4p`)
Implement new automated tests for every `ja4p` subcommand:
- **`init` Validation**: Verify that the wizard correctly generates `.env` files for POC, Dev, Performance, and Production scenarios.
- **`validate` Validation**: Pass valid and malformed configurations to ensure the validator correctly identifies errors (invalid ports, missing feeds).
- **`test ip` Parity**: Verify that the offline simulator produces identical scores and signals to the live `ja4pd` engine for a given set of test IPs.

### 3. "Clean Slate" System Test
Implement a high-level end-to-end test that:
1.  Clears the current environment.
2.  Uses `bin/ja4p init` (POC mode) to bootstrap.
3.  Starts the stack via `make start-poc`.
4.  Sends real TLS traffic through the proxy.
5.  Verifies the decision logic via Prometheus metrics and Redis state.

## Acceptance Criteria
- [ ] 100% of existing integration tests pass using the new binary names.
- [ ] New test suite for `bin/ja4p` achieves >80% coverage of the CLI logic.
- [ ] "Clean Slate" test proves the system is deployable from zero in a single automated flow.
- [ ] Documented "Validation Matrix" proving parity between the simulator and the engine.

---

## Strategic Intent
This phase ensures that our architectural split didn't just "look good" but actually works correctly in the real world. It guarantees that the operational tools (the CLI) are as reliable as the security engine (the proxy), providing a high-trust experience for Cyber Ops teams.
