# Phase 150: Unified Go Operational CLI

> **Status:** PROPOSED
> **Size:** MEDIUM
> **Depends on:** Phase 149
> **Owner:** Gemini CLI

## Goal
Consolidate all "human-facing" operational tools into a single, professional Go CLI (`bin/ja4p`) and strip non-core logic from the proxy daemon to ensure architectural purity.

## Scope

### 1. The Unified `ja4p` Binary
- Merge the Wizard from Phase 149 into a single CLI tool (`cmd/ja4p`).
- Move the following from `cmd/proxy/main.go` to `cmd/ja4p/main.go`:
    - `config validate`: Configuration verification.
    - `test ip`: Offline decision simulation.
    - `version`: Interactive version reporting.
- Provide a polished help interface using **Cobra**.

### 2. Core Proxy Stripping
- Refactor `cmd/proxy/main.go` to be a pure daemon.
- Remove all subcommand logic and interactive prompts.
- Ensure it only does one thing: Process traffic at high speed.

### 3. Makefile & Documentation Alignment
- Update all targets to use `bin/ja4p` for operational tasks.
- Update `README.md` and `OPERATIONS_GUIDE.md` to reflect the new command structure.

## Acceptance Criteria
- [ ] Core proxy binary (`bin/proxy`) is significantly smaller and contains zero interactive logic.
- [ ] Unified CLI (`bin/ja4p`) handles all setup, validation, and simulation tasks.
- [ ] `make help` correctly points to the new unified tool.
- [ ] Logic parity verified between the simulation tool and the live proxy.

---

## Strategic Intent
This phase completes the separation of concerns between the "Engine" (Performance-Critical) and the "Tools" (User-Friendly). It results in a cleaner codebase and a much more intuitive experience for security operators.
