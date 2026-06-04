# Phase 147: Automated Quality Guardrails & Meta-Validation

> **Status:** PROPOSED
> **Size:** MEDIUM
> **Depends on:** Phase 146
> **Owner:** Gemini CLI

## Goal
Implement automated mechanisms to ensure the project's "entry points" (Makefile, high-level scripts, CI) are syntactically correct, logically consistent, and perform exactly what they claim to do.

## Context
Recent stabilization efforts revealed that core commands (e.g., `make lint`) could be broken by automated edits without triggering immediate alarms. This phase addresses that "Meta-Quality" gap.

## Scope

### 1. Makefile Verification (Meta-Linter)
- **Recursive Variable Check**: Add a test that performs a `make --dry-run` or `make --print-data-base` to catch circular dependencies or recursive variable definitions (like the recent $(PYTHON) loop).
- **Phony Check**: Ensure every target that doesn't produce a file is marked as `.PHONY`.
- **Dependency Linting**: Use `checkmake` or a custom script to verify the Makefile structure.

### 2. The "Make Doctor" (Environment Guardrails)
- **Runtime Validation**: Implement a `make doctor` target that verifies:
  - Correct versions of Go (1.26+) and Python (3.14+).
  - Presence of required binaries (docker, hadolint, trivy, etc.).
  - Environment variable consistency (.env file vs expected keys).
- **Pre-flight Gate**: Link `make build` and `make test` to a lightweight version of `make doctor`.

### 3. CI Alignment
- **"Eat Your Own Dogfood"**: Update `.github/workflows/ci.yml` to use the high-level `make lint`, `make scan`, and `make test` targets instead of duplicating logic in YAML. 
- **Benefit**: If a `make` target is broken, the CI fails immediately, preventing the merge of broken ergonomics.

### 4. Doc-to-Command Synchronization
- **Verification**: Add a script that parses code blocks in `README.md` and `docs/OPERATIONS_GUIDE.md` to ensure that the commands listed there actually exist in the Makefile.

## Acceptance Criteria
- [ ] `make doctor` reports 100% health for a correctly set up environment.
- [ ] CI uses `make lint scan test` and passes.
- [ ] No recursive Makefile variables or broken phony targets exist.
- [ ] Automated gate prevents committing "Dirty" error messages in core scripts.

---

## Strategic Intent
This phase ensures that the "Bodywork" of the project is as robust as the "Engine." By automating the hygiene of our automation, we eliminate the possibility of a developer or agent accidentally breaking the fundamental interface of the repository.
