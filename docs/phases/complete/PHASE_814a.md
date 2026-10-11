# Charter, RoE, Test Range, and Verification Harness

## Goal
Establish the foundational infrastructure and validation gates for the JA4proxy penetration-testing programme: author the cycle's Rules of Engagement (RoE), build a self-asserting isolated test range with verified-zero egress, implement a two-state regression verification harness (`verify_revert.sh`) and finding specification linter (`check_finding_spec.py`), and wire referential integrity checks into continuous integration.

## Scope
### In Scope
1. **Charter & Rules of Engagement:**
   - Formalize operational boundaries, targeting restrictions, de-escalation ladders (L0–L4), and stop conditions in `docs/security/pentest/RULES_OF_ENGAGEMENT.md`.
2. **Pentest Target Range:**
   - Multi-container stack (`deploy/docker/docker-compose.pentest.yml`) layered on `docker-compose.poc.yml`.
   - Verified zero-egress internal networks (`ja4range-*`) with automated IP/DNS egress probing.
   - Pinned attacker container (`deploy/docker/Dockerfile.attacker`) with pre-installed diagnostic and pentest tooling.
   - Bring-up automation (`scripts/start-pentest-range.sh`) with 8 runtime sanity assertions and provenance reporting.
3. **Verification Harness & Finding Quality Floor:**
   - Finding specification completeness validator (`scripts/check_finding_spec.py`) enforcing the 12-section fix-spec template from `PROGRAMME.md` §9.
   - Two-state verification script (`scripts/verify_revert.sh`) testing that regression tests fail before fixes and pass on current code.
   - `Makefile` targets: `verify-finding`, `verify-findings-all`, `pentest-range`, `pentest-range-down`, `pentest-shell`.
4. **Referential Integrity & CI Gating:**
   - Provenance schema extension (`found_against`) in `docs/security/findings.yaml`.
   - Wiring `make verify-findings` into CI's meta-validation gate.
5. **Comprehensive Testing:**
   - Unit tests for configuration, range isolation, provenance parsing, spec validation, and an end-to-end test suite for `verify_revert.sh`.

### Out of Scope
- Execution of retrospective sweeps across historical findings (owned by Phase 814c).
- Attack surface enumeration and inventory generation (owned by Phase 814b).
- Active vulnerability hunting or exploit development (owned by Stage 1, Phases 814d–814o).

## Implementation Plan

### Step 1: Pre-Delivered Deliverables Verification (PR #397)
Confirm integrity and test status of assets landed in PR #397:
- `docs/security/pentest/RULES_OF_ENGAGEMENT.md`
- `deploy/docker/docker-compose.pentest.yml` & `Dockerfile.attacker`
- `scripts/start-pentest-range.sh`
- `scripts/check_finding_spec.py` and `tests/unit/test_check_finding_spec.py`
- `tests/unit/test_pentest_range_config.py` and `tests/unit/test_findings_provenance.py`

### Step 2: Makefile Integration
Wire the missing targets into `Makefile` per `PROGRAMME.md` §10.3 and `PHASE_814.md`:
- `verify-finding`: runs `scripts/verify_revert.sh "$$FINDING"`.
- `verify-findings-all`: runs verification over all findings carrying a `regression_test`.

### Step 3: Harness Hardening & End-to-End Test Suite
1. Ensure `scripts/verify_revert.sh`:
   - Passes `PYTHONPATH=/src` to containerized pytest.
   - Distinguishes between test assertion failures (exit 1) and crashes/import errors (exit 2, 3, 4).
   - Isolates Go tests using `-run "^<TestName>$"` and pins snap Go toolchain.
2. Implement `tests/unit/test_verify_revert_e2e.py`:
   - Sets up a self-contained temporary git repository fixture.
   - Asserts success when a test fails pre-fix and passes post-fix (true regression).
   - Asserts failure when a test passes pre-fix (detecting decorative tests).
   - Asserts failure when pre-fix code fails to compile or imports crash (rejecting environment false positives).
   - Asserts automatic cleanup of throwaway git worktrees.

### Step 4: Documentation & Close-Out
- Update `docs/phases/PHASE_814a_notes.md` with final verification results.
- Update `docs/phases/manifest.yaml` to mark Phase 814a `COMPLETE`.
- Run full preflight verification (`make preflight`) and execute phase close-out checklist.

## Test Strategy
- **Unit Tests:**
  - `tests/unit/test_pentest_range_config.py`: validates compose overrides, internal network flags, production posture defaults.
  - `tests/unit/test_findings_provenance.py`: validates `found_against` field schema and date-gating cutoff.
  - `tests/unit/test_check_finding_spec.py`: validates 13 test cases covering finding specification completeness.
  - `tests/unit/test_verify_revert_e2e.py`: validates the two-state revert verification script against temporary git fixtures.
- **Range Verification:**
  - Run `scripts/start-pentest-range.sh --verify-only` to validate runtime network isolation, zero egress, and container reachability.

## Acceptance Criteria
- [ ] `make pentest-range` initializes the target stack and asserts zero external egress.
- [ ] `make verify-finding FINDING=<ID>` is available in `Makefile` and executes `scripts/verify_revert.sh`.
- [ ] `make verify-findings` runs in CI Meta-Validation and passes.
- [ ] `scripts/check_finding_spec.py` passes with zero exemptions.
- [ ] `scripts/verify_revert.sh` rejects compilation/import crashes and requires true assertion failures.
- [ ] End-to-end test suite `tests/unit/test_verify_revert_e2e.py` passes 100% green.
- [ ] `make preflight` exits 0 with zero warnings and zero errors.
