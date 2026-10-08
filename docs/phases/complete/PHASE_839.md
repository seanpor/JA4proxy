# CI Preflight Parity and Git-State Verification

## Goal
Eliminate false-green local preflight passes where GitHub CI subsequently fails. Close the systemic escape vectors between local developer/agent preflight testing and remote GitHub Actions CI pipelines: Semgrep SAST ruleset drift, git-index vs. disk-state divergence ("zombie" tracked files), and unstaged workspace drift.

## Scope
1. **Semgrep SAST Ruleset Parity**: Align `Makefile` (`lint-semgrep`) with `.github/workflows/ci.yml:266`. Run official registry rulesets (`--config p/ci --config p/security-audit --config p/secrets`) alongside project-specific rules (`.semgrep-phase122.yml`).
2. **Git-Index State Verification in Phase Filing Tests**: Update `tests/unit/test_phase_doc_filing.py` to inspect both filesystem files *and* `git ls-files` tracked files. If an archived phase doc is moved or deleted locally via `mv` but remains tracked in the git index, the test must fail locally before reaching CI.
3. **Working Tree Cleanliness Enforcement in Preflight**: Ensure `make preflight` checks for un-staged modifications, ensuring what is tested locally is exactly what is committed to git.
4. **Phase Archival Script Safety**: Update `scripts/close-phase.sh` to mandate `git mv` and verify git tracking cleanliness during phase transitions.

## Implementation Plan
1. **Makefile Alignment**:
   - Update `lint-semgrep` in `Makefile` to include `--config p/ci --config p/security-audit --config p/secrets`.
2. **Enhanced Phase Filing Tests**:
   - Update `tests/unit/test_phase_doc_filing.py` `_docs_in()` to query `git ls-files docs/phases/PHASE_*.md` when executing inside a git repository, merging with `folder.glob()`.
   - Add unit test asserting that git-tracked zombie phase documents fail `test_archived_phases_are_not_left_in_the_root`.
3. **Preflight Tree Integrity Check**:
   - Add a lightweight pre-check in `make preflight` or `scripts/check_git_clean.py` warning or failing if untracked files or unstaged deletions exist.
4. **Phase Close-Out Safety**:
   - Ensure `scripts/close-phase.sh` uses `git mv` rather than filesystem `mv` when moving phase plans to `complete/`.

## Test Strategy
- Run `make lint-semgrep` locally using official container to verify it executes `p/ci`, `p/security-audit`, and `p/secrets`.
- Test `tests/unit/test_phase_doc_filing.py` against simulated git-tracked root phase documents.
- Run `make preflight` and verify 100% pass across all gates.

## Acceptance Criteria
- `make lint-semgrep` ruleset matches `.github/workflows/ci.yml`.
- `test_phase_doc_filing.py` catches git-tracked phase docs in root even if removed from the local working directory.
- `make lint-phases` and `make sync` exit 0.
- All unit tests pass cleanly in container.

## Out of Scope
- Modifying GitHub Actions runner hardware or orchestration configurations.
- Altering existing approved Trivy / pip-audit exceptions.
