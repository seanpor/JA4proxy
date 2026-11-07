# Phase 866: Custom SAST Rules & Dependabot Unpin Sweep

## Goal
1. Implement custom SAST rules tailored specifically to JA4proxy security mandates (`AGENTS.md`) and historical pentest findings.
2. Store custom rules in an isolated directory (`security/sast/custom-rules/`) completely separate from vendored community rules (`security/sast/rules/`), so upstream community rule updates never overwrite them.
3. Consolidate legacy project rules (`.semgrep-phase122.yml`) into `security/sast/custom-rules/` for a clean 2-directory SAST architecture (`rules/` vs `custom-rules/`).
4. Harden codebase locations identified by the new rules that decode or read HTTP response streams without an `io.LimitReader` bounds cap (`internal/config/netbox.go`, `internal/cli/commands/dial.go`, `internal/cli/client/client.go`).
5. Remove legacy Semgrep version ignore pins in `.github/dependabot.yml` (`jsonschema`, `mcp`, `pip-audit`), now that Semgrep is completely excised from the Python environment.

## Scope
- Directory layout: Create `security/sast/custom-rules/` containing `ja4proxy-patterns.yml` and migrated `phase-122-legacy.yml`.
- Makefile update: Update `lint-opengrep` to scan `--config security/sast/rules/ --config security/sast/custom-rules/`.
- Code hardening: Wrap external HTTP responses with `io.LimitReader` in `netbox.go`, `dial.go`, and `client.go`.
- Dependency cleanup: Relax Dependabot ignore rules in `.github/dependabot.yml`.

## Implementation Plan
1. Atomic claim: Branch `phase-866-custom-sast-rules-and-unpin` claimed and pushed.
2. Manifest registration: Register Phase 866 in `docs/phases/manifest.yaml` as `IN_PROGRESS`.
3. Create `security/sast/custom-rules/ja4proxy-patterns.yml` with rules for unbounded HTTP reads, sensitive key file permission checks, unmetered channel drops, and hotpath regex compiles.
4. Move `.semgrep-phase122.yml` to `security/sast/custom-rules/phase-122-legacy.yml`.
5. Update `Makefile` target `lint-opengrep` to scan both `security/sast/rules/` and `security/sast/custom-rules/`.
6. Harden `netbox.go`, `dial.go`, and `client.go` with `io.LimitReader`.
7. Update `.github/dependabot.yml` to remove outdated Semgrep pin ignores.
8. Validate SAST rules against code and fixtures with `make lint-opengrep`.
9. Run full gates: `make lint`, `make scan-regression`, and `make test`.
10. Execute `bash scripts/close-phase.sh` and open PR.

## Test Strategy
- Unit & SAST tests: Verify `make lint-opengrep` executes cleanly across both rule sets.
- Code regression tests: Verify `go test ./...` passes.
- Close-out gate: Full `scripts/close-phase.sh` must exit 0.

## Strict Acceptance Criteria Gates

| Gate ID | Area | Strict Acceptance Criterion | Precise Verification Command | Expected Output / Invariant |
|---|---|---|---|---|
| **GATE-1** | **Isolation & Migration** | Root `.semgrep-phase122.yml` is removed and relocated into `security/sast/custom-rules/phase-122-legacy.yml`. No custom rule exists in `security/sast/rules/`. | `test ! -f .semgrep-phase122.yml && test -f security/sast/custom-rules/phase-122-legacy.yml && test -f security/sast/custom-rules/ja4proxy-patterns.yml` | Exit 0; file assertions pass |
| **GATE-2** | **Rule Ingestion in Makefile** | `Makefile` target `lint-opengrep` ingests both `rules/` and `custom-rules/` with `--disable-version-check` and `--error`. | `grep -E -- '--config security/sast/rules/.*--config security/sast/custom-rules/' Makefile` | Matches exactly, no dangling reference to `.semgrep-phase122.yml` in Makefile |
| **GATE-3** | **Two-State Rule Proof (Positive & Negative)** | Every new rule in `ja4proxy-patterns.yml` is verified by test fixtures asserting both detection of violations (`ruleid`) and acceptance of safe patterns (`ok`). | `docker run --rm -v "$PWD":/src -w /src $(OPENGREP_IMG) scan --config security/sast/custom-rules/ja4proxy-patterns.yml security/sast/custom-rules/tests/` | Rule test runner confirms matches on positive fixtures and zero matches on negative fixtures |
| **GATE-4** | **Revert / Two-State Code Proof** | Intentionally reverting any of the 3 HTTP stream bounds fixes causes `make lint-opengrep` to exit with an error. | Revert `internal/config/netbox.go` `io.LimitReader` and run `make lint-opengrep` | Fails with `ja4p-unbounded-http-body-decode`; restoring exits 0 |
| **GATE-5** | **Zero False-Positive Gate** | `make lint-opengrep` runs across the entire repository (Go runtime, CLI, Python tools, config, shell). | `make lint-opengrep` | Exit code 0, 0 errors, 0 warnings on production codebase |
| **GATE-6** | **Runtime Code Invariant** | `internal/config/netbox.go`, `internal/cli/commands/dial.go`, and `internal/cli/client/client.go` strictly enforce body length limits (`256 KiB` and `2 MiB`). | `go test -v -run TestNetbox ./internal/config/... && go test -v ./internal/cli/...` | Exit code 0; all unit and integration tests pass |
| **GATE-7** | **Dependabot Unpin Hygiene** | `.github/dependabot.yml` has zero references to Semgrep workaround ignores (`pip-audit`, `jsonschema`, `mcp`). | `! grep -E '(pip-audit|jsonschema|mcp)' .github/dependabot.yml` | Exit code 0; all three workaround locks completely eradicated |
| **GATE-8** | **Python Dependency Audit Cleanliness** | Tools container runs `pip-audit` without waivers for `mcp` or `semgrep`. | `docker run --rm -v "$PWD":/src -w /src ja4proxy-tools pip-audit` | Output contains `No known vulnerabilities found`, exit code 0 |
| **GATE-9** | **Roadmap & Manifest Validation** | `manifest.yaml` updated with Phase 866; news fragment authored in `docs/fragments/`. | `make lint-phases && make sync && git status --porcelain` | `make lint-phases` exits 0; no uncommitted drift |
| **GATE-10** | **Preflight & Close-Out Automation** | Full CI simulation and close-out suite pass without exception or waiver. | `make preflight && bash scripts/close-phase.sh` | Both exit 0 with all 10 close-out sub-gates reporting `[OK]` |

## Out of Scope
- Rewriting third-party vendored rules in `security/sast/rules/`.
- Implementing AST slice windowing rules for PROXY protocol headers (governed by behavioral unit tests).
