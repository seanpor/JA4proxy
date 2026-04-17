---
phase: 207
title: "Go Test Coverage Improvement & Repository Hygiene"
status: PROPOSED
size: LARGE
created: 2026-04-16
audience: [developer, operator]
dependencies: []
---

# Phase 207 — Go Test Coverage Improvement & Repository Hygiene

## Problem

The Go proxy is the production runtime (promoted in Phase 15), but four packages
have dangerously low test coverage. Two command packages have **0% coverage**,
meaning any refactor or bug fix could introduce regressions undetected. The
overall Go coverage is dragged down by these gaps, giving a false sense of
security from the well-tested `internal/` packages.

Additionally, several repository hygiene issues accumulated during the Phase 101
cross-phase-gap work that should be addressed: README accuracy, lint tool
configuration, and stale test stubs.

### Current Go Coverage (2026-04-16)

| Package | Coverage | Lines | Status |
|---------|----------|-------|--------|
| `cmd/ja4check` | **0.0%** | 34 | No meaningful tests |
| `cmd/ja4proxy-cli` | **0.0%** | 898 | No meaningful tests |
| `cmd/syncagent` | **28.0%** | 736 | Minimal coverage |
| `cmd/proxy` | **46.6%** | 1,229 | Below threshold |
| `internal/cli/commands` | **67.4%** | 1,420 | Needs improvement |
| `internal/cli/config` | **76.9%** | 101 | Near threshold |
| `internal/cache` | 97.7% | — | Good |
| `internal/cli/auth` | 100.0% | — | Good |
| `internal/cli/client` | 85.2% | — | Good |
| `internal/cli/output` | 91.2% | — | Good |
| `internal/compliance` | 97.9% | — | Good |
| `internal/config` | 91.0% | — | Good |
| `internal/health` | 100.0% | — | Good |
| `internal/logging` | 95.7% | — | Good |
| `internal/metrics` | 84.9% | — | Good |
| `internal/proxy` | 88.4% | — | Good |
| `internal/redis` | 96.1% | — | Good |
| `internal/security` | 89.0% | — | Good |
| `internal/tls` | 84.3% | — | Good |
| `internal/webhook` | 90.7% | — | Good |

**Target: every package ≥ 80% coverage.** Packages already above 80% are not
in scope unless a gap is discovered during testing.

---

## Deliverables

### D1: Go Test Coverage — `cmd/ja4proxy-cli` (0% → 80%+)

The CLI tool (898 lines) has zero test coverage. This is the operator-facing
command-line interface for managing the proxy (allowlists, blocklists, dial,
health checks, policy).

**What to test:**
- Command parsing and flag validation for every subcommand
- Output formatting (JSON, table, plain)
- Error handling for unreachable API server
- Config file loading and precedence (flags > env > file > defaults)
- Authentication token flow (login, token refresh, token file)

**Approach:** The CLI communicates with the management API over HTTP. Tests
should mock the HTTP client (`internal/cli/client`) to avoid needing a live
server. Focus on testing command logic, not HTTP transport.

### D2: Go Test Coverage — `cmd/ja4check` (0% → 80%+)

Small utility (34 lines) for checking JA4 fingerprints. Low effort but must
not have zero coverage.

### D3: Go Test Coverage — `cmd/syncagent` (28% → 80%+)

The sync agent (736 lines) handles cross-instance coordination. Existing tests
cover only basic RPC and security checks.

**What to test:**
- Agent lifecycle (start, stop, graceful shutdown)
- Sync protocol: full sync, incremental sync, conflict resolution
- Redis watch and notification handling
- Error paths: Redis unavailable, peer unreachable, corrupt state
- Configuration validation

### D4: Go Test Coverage — `cmd/proxy` (46.6% → 80%+)

The main proxy entry point (1,229 lines). Has some tests but major paths are
uncovered.

**What to test:**
- Server startup and shutdown lifecycle
- Configuration loading and validation
- TLS ClientHello parsing edge cases not covered by `internal/tls`
- Connection handling: accept, forward, tarpit, block, ban paths
- Health endpoint responses (shallow and deep)
- Metrics endpoint exposure
- PROXY protocol v1/v2 parsing (if implemented)
- Graceful shutdown with in-flight connections

### D5: Go Test Coverage — `internal/cli/commands` (67.4% → 80%+)

CLI command implementations (1,420 lines). The `policy` subcommand (705 lines)
is the largest and likely least-covered.

**What to test:**
- Policy command: list, get, set, validate operations
- Edge cases in each command's argument parsing
- Error formatting and exit codes

### D6: Go Test Coverage — `internal/cli/config` (76.9% → 80%+)

Small package (101 lines), nearly at threshold. Likely needs 1-2 additional
tests for edge cases.

### D7: README Accuracy

The current README has several inaccuracies:
- **Badges:** Python version badge says 3.14+ (should be 3.10+), Go version
  outdated, coverage badge shows ≥99% (actual Python coverage is ~93%)
- **Go proxy section:** Claims feature parity that doesn't exist — signal
  modules, /metrics endpoint, and PROXY protocol are not yet ported
- **Codebase statistics:** Line counts and test counts are stale
- **Enterprise phases (79-86):** Described in future tense but are complete

**Note:** Phase 101 branch has a comprehensive README rewrite. If PR #34 merges
first, this deliverable reduces to verifying accuracy. If not, the rewrite
should be done here.

### D8: Lint Fixes

- **mypy:** `src/analytics/ti_feeds/safe_resolver.py` has a variable shadowing
  error (IPv4Network/IPv6Network loop variable reuse). Fix: rename loop
  variables to `v4net`/`v6net`.
- **semgrep:** Makefile invokes `python3 -m semgrep scan` which is deprecated
  since semgrep 1.38.0. Fix: change to `semgrep scan`.
- **semgrep false positives:** 29 findings from `logger-credential-leak` rule
  in `management/api/routes/` — all false positives on structured log fields.
  Evaluate whether to add `# nosemgrep` annotations or a rule exclusion.

**Note:** Phase 101 branch already fixes the mypy and semgrep invocation
issues. If PR #34 merges first, only the false-positive triage remains.

### D9: Stale Test Stub Cleanup

`tests/unit/test_phase_101c_safety_caps.py` contains 11 tests that call
`pytest.skip("placeholder")`. These are TDD stubs from Phase 101 that were
never implemented because the safety-cap feature was descoped. Either:
- Remove the stubs entirely (if the feature is permanently descoped), or
- Convert them to proper tests if the feature will be implemented in a
  future phase.

---

## Acceptance Criteria

### Coverage Gates
- [ ] `cmd/ja4check` coverage ≥ 80%
- [ ] `cmd/ja4proxy-cli` coverage ≥ 80%
- [ ] `cmd/syncagent` coverage ≥ 80%
- [ ] `cmd/proxy` coverage ≥ 80%
- [ ] `internal/cli/commands` coverage ≥ 80%
- [ ] `internal/cli/config` coverage ≥ 80%
- [ ] All 20 Go packages pass: `go test ./...` exits 0
- [ ] No existing Go tests broken or weakened

### Hygiene Gates
- [ ] README badges reflect actual versions and coverage
- [ ] README Go proxy section accurately describes ported vs not-ported features
- [ ] `make lint-all` exits 0 (mypy, ruff, semgrep clean)
- [ ] Stale pytest.skip stubs resolved (removed or implemented)

### Standard Gates
- [ ] `make test` passes (all Python tests green)
- [ ] `go test ./...` passes (all Go tests green)
- [ ] `ruff check .` clean
- [ ] CHANGELOG.md updated
- [ ] manifest.yaml updated

---

## Risks & Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| `cmd/proxy/main.go` has tightly coupled startup logic that's hard to test in isolation | HIGH | Extract testable functions; use build tags or test helpers to inject mock listeners/Redis |
| `cmd/ja4proxy-cli` tests may need a mock HTTP server | MEDIUM | Use `httptest.NewServer` with canned responses; keep tests fast |
| `cmd/syncagent` sync protocol may have undocumented edge cases | MEDIUM | Read existing agent.go carefully; test observed behavior, not assumed behavior |
| Phase 101 PR #34 may conflict with D7/D8 if both land | LOW | Check PR status before starting D7/D8; rebase if needed |

---

## Estimated Effort

| Deliverable | Estimate | Priority |
|-------------|----------|----------|
| D1: `cmd/ja4proxy-cli` | 4-6h | HIGH |
| D2: `cmd/ja4check` | 30min | HIGH |
| D3: `cmd/syncagent` | 3-4h | HIGH |
| D4: `cmd/proxy` | 4-6h | HIGH |
| D5: `internal/cli/commands` | 2-3h | MEDIUM |
| D6: `internal/cli/config` | 30min | MEDIUM |
| D7: README | 1h | MEDIUM |
| D8: Lint fixes | 1h | MEDIUM |
| D9: Stale stubs | 30min | LOW |

**Total: ~17-22 hours of implementation work.**

---

## Out of Scope

- Increasing coverage of packages already above 80%
- Go signal module implementation (that's Phase 15 continuation work)
- Python test coverage improvements
- New features or behavioral changes to the Go proxy
