# Phase 104 — Code Health & Coverage Gap Closure

> **Status:** PROPOSED
> **Size:** LARGE (15 sub-tasks, all XS/S, all parallel)
> **Dependencies:** None (standalone)
> **Triggered by:** Code health audit 2026-04-16
> **Review:** `docs/phases/complete/PHASE_104_review.md`

## Goal

Close all quality gaps across Python and Go: fix `make lint-all`, bring all
Python files to ≥80% coverage, raise Go coverage from 52% to ≥65%, fix the
stale README badge, and add a single `make quality` target that runs everything.

---

## Current State (2026-04-16, post quick-wins)

| Metric | Python | Go |
|--------|--------|----|
| Coverage | 92.76% (14 files <80%) | 52.3% (11 pkgs <80%) |
| Lint | mypy clean | go vet + golangci-lint clean |
| `make lint-all` | FAIL (semgrep invocation) | — |
| README badge | Claims ≥99% (stale from Phase 46) | — |

---

## Sub-phases (15 tasks, all XS or S, all independent)

### Scaffolding & DevOps

| ID | Description | Size |
|----|-------------|------|
| 104.1 | Fix `lint-semgrep` + add `make quality` target | XS |
| 104.2 | Fix README coverage badge | XS |

### Python — Tier 1 Critical (<50%)

| ID | File(s) | Current | Size |
|----|---------|---------|------|
| 104.3a | `src/cli/main.py` | 0% | XS |
| 104.3b | `src/management/redis_client.py` | 30% | XS |
| 104.3c | `src/analytics/main.py` | 36% | S |

### Python — TI Feeds Cluster (40–79%, 9 files)

| ID | Scope | Size |
|----|-------|------|
| 104.4a | runner.py — config reload + client lifecycle | S |
| 104.4b | runner.py — poll loop + safety caps + cleanup | S |
| 104.4c | runner.py trigger stream + seed_file.py | S |
| 104.4d | rest_generic.py + crowdstrike.py | S |
| 104.4e | state.py + contribution + ja4_safety + taxii + mgmt_client | S |

### Python — Security

| ID | File(s) | Current | Size |
|----|---------|---------|------|
| 104.5 | seccomp_transition.py (56%) + validation.py (79%) | S | S |

### Go — Production Packages

| ID | Package(s) | Current | Size |
|----|------------|---------|------|
| 104.6a | `internal/redis` | 48.9% | S |
| 104.6b | `internal/security` | 72.8% | S |
| 104.6c | `internal/metrics` + `internal/cli/*` | 42–77% | S |

### Go — CLI Entrypoints

| ID | Package(s) | Current | Size |
|----|------------|---------|------|
| 104.7a | `cmd/ja4check` + `cmd/ja4proxy-cli` | 0% | XS |
| 104.7b | `cmd/proxy` + `cmd/syncagent` | 4.7–25.9% | S |

---

## Acceptance Criteria

- [ ] `make lint-all` passes with 0 errors
- [ ] `make quality` target exists and runs lint-all + coverage checks
- [ ] `make test` passes with 0 warnings
- [ ] All 14 Python files reach ≥80% line coverage
- [ ] Python total coverage ≥95%
- [ ] Go `internal/redis`, `internal/security`, `internal/metrics` reach ≥70%
- [ ] Go total coverage ≥65%
- [ ] All Go `cmd/` packages have test files
- [ ] README badge matches measured reality
