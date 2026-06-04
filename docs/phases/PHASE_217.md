---
phase: 217
title: "Fix Pre-Existing CI Pipeline Failures — Python, Lint, Build"
status: PROPOSED
size: SMALL
created: 2026-06-03
audience: [developer, devops]
---

# Fix Pre-Existing CI Pipeline Failures — Python, Lint, Build

## Goal

Resolve the five blocking CI/build failures on `main` so that every future PR
can merge green and `make build` succeeds again. All are mechanical — not
architectural — but have been blocking the pipeline since before Phase 215.

## Scope

### Files to modify

| File | Change |
|------|--------|
| `requirements.txt` | Lower `urllib3>=2.7.2` to `urllib3>=2.7.0` — 2.7.2 was never released on PyPI; latest is 2.7.0 which covers all four listed CVEs |
| `cmd/proxy/fuzz_test.go` | Fix import ordering with `gofmt -w` |
| `docs/compliance/SECURITY_CONTROLS_MAPPING.md` | Fix broken link `docs/operator/` → `docs/runbooks/` (lychee error) |
| `Makefile` | Update trivy `0.70.0` → `0.71.0` (latest, released 2026-06-01) |
| `requirements.txt` | Also lower `pytest>=9.0.4` to `pytest>=9.0.3` — 9.0.4 was never released; CVE-2025-71176 is fixed in 9.0.3 |

### No change needed

- **Traceability matrix check** — passes locally (`python3 scripts/traceability.py --check` exits 0).
- **Python tests / pip-audit** — blocked only by the urllib3 dependency; fix the dependency and both pass.
- **Go tests / Go dep audit** — already green.
- **`make build`** — blocked only by urllib3 in the Docker admin-api build stage; auto-fixed.

## Implementation Plan

### A — Fix urllib3 version pin

1. Change `urllib3>=2.7.2` to `urllib3>=2.7.0` in `requirements.txt`.
2. CVE fix versions confirmed:
   - CVE-2025-50181 → fixed in 2.5.0
   - CVE-2025-66418 → fixed in 2.6.0
   - CVE-2025-66471 → fixed in 2.6.0
   - CVE-2026-21441 → fixed in 2.6.3

### B — Fix gofmt in fuzz_test.go

1. Run `GOROOT=/snap/go/current gofmt -w cmd/proxy/fuzz_test.go`.

### C — Fix lychee broken link

1. `docs/compliance/SECURITY_CONTROLS_MAPPING.md:140` links to `../operator/`
   which does not exist. Redirect to `../runbooks/` which holds operational docs.

### D — Update trivy

1. Bump `aquasec/trivy:0.70.0` → `aquasec/trivy:0.71.0` in all 3 Makefile targets.

## Test Strategy

| Check | What to verify |
|-------|---------------|
| `pip install -r requirements.txt` | urllib3 resolves to 2.7.0 |
| `gofmt -d cmd/proxy/fuzz_test.go` | No output (file is clean) |
| `make build` | Docker build succeeds |
| `make lint-phases` | 156/156 OK |

## Acceptance Criteria

1. `pip install -r requirements.txt` succeeds.
2. `gofmt -d cmd/proxy/fuzz_test.go` produces no output.
3. `make build` succeeds.
4. CI pipeline on the PR branch shows all checks green (Go tests, lint, semgrep, etc.).
5. After merge, post-merge CI on `main` is also green.

## Out of Scope

- Python proxy runtime fixes (deprecated).
- Adding new features or tests.
- Fixing lint in files not listed above.
- CI beyond what's broken on `main` today.
