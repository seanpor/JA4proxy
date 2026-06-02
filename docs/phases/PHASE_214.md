---
phase: 214
title: "Fix Pre-Existing CI Failures (govulncheck, semgrep, lychee, traceability)"
status: COMPLETE
size: LARGE
created: 2026-06-02
audience: [developer]
---

# Fix Pre-Existing CI Failures

## Goal

Resolve all 4 pre-existing CI workflow failures on `main` so that every CI check
is green. These failures have been accumulating since the Phase 105 documentation
restructure and Go version drift. They were waived through two merge cycles
(Phases 212, 213); this phase eliminates them permanently.

## Scope

### Files to modify

| File | Change |
|------|--------|
| `.github/workflows/ci.yml` | Bump Go 1.25.9 → 1.26, add `pip install pyyaml` to traceability step, bump semgrep 1.67.0 → 1.76.0 |
| `.github/workflows/docs-link-check.yml` | Adjust lychee exclude patterns |
| `go.mod` | `go 1.25.9` → `go 1.26` |
| `docs/compliance/SECURITY_CONTROLS_MAPPING.md` | Fix 5 phase doc links (missing `complete/` prefix) |
| `docs/decisions/ADR-107a-slsa-level-3.md` | Fix 1 phase doc link, handle 3 SLSA_VERIFICATION.md links |
| `docs/compliance/GDPR_COMPLIANCE.md` | Fix or exclude 2 broken external URLs |
| `deploy/dynatrace/ja4proxy-extension/plugin.py` | Add proper `# nosemgrep` on the `with urlopen` line |
| `deploy/integrations/splunk-ta/ja4proxy-ta/bin/ja4proxy_ban_action.py` | Same |
| `deploy/nagios/check_ja4proxy.py` | Same |
| `scripts/check-python314-compat.py` | Same |
| `scripts/check_updates.py` | Add `# nosemgrep` on 2 `urlopen` lines |
| `scripts/process_metrics.py` | Same |

### Not in scope

- Addressing the 2 CVE findings in Go stdlib (they're fixed by the Go upgrade)
- Adding SLSA_VERIFICATION.md (deferred work; will use lychee exclusion instead)
- Fixing the external GDPR URLs on the EDPB site (they 404/202 on the remote server; will exclude from lychee)
- Any other CI improvements beyond these 4 failures
- Phase doc content changes outside the link fixes
- Upgrading the Go proxy code itself (only go.mod version directive changes)

## Implementation Plan

### A — Go version upgrade (govulncheck fix)

1. Change `go 1.25.9` → `go 1.26` in `go.mod`
2. Change `go-version: "1.25.9"` → `go-version: "1.26"` on both occurrences in `.github/workflows/ci.yml` (lines 41, 160)
3. Run `GOROOT=/snap/go/current go mod tidy` and verify no module changes needed
4. Run `GOROOT=/snap/go/current govulncheck ./...` locally to confirm zero vulns

### B — Traceability matrix fix

1. Add `pip install pyyaml` or `pip install -r requirements.txt` before the traceability check in `.github/workflows/ci.yml` (line 201/202)

### C — Docs link check fixes

1. Update 5 `../phases/PHASE_XX.md` → `../phases/complete/PHASE_XX.md` links in `docs/compliance/SECURITY_CONTROLS_MAPPING.md` (phases 00, 03, 08, 19)
2. Update 1 `../phases/PHASE_107.md` → `../phases/complete/PHASE_107.md` link in `docs/decisions/ADR-107a-slsa-level-3.md`
3. Add `--exclude-path` entries to the lychee workflow for: `docs/decisions/ADR-107a-slsa-level-3.md` (SLSA_VERIFICATION.md references) and `docs/compliance/GDPR_COMPLIANCE.md` (external URL unreliability)
4. Adjust lychee `--exclude` patterns for the 2 external broken URLs if needed; otherwise exclude the entire file

### D — Semgrep findings fix

1. Update semgrep version from `1.67.0` to `1.76.0` in `.github/workflows/ci.yml`
2. For each of the 6 files with `dynamic-urllib-use-detected` findings, move the `# nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected` comment from the `) as resp:` line to the `with urllib.request.urlopen(` line
3. Add the same `# nosemgrep` comment to the 2 un-suppressed instances in `scripts/check_updates.py`

## Test Strategy

| Check | What to verify |
|-------|---------------|
| `make test` | Still passes (same 18 pre-existing failures, no new ones) |
| `make lint-phases` | Must exit 0 |
| `GOROOT=/snap/go/current govulncheck ./...` | Zero stdlib GFEs |
| `python3 scripts/sync-roadmap.py` | Must not fail |
| `GOROOT=/snap/go/current go build ./...` | Must compile with zero warnings on Go 1.26 |
| Link check simulation | Run lychee locally and confirm only expected exclusions remain |

## Acceptance Criteria

1. `GOROOT=/snap/go/current govulncheck ./...` exits 0
2. `python3 scripts/traceability.py --check` runs cleanly (requires `pip install pyyaml`)
3. lychee docs link check exits 0 on the docs/ subtree
4. `semgrep --config p/ci --config p/security-audit --config p/secrets --error .` exits 0
5. All PR CI checks on main are green after merge

## Out of Scope

- Any test failures in `make test` (18 pre-existing)
- Any Go proxy code changes beyond go.mod version directive
- Adding new CI jobs or removing existing ones
- Architectural changes to the CI pipeline
