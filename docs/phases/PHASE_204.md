# README Badges — Phase 204

## Goal

Add a comprehensive badge section to the top of README.md to provide at-a-glance project status information for developers, users, and enterprise evaluators.

## Scope

**Files to create/modify:**
- `README.md` — add badge section below H1, before tagline
- `docs/phases/manifest.yaml` — add Phase 204 entry

**Badges to add (all using shields.io / standard badge providers):**

| Category | Badge | Rationale |
|----------|-------|-----------|
| License | MIT License | Standard open source transparency |
| Python | Python 3.14+ | Python proxy minimum version |
| Go | Go 1.25.9 | Production proxy version |
| CI | CI Status (GitHub Actions) | Build health visibility |
| Tests | Test Coverage (≥80%) | Quality gate visibility |
| Go Tests | Go Tests Passing | Dual-language test coverage |
| Docker | Docker Compose Ready | Deployment readiness |
| Release | CLI Release (GitHub) | If/when CLI gets semver tags |
| Security | Semgrep Score | SAST scan status |
| Security | TruffleHog Secrets | Secret scanning status |
| Dependencies | Deps Audited (pip-audit + govulncheck) | Supply chain health |
| Code Quality | Ruff Linting | Python code quality |
| Code Quality | Go Linting (gofmt + vet) | Go code quality |
| Architecture | Dual Proxy (Python + Go) | Unique project feature |
| Parity | Python/Go Parity | Signal score parity guarantee |

## Implementation plan

1. Create phase document at `docs/phases/PHASE_204.md`
2. Add Phase 204 entry to `docs/phases/manifest.yaml` under the "Operational Excellence & Lifecycle Management" epic
3. Run `python3 scripts/sync-roadmap.py` to regenerate TODO.md and PROJECT_STATUS.md
4. Add badge markdown to README.md below the `# JA4proxy` heading, before the tagline paragraph
5. Use static badges from shields.io for project metadata (Python, Go, License)
6. Use GitHub Actions workflow status badges for dynamic ones (CI, tests, linting)
7. Verify all badge URLs are correct and render properly
8. Commit changes

**Badge URL format:**
```markdown
[![Badge Label](https://img.shields.io/badge/color?style=for-the-badge&logo=logo)](link)
```

**Dynamic badges will use GitHub workflow status:**
```markdown
![CI](https://github.com/anomalyco/ja4proxy/actions/workflows/ci.yml/badge.svg)
```

## Test strategy

- Manual: Open README.md in a markdown preview or GitHub to verify badge rendering
- No automated tests needed — this is documentation-only

## Acceptance criteria

- [ ] Badge section exists immediately below `# JA4proxy` heading
- [ ] At minimum: License, Python version, Go version, CI status badges are present
- [ ] All static badges use correct shields.io URLs with proper colors
- [ ] All dynamic badges point to correct GitHub Actions workflow paths
- [ ] Badge links open to relevant project pages or workflows
- [ ] `make lint-phases` exits 0
- [ ] `python3 scripts/sync-roadmap.py` runs successfully

## Out of scope

- Changing any project configuration, dependencies, or code
- Setting up new badge providers or custom badge infrastructure
- Adding badges that require external service signup (e.g., Code Climate, Snyk)
- Modifying any file except README.md and phase documentation
