# Phase 845: Zero-Warning Quality Enforcement & Deprecation Elimination

## Goal
Enforce a strict zero-warning policy across test and lint pipelines (`gcc -Wall` philosophy for CI), eliminating all upstream deprecation warnings, link-checker breaks, and advisor-stage noise so that `make lint` and `make test` emit zero warnings and cleanly reflect genuine codebase health.

## Context & Motivation
Currently, `make lint` and `make test` pass, but they print advisory and runtime warnings:
1. **Python 3.14 Runtime Deprecations**:
   - `StarletteDeprecationWarning: HTTP_422_UNPROCESSABLE_ENTITY is deprecated. Use HTTP_422_UNPROCESSABLE_CONTENT instead.`
   - `onelogin/saml2` and test harnesses calling deprecated `datetime.datetime.utcnow()` and `datetime.datetime.utcfromtimestamp()` instead of `datetime.datetime.now(datetime.UTC)` and `datetime.datetime.fromtimestamp(ts, datetime.UTC)`.
   - `Starlette.testclient` and `httpx` cookie deprecation warnings during integration tests.
   - `authlib.jose` module deprecation warnings.
2. **Lychee Link Checker**:
   - 12 broken links in archived documentation references (`docs/phases/complete/PHASE_232c.md`, local URL fixtures `https://127.0.0.1:8444/`).
3. **Codespell & Markdownlint**:
   - Double blank lines in `README.md` and spelling mismatches (`Pre-empt` vs `Preempt`).

Treating warnings as bugs prevents latent technical debt from obscuring real security and correctness regressions.

## Scope
1. **Management API & Python Deprecation Updates**:
   - Update Starlette 422 status codes across `management/api/routes/` from `HTTP_422_UNPROCESSABLE_ENTITY` to `HTTP_422_UNPROCESSABLE_CONTENT`.
   - Update datetime usage across tests and helper scripts to timezone-aware UTC objects (`datetime.now(datetime.UTC)`).
   - Configure pytest and warning filters to treat unhandled runtime warnings as errors (`-W error`), with explicit, auditable exemptions for unpatched third-party internals only.
2. **Lychee Link Hygiene**:
   - Update broken historical paths in archived phase docs or add explicit `.lycheeignore` patterns for historical retrospectives.
   - Exclude mock fixture URLs (`127.0.0.1:8444`) from live URL checking.
3. **Markdown & Spell Checking**:
   - Fix blank lines in `README.md`.
   - Update `.codespellignore` for acceptable security domain terminology.

## Test Strategy
- `make lint` must exit 0 with 0 errors and clean output across all stages.
- `make test` must pass all test suites with 0 unhandled deprecation warnings.

## Acceptance Criteria
- [ ] No `StarletteDeprecationWarning` or `datetime.utcnow()` warnings produced during `make test`.
- [ ] `lychee` exits 0 with 0 broken links in `make lint`.
- [ ] Pytest warning filter clean and verified.
