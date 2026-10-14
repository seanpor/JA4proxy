# Phase 845: Zero-Warning Quality Enforcement & Deprecation Elimination

## Goal
Enforce a strict zero-warning policy across test and lint pipelines (`gcc -Wall` philosophy for CI), eliminating all upstream deprecation warnings, link-checker breaks, and advisor-stage noise so that `make lint` and `make test` emit zero warnings and cleanly reflect genuine codebase health.

## Context & Motivation
Currently, `make lint` and `make test` pass, but they print advisory and runtime warnings:
1. **Python 3.14 Runtime Deprecations**:
   - `StarletteDeprecationWarning: HTTP_422_UNPROCESSABLE_ENTITY is deprecated. Use HTTP_422_UNPROCESSABLE_CONTENT instead.`
   - Test harnesses calling deprecated `datetime.datetime.utcnow()` and `datetime.datetime.utcfromtimestamp()` instead of `datetime.datetime.now(datetime.UTC)` and `datetime.datetime.fromtimestamp(ts, datetime.UTC)`.
   - `Starlette.testclient` and `httpx` cookie deprecation warnings during integration tests.
   - `authlib.jose` module deprecation warnings.
2. **Lychee Link Checker**:
   - 12 broken links in archived documentation references (`docs/phases/complete/PHASE_232c.md`, local URL fixtures `https://127.0.0.1:8444/`).
3. **Codespell & Markdownlint**:
   - Double blank lines in `README.md` and spelling mismatches (`Pre-empt` vs `Preempt`).

Treating warnings as bugs prevents latent technical debt from obscuring real security and correctness regressions.

## Scope & Implementation Guardrails

### 1. Management API & Python Deprecation Updates
- Safely migrate Starlette 422 status codes across `management/api/routes/` from `HTTP_422_UNPROCESSABLE_ENTITY` to `HTTP_422_UNPROCESSABLE_CONTENT`.
- Modernize all datetime usage in JA4proxy codebase and test suites to timezone-aware UTC objects (`datetime.now(datetime.UTC)`).
- **No Monkey-Patching of Third-Party Crypto/Auth Libraries:** Upstream libraries like `python3-saml` (`onelogin/saml2`) internally using deprecated functions must not be monkey-patched (preventing epoch skew or assertion validation errors). Instead:
  - Scope `-W error` strictly to project packages (`management.*`, `src.*`).
  - Add explicit, auditable, targeted pytest filter expressions in `pyproject.toml` for unpatched upstream vendor internals:
    `"ignore:datetime.datetime.utcnow\\(\\) is deprecated:DeprecationWarning:onelogin.saml2.*"`
  - Document all upstream library exemptions in `docs/security/EXCEPTIONS.md`.

### 2. Lychee Link Hygiene (Strict Rule: Fix Actual Links, Never Hide)
- **Zero `.lycheeignore` Additions:** In strict accordance with the mandatory policy (*"when we are fixing things like broken links, we must not hide broken links, we must actually fix them"*), no broken links may be hidden via `.lycheeignore`.
- Update all broken relative and absolute file paths in `docs/` and `docs/phases/complete/` to point to their valid destination files.
- For documentation discussing local mock endpoints (e.g. `127.0.0.1:8444`), convert them from hyperlinks to code literals (inline backticks `` `https://127.0.0.1:8444/` ``), which represent literal code syntax and are not crawled as live HTTP links.

### 3. Markdown & Spell Checking
- Fix Markdown formatting errors (double blank lines) in `README.md`.
- Update `.codespellignore` for verified security domain terminology.

## Test Strategy
- `make lint` must exit 0 with 0 errors and zero broken links in Lychee.
- `make test` must pass all test suites with 0 unhandled deprecation warnings.
- Pytest `-W error` scoped to project code verified in CI.

## Acceptance Criteria
- [ ] No `StarletteDeprecationWarning` produced across `management/` routes.
- [ ] No `datetime.utcnow()` or `datetime.utcfromtimestamp()` calls remain in JA4proxy first-party codebase.
- [ ] `lychee` exits 0 with 0 broken links in `make lint` without adding new ignore rules.
- [ ] Scoped `-W error` enabled in `pyproject.toml` with zero test failures.
