# Code Health Report — 2026-04-16

## Summary

| Metric | Value | Status |
|--------|-------|--------|
| Tests passing | 5444 | OK |
| Tests skipped | 12 | OK (all approved) |
| Warnings | 416 | Needs attention |
| Overall coverage | 92.76% (target 80%) | OK |
| mypy | 1 error | FAIL |
| Duration | 95s | OK |

---

## 1. Lint Failure: mypy

`make lint-all` fails due to one mypy error:

```
src/analytics/ti_feeds/safe_resolver.py:47: error: Incompatible types in assignment
  (expression has type "IPv6Network", variable has type "IPv4Network")
```

**Root cause:** The `_IPV6_PRIVATE` tuple on line 19 contains `IPv6Network` objects,
but mypy infers the loop variable type from the first branch (`_IPV4_PRIVATE`) which
uses `IPv4Network`. The `elif` branch iterates `_IPV6_PRIVATE` with the same variable
name `net`, and mypy flags the type mismatch.

**Fix:** Trivial — add explicit `Union` type annotation or use a different variable name
in the `elif` block.

Additionally, `src/management/app.py:126` has an `annotation-unchecked` note — untyped
function body not being checked. Lower priority but worth adding type hints.

---

## 2. Test Warnings (416)

All 416 warnings fall into two categories:

### a. Unregistered `pytest.mark.unit` (6 files, ~96 warnings)

These files use `@pytest.mark.unit` which is not registered in `pyproject.toml`:

| File | Approx warnings |
|------|-----------------|
| `tests/chaos/test_ti_feed_taxii_unavailable.py` | 16 |
| `tests/integration/test_ti_feeds_e2e.py` | 16 |
| `tests/integration/test_ti_feeds_cleanup.py` | 16 |
| `tests/integration/test_ti_feeds_conflict.py` | 16 |
| `tests/integration/test_ti_feeds_hot_reload.py` | 16 |
| `tests/unit/management/test_phase_101b_compliance_hygiene.py` | 80 |

**Fix:** Add `"unit: marks a unit test"` to the `markers` list in `pyproject.toml`.

### b. Google API deprecation warning (~320 warnings)

```
google.api_core._python_version_support.py: FutureWarning: Python 3.10 support
ending 2026-10-04
```

**Fix:** Either upgrade to Python 3.11+ or suppress in `pyproject.toml` filterwarnings:
```
filterwarnings = ["ignore::FutureWarning:google.api_core"]
```

---

## 3. Coverage: Files Below 80% Threshold

These files are below the project's 80% coverage target:

| File | Stmts | Miss | Cover | Notes |
|------|-------|------|-------|-------|
| `src/cli/main.py` | 48 | 48 | **0%** | CLI entrypoint, no tests at all |
| `src/management/redis_client.py` | 76 | 53 | **30%** | Redis wrapper, mostly untested |
| `src/analytics/main.py` | 140 | 90 | **36%** | Analytics entrypoint |
| `src/analytics/ti_feeds/runner.py` | 304 | 181 | **40%** | TI feed runner |
| `src/analytics/ti_feeds/seed_file.py` | 119 | 70 | **41%** | Seed file loader |
| `src/analytics/ti_feeds/rest_generic.py` | 135 | 62 | **54%** | Generic REST client |
| `src/analytics/ti_feeds/crowdstrike.py` | 151 | 68 | **55%** | CrowdStrike integration |
| `src/security/seccomp_transition.py` | 78 | 34 | **56%** | Seccomp support |
| `src/analytics/ti_feeds/state.py` | 242 | 88 | **64%** | Feed state management |
| `src/analytics/ti_feeds/contribution.py` | 110 | 37 | **66%** | TI feed contribution |
| `src/analytics/ti_feeds/ja4_safety.py` | 36 | 11 | **69%** | JA4 safety checks |
| `src/analytics/ti_feeds/taxii.py` | 170 | 50 | **71%** | TAXII client |
| `src/analytics/ti_feeds/mgmt_client.py` | 159 | 46 | **71%** | Management API client |
| `src/security/validation.py` | 217 | 45 | **79%** | Input validation |

**Pattern:** The `src/analytics/ti_feeds/` subsystem is the weakest area — 9 of 14
below-threshold files are in that directory. The `runner.py` and `seed_file.py` are
particularly under-tested. `src/cli/main.py` at 0% and `src/management/redis_client.py`
at 30% are the worst individual files.

---

## 4. Recommended Actions (Priority Order)

1. **Fix mypy error** in `safe_resolver.py` — unblocks `make lint-all` (5 min)
2. **Register `unit` marker** in `pyproject.toml` — eliminates ~96 warnings (1 min)
3. **Suppress Google API FutureWarning** — eliminates ~320 warnings (1 min)
4. **Add tests for `src/cli/main.py`** — 0% coverage is a gap (low effort, CLI is small)
5. **Add tests for `src/management/redis_client.py`** — 30% on a Redis wrapper is risky
6. **Improve `ti_feeds/` coverage** — runner.py, seed_file.py, state.py are the most
   impactful targets given their size

Items 1–3 bring `make lint-all` to green and `make test` to zero warnings.
Items 4–6 are coverage debt that should be addressed in a dedicated phase.
