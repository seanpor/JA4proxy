# Python Management API & Analytics Coverage Push

## Goal
Implement unit tests and Hypothesis stateful model-based tests across JA4proxy's Python Management UI (`management/`) and analytics engines (`src/`). Elevate Python package coverage to $\ge 90\%$.

---

## Scope
1. **Target Packages**: `management/api/`, `src/analytics/`.
2. **New Test Files**: `management/tests/test_hypothesis_stateful.py`.

---

## Test Strategy
- `make cover-python`

---

## Acceptance Criteria
- [ ] `management/tests/test_hypothesis_stateful.py` implemented and passing.
- [ ] Python statement coverage $\ge 90\%$.
