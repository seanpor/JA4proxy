# Python Management API & Analytics Coverage Push

## Goal
Implement comprehensive unit tests and Hypothesis stateful model-based tests across JA4proxy's Python Management UI (`management/`) and analytics engines (`src/`). Elevate Python package statement coverage from baseline to $\ge 90.0\%$.

---

## Read These First
- `management/api/main.py` (`create_app`)
- `management/api/models.py` (Pydantic models)
- `src/analytics/` (Python threat analytics)
- `management/tests/test_environment_failclosed.py` (existing pytest setup)

---

## Verified API Surface
- `management.api.main.create_app` — `management/api/main.py:386`
- `pytest-cov` containerised runner — `Makefile` (`cover-python`)

---

## Invariants

| ID | Plain-English Statement | Formal Statement | SecOps Rationale |
|---|---|---|---|
| `INV-PY-001` | Pydantic Request Validation Boundary | $\forall d \notin \text{Schema}, \quad \text{POST}(d) \implies \text{HTTP 422}$ | Guarantees malformed API payloads are rejected at the input boundary before reaching business logic. |
| `INV-PY-002` | Ban Lifecycle State Machine Integrity | $\text{Hypothesis}(\text{RuleBasedStateMachine}) \implies \text{StateInvariantsHold}$ | Uses property-based state machine tests to verify ban creation, modification, and deletion consistency over arbitrary call sequences. |

---

## Step-by-Step Implementation Guide

### Step 1: Create `management/tests/test_hypothesis_stateful.py`
```python
"""
management/tests/test_hypothesis_stateful.py
Hypothesis stateful testing for ban and rule lifecycle.
"""
import pytest
from hypothesis.stateful import RuleBasedStateMachine, rule, initialize
from management.api.main import create_app

class BanLifecycleMachine(RuleBasedStateMachine):
    @initialize()
    def setup(self):
        self.app = create_app()
        self.active_bans = set()

    @rule()
    def check_state_consistency(self):
        # Assert active bans in memory match database state...
        pass

TestBanLifecycle = BanLifecycleMachine.TestCase
```

---

## Make It Fail First

| Invariant ID | Temporary Code Mutation | Expected Test Failure |
|---|---|---|
| `INV-PY-001` | Disable Pydantic validation on `/api/v1/bans` POST | Request validation test detects 200 OK on malformed data |
| `INV-PY-002` | Remove database delete call from ban removal endpoint | Hypothesis state machine test detects lingering ban in state |

---

## Test Commands

- **Run Python Invariants:**
  `docker run --rm -v "$PWD":/src -w /src ja4proxy-tools pytest management/tests/test_hypothesis_stateful.py`
- **Run Python Coverage:**
  `make cover-python`

---

## Coverage Target

- **Python Baseline:** Current Baseline $\to \ge 90.0\%$

---

## Acceptance Criteria

- [ ] `management/tests/test_hypothesis_stateful.py` created and passing.
- [ ] Invariants registered in `docs/testing/invariants.yaml`.
- [ ] Python statement coverage verified $\ge 90.0\%$.
- [ ] News fragment created in `docs/fragments/phase-606k-python-coverage.md`.
- [ ] `make preflight` passes 100% green.

---

## Out of Scope
- Go proxy core (covered in Phases 606a-g).
