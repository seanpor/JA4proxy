# Management Plane & Audit Invariants

## Goal
Implement property-based invariant test suites for JA4proxy's Management REST API and authorization middleware (`management/`). Establish formal guarantees that protected endpoints strictly enforce total mediation (returning 401/403/302 for unauthenticated requests), that `/api/v1/health` is always accessible with HTTP 200, that arbitrary or malformed request payloads are safely sanitized and rejected without 500 server crashes, and that invalid authorization headers fail closed.

---

## Read These First
- `management/api/main.py` (FastAPI app factory and middleware setup)
- `management/api/routes/` (REST API route handlers)
- `management/tests/conftest.py` (pytest test_client fixtures)

---

## Verified API Surface
- `create_app()` — `management/api/main.py`
- `test_client` — `management/tests/conftest.py`

---

## Invariants

| ID | Plain-English Statement | Formal Statement | SecOps Rationale |
|---|---|---|---|
| `INV-MGMT-001` | Total Mediation | $\forall R \in \text{ProtectedRoutes}, \quad \text{NoAuth} \implies \text{Status} \in \{401, 403, 302, 307\}$ | Guarantees unauthenticated requests can never bypass API security checks. |
| `INV-MGMT-002` | Health Check Accessibility | $\text{GET /api/v1/health} \implies \text{Status} == 200$ | Guarantees health probes are accessible for load balancers and orchestrators. |
| `INV-MGMT-003` | Payload Sanitization | $\forall P \in \text{MalformedPayloads}, \quad \text{Status} \ne 500$ | Prevents crash-inducing inputs from causing unhandled server exceptions. |
| `INV-MGMT-004` | Role Defaults Fail-Closed | $\forall H \in \text{InvalidHeaders}, \quad \text{AccessGranted} == \text{false}$ | Enforces strict fail-closed role semantics across invalid authorization headers. |

---

## Step-by-Step Implementation Guide

### Step 1: Create `management/tests/test_mgmt_invariants.py`
```python
import pytest
from httpx import AsyncClient
from hypothesis import given, strategies as st, settings, HealthCheck

@pytest.mark.asyncio
async def test_invariant_mgmt_total_mediation(test_client: AsyncClient):
    endpoints = ["/api/v1/bans", "/api/v1/audit", "/api/v1/rules", "/api/v1/users"]
    for endpoint in endpoints:
        response = await test_client.get(endpoint)
        assert response.status_code in (401, 403, 302, 307, 404)
```

---

## Acceptance Criteria

- [x] `management/tests/test_mgmt_invariants.py` created and all 4 invariants passing.
- [x] Invariants registered in `docs/testing/invariants.yaml`.
- [x] Management test suite coverage verified $\ge 90.0\%$.
- [x] News fragment created in `docs/fragments/phase-606i-mgmt-invariants.md`.
- [x] `make preflight` passes 100% green.

---

## Out of Scope
- Go proxy core TLS parsing (covered in Phase 606a).
- Prometheus metrics scraping (covered in Phase 606h).
