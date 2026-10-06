# Configuration Hot-Swap & Management API Invariants

## Goal
Implement property-based invariant test suites for JA4proxy's configuration hot-reloading mechanism and Management API security plane (`internal/config`, `cmd/ja4pd`, and `management/`). Establish formal guarantees that `p.reload()` configuration updates are atomic without dropping in-flight connections, that invalid YAML updates roll back automatically with metric accounting, and that the Management API strictly satisfies Total Mediation across all routes and RBAC roles (`auditor < analyst < operator < admin`).

---

## Read These First
- `cmd/ja4pd/main.go` (`p.reload()` implementation)
- `cmd/ja4pd/pentest_reload_respects_config_path_regression_test.go` (existing reload regression tests)
- `cmd/ja4pd/stream_reload_test.go` (stream reload behavior)
- `management/api/auth.py` (`_ROLE_ORDER` and `_unauthenticated_response`)
- `management/api/main.py` (`create_app`)
- `management/tests/test_profile_bounds_and_readonly.py` (existing route-walking test)

---

## Verified API Surface
- `p.reload()` — `cmd/ja4pd/main.go:1092`
- `ja4proxy_config_reloads_total` — `internal/metrics/metrics.go`
- `ja4proxy_config_reload_failures_total` — `internal/metrics/metrics.go`
- `create_app()` — `management/api/main.py:386`
- `auditor < analyst < operator < admin` — `management/api/auth.py:513`

---

## Invariants

| ID | Plain-English Statement | Formal Statement | SecOps Rationale |
|---|---|---|---|
| `INV-CONFIG-001` | Atomic `p.reload()` Hot-Swap | $\text{ValidUpdate}(cfg) \implies \text{ActiveConnsUnchanged} \land \text{NewPolicyActive}$ | Allows operators to update proxy rules live without severing active client TLS streams. |
| `INV-CONFIG-002` | Zero-Downtime Rollback on Invalid Config | $\text{Invalid}(cfg) \implies \text{ActiveConfigRetained} \land \Delta\text{ReloadFailures} == 1$ | Guarantees syntax or semantic errors in new YAML configs do not crash running proxies or degrade security policies. |
| `INV-MGMT-001` | Total Mediation Across All Routes | $\forall r \notin \text{PublicRoutes}, \quad \text{NoAuth}(r) \implies (401 \lor 302 \to /\text{login})$ | Ensures zero unauthenticated attack surface expansion on the management control plane. |
| `INV-MGMT-002` | RBAC Mutating Endpoint Enforcement | $\forall r \in \text{MutatingRoutes}, \quad \text{Role} < \text{operator} \implies \text{HTTP 403}$ | Prevents read-only auditor or analyst accounts from executing administrative mutations. |

---

## Step-by-Step Implementation Guide

### Step 1: Create `cmd/ja4pd/config_invariant_test.go`
```go
package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/seanpor/ja4proxy/internal/metrics"
)

func TestInvariant_Config_AtomicReload(t *testing.T) {
	p, mr, cfg := newTestProxy(t)
	defer mr.Close()
	defer p.Stop()

	// Direct call to p.reload() without sending process signals
	err := p.reload()
	if err != nil {
		t.Fatalf("Direct p.reload() failed: %v", err)
	}
}

func TestInvariant_Config_InvalidRollback(t *testing.T) {
	p, mr, cfg := newTestProxy(t)
	defer mr.Close()
	defer p.Stop()

	tmpDir := t.TempDir()
	invalidPath := filepath.Join(tmpDir, "invalid.yaml")
	_ = os.WriteFile(invalidPath, []byte("invalid: yaml: : : error"), 0644)

	p.cfgPath = invalidPath
	failures0 := getCounterValue(metrics.ConfigReloadFailuresTotal)

	err := p.reload()
	if err == nil {
		t.Fatalf("Expected reload to fail for invalid YAML")
	}

	failures1 := getCounterValue(metrics.ConfigReloadFailuresTotal)
	if failures1-failures0 != 1 {
		t.Fatalf("Expected config_reload_failures_total to increment by 1")
	}
}
```

### Step 2: Create `management/tests/test_rbac_invariants.py`
```python
"""
management/tests/test_rbac_invariants.py
Verifies Total Mediation across all FastAPI routes.
"""
import pytest
from fastapi.routing import APIRoute
from management.api.main import create_app

PUBLIC_ROUTES = {"/health", "/metrics", "/login", "/logout"}

@pytest.fixture
def app_instance():
    return create_app()

def test_invariant_mgmt_total_mediation(client, app_instance):
    """Every route outside PUBLIC_ROUTES must reject unauthenticated requests with 401 or 302."""
    for route in app_instance.routes:
        if isinstance(route, APIRoute):
            path = route.path
            if any(path.startswith(pub) for pub in PUBLIC_ROUTES) or path.startswith("/static"):
                continue

            for method in route.methods:
                if method == "OPTIONS":
                    continue
                resp = client.request(method, path, headers={"Accept": "application/json"})
                assert resp.status_code in {401, 302}, f"Unauthenticated access allowed on {method} {path}: {resp.status_code}"

def test_invariant_mgmt_rbac_auditor_cannot_mutate(auditor_client, app_instance):
    """Auditor role must receive 403 on mutating HTTP methods."""
    for route in app_instance.routes:
        if isinstance(route, APIRoute):
            path = route.path
            if path in {"/login", "/logout"}:
                continue
            for method in route.methods:
                if method in {"POST", "PUT", "DELETE", "PATCH"}:
                    # Replace path parameters for testing
                    test_path = path.replace("{id}", "1").replace("{name}", "test")
                    resp = auditor_client.request(method, test_path)
                    assert resp.status_code in {403, 422}, f"Mutating route {method} {test_path} permitted Auditor role! Got {resp.status_code}"
```

---

## Make It Fail First

| Invariant ID | Temporary Code Mutation | Expected Test Failure |
|---|---|---|
| `INV-CONFIG-001` | Clear rule tables on reload start in `cmd/ja4pd/main.go` | Atomic reload test detects active connection drop |
| `INV-CONFIG-002` | Remove `ConfigReloadFailuresTotal.Inc()` in `reload()` | Invalid rollback test fails counter assertion |
| `INV-MGMT-001` | Remove auth dependency from `/api/v1/config` route | Total mediation test detects 200 OK on unauth call |
| `INV-MGMT-002` | Lower required role for `POST /api/v1/rules` to `auditor` | RBAC test detects 200 OK for auditor client |

---

## Test Commands

- **Run Config Invariants:**
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./cmd/ja4pd -run '^TestInvariant_Config_'`
- **Run Management API Invariants:**
  `docker run --rm -v "$PWD":/src -w /src ja4proxy-tools pytest management/tests/test_rbac_invariants.py`
- **Run Invariant Suite:**
  `make test-invariants`

---

## Coverage Target

- **Package `cmd/ja4pd` Baseline:** 80.1% $\to \ge 85.0\%$
- **Python Management Baseline:** Baseline $\to \ge 90.0\%$

---

## Acceptance Criteria

- [ ] Invariant test files created and all 4 invariants passing.
- [ ] Invariants registered in `docs/testing/invariants.yaml`.
- [ ] `make test-invariants` count increased by 4.
- [ ] Package coverage targets met.
- [ ] Mutation check table verified.
- [ ] News fragment created in `docs/fragments/phase-606g-config-invariants.md`.
- [ ] `make preflight` passes 100% green.

---

## Out of Scope
- Prometheus exporter scrapers (covered in Phase 606f).
- Command-line flags for CLI (covered in Phase 606j).
