# Configuration Hot-Swap & Management API Invariants

## Goal
Implement property-based invariant test suites for JA4proxy's configuration hot-reloading mechanism and Management API security plane (`internal/config/` and `management/`). Establish formal mathematical guarantees that SIGHUP configuration updates are atomic (zero connection drops), that invalid configuration reloads rollback automatically without downtime, and that the Management API strictly satisfies the principle of Total Mediation (every endpoint enforces authentication and RBAC with 100% audit logging).

---

## Scope
1. **Target Packages**:
   - `internal/config/` (YAML loader, validator, SIGHUP signal listener, hot-swap engine).
   - `management/` (FastAPI routes, JWT verification, role-based access control, audit logs).
2. **New Test Files**:
   - `internal/config/config_invariant_test.go`
   - `management/tests/test_rbac_invariants.py`
3. **Formal Invariants to Enforce**:
   - **Invariant 1 (Atomic SIGHUP Hot-Swap)**:
     Sending SIGHUP with a valid configuration update must atomically replace the proxy's running configuration. Active TCP connections in flight must complete normally without reset, and new connections immediately observe the new configuration.
   - **Invariant 2 (Zero-Downtime Rollback on Invalid Configuration)**:
     If a SIGHUP is triggered with a syntactically invalid YAML file, unparseable CIDR, or semantic constraint violation (e.g. negative timeout):
     - The reload must fail safely and log an error.
     - The proxy must retain the previous valid configuration with zero disruption or downtime.
     - The metric `config_reload_failures_total` must increment.
   - **Invariant 3 (Total Mediation & RBAC Invariance)**:
     Let $\mathcal{R}$ be the set of all Management API routes.
     $$\forall r \in \mathcal{R} \setminus \text{PublicRoutes}, \quad \text{Request}(r, \text{NoAuth}) \implies \text{HTTP 401}$$
     $$\forall r \in \mathcal{R}_{\text{Admin}}, \quad \text{Request}(r, \text{Role}=\text{Viewer}) \implies \text{HTTP 403}$$
     Every non-public endpoint strictly mediates access; zero routes bypass authentication.
   - **Invariant 4 (Complete Audit Attribution)**:
     Every mutating API call (creating a ban, removing a rule, updating proxy config) must write an audit record with timestamp, caller identity, IP, action, and result before returning HTTP 200.

---

## Junior Developer Implementation Guide

### Step 1: Implement Go Config Reload Invariant Test
In `internal/config/config_invariant_test.go`:
```go
package config_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/seanpor/ja4proxy/internal/config"
	"github.com/seanpor/ja4proxy/internal/proxy"
)

func TestInvariant_AtomicConfigSwap(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	// 1. Write initial configuration (AllowedJA4: ["t13d..."])
	writeConfigFile(t, cfgPath, initialConfigYAML)

	p := proxy.NewFromConfigFile(cfgPath)
	listener, err := p.Start()
	if err != nil {
		t.Fatalf("Failed to start proxy: %v", err)
	}
	defer p.Stop()

	// 2. Overwrite config file with new rule (AllowedJA4: ["t13d...", "new_fingerprint..."])
	writeConfigFile(t, cfgPath, updatedConfigYAML)

	// 3. Send SIGHUP to trigger reload
	_ = syscall.Kill(syscall.Getpid(), syscall.SIGHUP)
	time.Sleep(100 * time.Millisecond) // Allow reload goroutine to swap pointer

	// 4. Assert new rule is active immediately
	currentCfg := p.GetActiveConfig()
	if len(currentCfg.AllowedJA4) != 2 {
		t.Fatalf("Atomic swap failed: expected 2 allowed JA4s, got %d", len(currentCfg.AllowedJA4))
	}
}

func TestInvariant_InvalidConfigRollback(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	writeConfigFile(t, cfgPath, initialConfigYAML)

	p := proxy.NewFromConfigFile(cfgPath)
	_, _ = p.Start()
	defer p.Stop()

	// Overwrite with invalid syntax
	_ = os.WriteFile(cfgPath, []byte("invalid: yaml: : : syntax error"), 0644)

	_ = syscall.Kill(syscall.Getpid(), syscall.SIGHUP)
	time.Sleep(100 * time.Millisecond)

	// Assert previous valid config is still running
	currentCfg := p.GetActiveConfig()
	if len(currentCfg.AllowedJA4) != 1 {
		t.Fatalf("Rollback failed: active config corrupted by invalid reload")
	}
}
```

### Step 2: Implement Python Management API RBAC Invariant Test
In `management/tests/test_rbac_invariants.py`:
```python
"""
management/tests/test_rbac_invariants.py
Property-based invariant test verifying Total Mediation across all FastAPI routes.
"""
import pytest
from fastapi.routing import APIRoute
from management.api.main import app

PUBLIC_ROUTES = {"/health", "/metrics", "/docs", "/openapi.json"}

def test_invariant_total_mediation_unauthenticated(client):
    """Every route outside PUBLIC_ROUTES must reject unauthenticated requests with 401."""
    for route in app.routes:
        if isinstance(route, APIRoute):
            path = route.path
            if path in PUBLIC_ROUTES:
                continue

            for method in route.methods:
                if method == "OPTIONS":
                    continue
                resp = client.request(method, path)
                assert resp.status_code == 401, f"Route {method} {path} allowed unauthenticated access! Got {resp.status_code}"

def test_invariant_rbac_viewer_cannot_mutate(viewer_client):
    """Viewer role must receive 403 on all mutating operations (POST, PUT, DELETE, PATCH)."""
    for route in app.routes:
        if isinstance(route, APIRoute):
            path = route.path
            for method in route.methods:
                if method in {"POST", "PUT", "DELETE", "PATCH"}:
                    resp = viewer_client.request(method, path)
                    assert resp.status_code == 403, f"Mutating route {method} {path} permitted Viewer role! Got {resp.status_code}"
```

---

## Test Strategy
- Run Go config reload tests:
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./internal/config -run ConfigInvariant`
- Run Python Management API RBAC tests (in container):
  `docker run --rm -v "$PWD":/src -w /src ja4proxy-tools pytest management/tests/test_rbac_invariants.py`
- Validate entire suite:
  `make preflight`

---

## Acceptance Criteria
- [ ] `internal/config/config_invariant_test.go` implemented and passing.
- [ ] `management/tests/test_rbac_invariants.py` implemented and passing.
- [ ] Atomic SIGHUP config hot-swap verified without connection disruption.
- [ ] Invalid YAML reload proven to leave running configuration 100% intact.
- [ ] Total Mediation proven across 100% of Management API routes with zero auth bypasses.
- [ ] `make test-unit` and `make preflight` pass 100% green.

---

## Out of Scope
- TLS ClientHello parsing (covered in 606a).
- Prometheus metric arithmetic conservation (covered in 606f).
