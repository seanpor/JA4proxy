# Dependency Security Hardening: PyJWT Migration & Upstream gRPC Bump

## Goal
Eliminate recurring security waivers and close Dependabot security alerts by:
1. Migrating the Management API's JWT stack from unmaintained `python-jose` to `PyJWT`, removing `python-ecdsa` and permanently clearing `CVE-2024-23342` from `.trivyignore.first-party`.
2. Upgrading `google.golang.org/grpc` from `1.82.1` to `1.83.1` in `deploy/terraform-provider` (resolving Dependabot alerts #102, #103, #104 / PR #483).

## Background
- **`python-jose` & `CVE-2024-23342`:** `python-jose` is abandoned upstream and transitively pulls in `python-ecdsa`, which suffers from the Minerva timing attack (`CVE-2024-23342`). The upstream maintainer refuses to implement constant-time operations ("out of scope"). This has required maintaining a recurring 7-day waiver in `.trivyignore.first-party` for months. Switching to `PyJWT` (which uses standard `cryptography`) removes `python-jose` and `python-ecdsa` completely.
- **`google.golang.org/grpc` & PR #483:** Dependabot flagged three vulnerabilities (`CVE-2026-84445`, `CVE-2026-84304`, `CVE-2026-84303`) in the Terraform provider's gRPC dependency. PR #483 was created by Dependabot to bump to `1.83.1`. Incorporating this bump directly into Phase 831 resolves all three alerts simultaneously.

## Scope
1. **PyJWT Migration**:
   - In `management/requirements.txt`, replace `python-jose[cryptography]==3.5.0` with `PyJWT[crypto]==2.13.0`.
   - Update `management/api/auth.py` and `management/api/middleware/csrf.py` to use `jwt` (PyJWT) and handle `jwt.PyJWTError`.
   - Update test suites (`management/tests/test_auth.py`, `management/tests/test_saml.py`, `management/tests/test_oidc.py`, `management/tests/test_pentest_jwt_role_default_regression.py`) to import and expect `jwt.PyJWTError`.
   - Delete `CVE-2024-23342` from `.trivyignore.first-party`.
2. **Terraform Provider gRPC Bump**:
   - Update `deploy/terraform-provider/go.mod` and `deploy/terraform-provider/go.sum` to `google.golang.org/grpc v1.83.1`.
   - Close Dependabot alerts #102, #103, #104.
3. **Validation**:
   - Verify management API auth and CSRF test suite passes 100%.
   - Verify `make lint-phases`, `make scan-exceptions`, and `go test ./...` pass.

## Implementation Plan

### Step 1: Update Dependencies
- Modify `management/requirements.txt` to replace `python-jose` with `PyJWT[crypto]==2.13.0`.
- Update `deploy/terraform-provider/go.mod` to bump `google.golang.org/grpc` to `v1.83.1`.

### Step 2: Code Changes
- Replace `from jose import JWTError, jwt` with:
  ```python
  import jwt
  from jwt.exceptions import PyJWTError
  ```
- In `csrf.py`, replace `jwt.get_unverified_claims(token)` with `jwt.decode(token, options={"verify_signature": False})`.

### Step 3: Waiver Deletion
- Remove `CVE-2024-23342` from `.trivyignore.first-party`.

## Acceptance Criteria
1. All auth, SAML, OIDC, and pentest regression tests in `management/tests/` pass with zero failures.
2. `make scan-exceptions` runs with `CVE-2024-23342` removed.
3. `deploy/terraform-provider` compiles and tests cleanly with gRPC 1.83.1.
