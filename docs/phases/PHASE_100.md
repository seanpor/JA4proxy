<!--
title: Phase 100 — Phase 79 SSO/MFA Gap Closure
audience: Developers
phase: 100
-->

# Phase 100 — Phase 79 SSO/MFA Gap Closure

> Gap-tracking phase.  All items below were identified during the Phase 79 C7–C9
> critical review (2026-04-07) and are either too large to fix inline or require
> external accounts/infrastructure not available during the original implementation.

---

## Context

Phase 79 implemented TOTP MFA (C6), WebAuthn/FIDO2 (C7), SAML 2.0 SSO (C8), and
OIDC SSO (C9).  The implementation is functionally correct and fully tested with
mocks.  The following gaps were identified and deferred:

---

## Gap 1 — OIDC ID Token Signature Not Verified

**File**: `management/api/routes/oidc.py:_extract_claims`

**Problem**: `_extract_claims()` base64-decodes the JWT payload without verifying
the RS256/ES256 signature.  An attacker who can intercept or forge a token response
could supply a crafted `id_token` with arbitrary claims (elevated role, different
`sub`).

**Fix**:
1. After fetching the discovery doc, also fetch `jwks_uri`.
2. Use `authlib.jose.JsonWebKey` to load the JWKS.
3. Verify the `id_token` signature using `authlib.jose.jwt.decode(id_token, key)`.
4. Validate `iss`, `aud`, `exp`, `iat` claims per RFC 8693.

**Acceptance criteria**:
- `_extract_claims` raises on invalid signature.
- Tests mock the JWKS endpoint and provide a real RS256 key pair to sign the test id_token.
- Production: fetched JWKS are cached per `Cache-Control` header (or 1h TTL).

---

## Gap 2 — SSO Login Events Not Audited

**Files**: `management/api/routes/saml.py`, `management/api/routes/oidc.py`

**Problem**: Successful SAML ACS and OIDC callback logins are logged at INFO level
but are NOT written to `management:audit_log`.  SOC 2 evidence requires all login
events to appear in the audit trail.

**Fix**:
- In `saml_acs` and `oidc_callback`, after issuing the JWT cookie, call
  `write_audit(redis, actor_id=username, actor_ip=..., action_type="sso.login",
  resource_type="session", role=role.value, after_value={"provider": "saml"|"oidc"})`.
- Use `_client_ip(request)` for `actor_ip`.

**Acceptance criteria**:
- `GET /api/v1/audit` shows an entry for each SSO login.
- Entry includes `actor_id` (NameID / OIDC sub), `actor_ip`, `action_type=sso.login`.
- Tests assert the audit log entry exists after a mocked successful login.

---

## Gap 3 — No DELETE Endpoint for WebAuthn Credentials

**File**: `management/api/routes/webauthn.py`

**Problem**: Users can register multiple WebAuthn credentials but cannot remove
individual ones.  A lost or compromised hardware key cannot be revoked.

**Fix**:
- `DELETE /auth/mfa/webauthn/credentials/{credential_id_b64}` — remove one credential.
- Validates ownership (credential.user_id must match authenticated user).
- Removes from `mgmt:webauthn:credential:{id}` and from
  `mgmt:webauthn:user:{user_id}:credentials` SET.
- Returns 404 if credential not found; 403 if not owned by caller.
- `GET /auth/mfa/webauthn/credentials` — list enrolled credential IDs + created_at.

**Acceptance criteria**:
- DELETE removes the hash and SET entry.
- DELETE on another user's credential returns 403.
- GET lists all credential IDs for the authenticated user.
- Tests cover all paths.

---

## Gap 4 — SSO-Delegated MFA Not Implemented

**File**: `management/api/auth.py:require_mfa_verified`

**Problem**: When a user authenticates via SAML or OIDC, the IdP may have already
enforced MFA (e.g. Okta Verify, Entra ID Authenticator).  The current implementation
still requires the user to complete TOTP or WebAuthn after SSO login, even when the
IdP has asserted `amr=mfa` or equivalent.

**Fix**:
- In `saml_acs` and `oidc_callback`, after role mapping, check whether the IdP
  asserted MFA.
  - SAML: `auth.get_last_authn_contexts()` — check for
    `urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract` or
    `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport` at minimum.
  - OIDC: ID token `amr` claim — check for `"mfa"`, `"otp"`, `"hwk"`.
- If IdP asserts MFA, call `_set_mfa_verified(redis, jwt_token)` immediately after
  issuing the cookie (write `mgmt:mfa:session:{sha256(token)}` → "verified").
- Add env var `MANAGEMENT_SSO_TRUST_IDP_MFA=true` (default false) — admin must
  explicitly enable IdP MFA trust.

**Acceptance criteria**:
- With `MANAGEMENT_SSO_TRUST_IDP_MFA=true`, a SAML/OIDC login with an `amr=mfa`
  claim skips the local MFA gate.
- With the flag false (default), the local MFA gate still applies.
- Tests verify both paths.

---

## Gap 5 — SAML Integration Test Markers Missing

**File**: `management/tests/test_saml.py`

**Problem**: The spec requires SAML tests against live IdPs to be marked
`@pytest.mark.integration` and skipped without `OKTA_METADATA_URL`.  Current tests
use mocks (correct) but the marker is missing, so future live-IdP tests have no
skeleton to slot into.

**Fix**:
- Add a `pytest.ini` or `pyproject.toml` marker definition for `integration`.
- Add at least one placeholder test decorated with:
  ```python
  @pytest.mark.integration
  @pytest.mark.skipif(
      not os.environ.get("OKTA_METADATA_URL"),
      reason="OKTA_METADATA_URL not set — live Okta test skipped",
  )
  async def test_saml_live_okta_login():
      ...
  ```
- Same pattern for Entra ID OIDC: `ENTRA_OIDC_DISCOVERY_URL`.

**Acceptance criteria**:
- `pytest -m "not integration"` skips all live-IdP tests.
- `pytest -m integration` runs only live-IdP tests.
- Marker registered in `pyproject.toml` (no unknown-marker warnings).

---

## Gap 6 — Group-to-Role Mapping via config/proxy.yml Not Wired

**Files**: `management/api/routes/saml.py`, `management/api/routes/oidc.py`

**Problem**: The Phase 79 spec shows role mapping configured in `config/proxy.yml`:
```yaml
sso:
  role_mapping:
    "SOC-Analysts": analyst
```
Current implementation reads only from env vars (`MANAGEMENT_SAML_ROLE_MAPPING`,
`MANAGEMENT_OIDC_ROLE_MAPPING`).  The proxy config file is not consulted.

**Fix**:
- Load the `sso.role_mapping` section from `config/proxy.yml` at startup (or per-request
  with caching).
- Merge with env var overrides (env var takes precedence if both are set).
- This likely requires the management service to have read access to `config/proxy.yml`.

**Note**: This may be better addressed as part of a dedicated config unification phase
since it touches how the management service reads proxy config.

**Acceptance criteria**:
- Role mapping in `config/proxy.yml` is honoured without env vars.
- Env var overrides config file when both are present.
- Hot-reload of config reloads the mapping.

---

## Gap 7 — OpenAPI 3.1 Spec (`docs/api/openapi.yaml`)

**Status**: Deferred to Phase 79 Cluster 10 (C10, not yet started).

**Description**: FastAPI's `/api/docs` provides an auto-generated OpenAPI 3.0 spec.
The requirement is to export and commit a static OpenAPI 3.1 spec at
`docs/api/openapi.yaml` so it can be used by downstream tooling (Terraform provider,
SDK generation, compliance evidence).

**Acceptance criteria** (from Phase 79 spec):
- `docs/api/openapi.yaml` exists and is valid OpenAPI 3.1.
- All Phase 79 routes are present in the spec.
- Committed to the branch as part of Phase 79 close-out.

---

## Implementation Order

| Priority | Gap | Effort | Blocker |
|----------|-----|--------|---------|
| P0 | Gap 1 — OIDC JWKS signature | Medium | None |
| P0 | Gap 2 — SSO audit events | Small | None |
| P1 | Gap 3 — WebAuthn credential DELETE | Small | None |
| P1 | Gap 4 — SSO-delegated MFA | Medium | Requires IdP config |
| P2 | Gap 5 — Integration test markers | Trivial | None |
| P2 | Gap 6 — config.yml role mapping | Large | Config unification |
| P2 | Gap 7 — OpenAPI spec | Small | C10 |

---

## Dependencies

- Phase 79 (must be COMPLETE first — this phase closes its gaps)
- Phase 84 (Compliance Reporting) benefits from Gap 2 (audit events)

---

*Created: 2026-04-07*
*Source: Phase 79 C7–C9 critical review*
