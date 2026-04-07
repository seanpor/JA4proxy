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

## Prerequisites

- Phase 79 must be **COMPLETE** before starting this phase.
- Branch from `main` after the Phase 79 merge:
  ```bash
  git checkout main && git pull
  git checkout -b claude/phase-100-sso-mfa-gap-closure
  ```
- Work in this order: Gap 2 (audit events, trivial) → Gap 1 (JWKS sig) → Gap 3
  (WebAuthn DELETE) → Gap 4 (SSO-delegated MFA) → Gap 5 (test markers) → Gap 6
  (config.yml role mapping — large) → Gap 7 (OpenAPI spec).

---

## Context

Phase 79 implemented TOTP MFA (C6), WebAuthn/FIDO2 (C7), SAML 2.0 SSO (C8), and
OIDC SSO (C9).  The implementation is functionally correct and fully tested with
mocks.  The following gaps were identified and deferred:

---

## Gap 1 — OIDC ID Token Signature Not Verified

**File**: `management/api/routes/oidc.py`

**Function**: `_extract_claims(id_token: str) -> dict` (currently ~line 113)

**Problem**: `_extract_claims()` base64-decodes the JWT payload without verifying
the RS256/ES256 signature.  An attacker who can MITM or forge a token response
could supply a crafted `id_token` with arbitrary claims (elevated role, different
`sub`).

**Fix**:

The `authlib` package is already a dependency (`authlib>=1.3.0` in
`management/requirements.txt`).  Use it for both JWKS fetching and JWT verification.

1. Add a module-level JWKS cache (simple dict — one entry per `jwks_uri`):

   ```python
   import time
   from authlib.jose import JsonWebKey, jwt as authlib_jwt

   _jwks_cache: dict[str, tuple[object, float]] = {}  # uri → (key_set, expires_at)
   _JWKS_DEFAULT_TTL = 3600  # 1 hour
   ```

2. Add a `_fetch_jwks(jwks_uri: str) -> object` async helper (mockable, same pattern
   as `_fetch_oidc_discovery`):

   ```python
   async def _fetch_jwks(jwks_uri: str) -> object:
       """Fetch and cache JWKS from the IdP.  Returns an authlib KeySet."""
       now = time.monotonic()
       if jwks_uri in _jwks_cache:
           key_set, expires_at = _jwks_cache[jwks_uri]
           if now < expires_at:
               return key_set

       async with httpx.AsyncClient() as client:
           r = await client.get(jwks_uri, timeout=10.0)
           r.raise_for_status()
           # Honour Cache-Control max-age if present; fallback to 1h
           cc = r.headers.get("Cache-Control", "")
           ttl = _JWKS_DEFAULT_TTL
           for part in cc.split(","):
               if part.strip().startswith("max-age="):
                   try:
                       ttl = int(part.strip().split("=", 1)[1])
                   except ValueError:
                       pass
           key_set = JsonWebKey.import_key_set(r.json())
           _jwks_cache[jwks_uri] = (key_set, now + ttl)
           return key_set
   ```

3. Replace `_extract_claims` with a version that verifies the signature:

   ```python
   async def _extract_claims(id_token: str, jwks_uri: str) -> dict:
       """Verify the ID token signature and return its claims.

       Raises:
           HTTPException(401): on signature failure or claim validation failure.
       """
       try:
           key_set = await _fetch_jwks(jwks_uri)
           claims = authlib_jwt.decode(id_token, key_set)
           claims.validate()   # validates exp, iat, iss, aud
           return dict(claims)
       except Exception as exc:
           logger.warning("oidc | event=id_token_invalid | error=%s", exc)
           raise HTTPException(
               status_code=status.HTTP_401_UNAUTHORIZED,
               detail="ID token signature verification failed",
           )
   ```

   Note: `claims.validate()` in authlib checks `exp`, `iat`, and optionally `iss`
   and `aud` if you pass `claims_options` — see authlib docs for RFC 7519 / OIDC
   Core 1.0 Section 3.1.3.7.

4. In `oidc_callback`, pass the JWKS URI to `_extract_claims`:

   ```python
   # After discovery dict is loaded:
   jwks_uri = discovery["jwks_uri"]
   # ...
   claims = await _extract_claims(id_token, jwks_uri)
   ```

   Change the call site from `_extract_claims(id_token)` to
   `await _extract_claims(id_token, jwks_uri)`.

**Test requirements** (add to `management/tests/test_oidc.py`):

- Generate a real RS256 key pair in the test using `cryptography`:
  ```python
  from cryptography.hazmat.primitives.asymmetric import rsa
  from cryptography.hazmat.primitives import serialization
  private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  ```
- Sign a test `id_token` with the private key using `authlib.jose.jwt.encode()`.
- Mock `_fetch_jwks` to return a `JsonWebKey.import_key_set(...)` from the public key.
- Assert `_extract_claims` succeeds with the signed token.
- Assert `_extract_claims` raises HTTP 401 when the signature is from a different key.
- Assert `_extract_claims` raises HTTP 401 when the token is expired (`exp` in the past).

**Acceptance criteria**:
- `_extract_claims` raises HTTP 401 on invalid signature.
- `_extract_claims` raises HTTP 401 on expired token.
- JWKS are cached: a second call to `_extract_claims` with the same `jwks_uri` does
  not trigger a second HTTP request to the JWKS endpoint.
- TTL defaults to 3600s; respects `Cache-Control: max-age=N` if present.

---

## Gap 2 — SSO Login Events Not Audited

**Files**: `management/api/routes/saml.py`, `management/api/routes/oidc.py`

**Problem**: Successful SAML ACS and OIDC callback logins are logged at INFO level
but are NOT written to `management:audit_log`.  SOC 2 evidence requires all login
events to appear in the audit trail.

**Fix**:

In `saml.py` — add the import:
```python
from ..auth import _client_ip, _create_access_token   # _client_ip was missing
from ..audit_utils import write_audit
```

In `saml_acs`, after the `response.set_cookie(...)` call and before `return response`:
```python
await write_audit(
    redis,
    actor_id=nameid,
    actor_ip=_client_ip(request),
    action_type="sso.login",
    resource_type="session",
    role=role.value,
    after_value={"provider": "saml"},
)
```

In `oidc.py` — add the import:
```python
from ..auth import _client_ip, _create_access_token   # _client_ip was missing
from ..audit_utils import write_audit
```

In `oidc_callback`, after the `response.set_cookie(...)` call and before `return response`:
```python
await write_audit(
    redis,
    actor_id=sub,
    actor_ip=_client_ip(request),
    action_type="sso.login",
    resource_type="session",
    role=role.value,
    after_value={"provider": "oidc"},
)
```

`write_audit` signature (from `management/api/audit_utils.py`):
```python
async def write_audit(redis, *, actor_id, actor_ip, action_type, resource_type,
                      resource_id=None, before_value=None, after_value=None,
                      session_id=None, role) -> None:
```
It never raises — failures are swallowed and logged internally.

**Acceptance criteria**:
- After a mocked SAML login, `GET /api/v1/audit` shows an entry with
  `action_type="sso.login"`, `actor_id` equal to the SAML NameID, and the
  correct `actor_ip`.
- Same for OIDC — `actor_id` equals the `sub` claim.
- Tests assert the audit entry exists by checking the fake Redis `management:audit_log`
  key after a successful mock login.

---

## Gap 3 — No DELETE Endpoint for WebAuthn Credentials

**File**: `management/api/routes/webauthn.py`

**Problem**: Users can register multiple WebAuthn credentials but cannot remove
individual ones.  A lost or compromised hardware key cannot be revoked.

**Fix** — add two new routes to `webauthn.py`:

**GET `/auth/mfa/webauthn/credentials`** — list all credential IDs for the caller:

```python
@router.get("/auth/mfa/webauthn/credentials")
async def webauthn_list_credentials(
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> JSONResponse:
    identity, role = current_user
    user_id = identity.removeprefix("token:")
    credential_ids = await redis.smembers(_user_credentials_key(user_id))
    result = []
    for cid in credential_ids:
        fields = await redis.hgetall(_credential_key(cid))
        result.append({
            "credential_id": cid,
            "created_at": fields.get("created_at"),
        })
    return JSONResponse(content={"credentials": result})
```

**DELETE `/auth/mfa/webauthn/credentials/{credential_id_b64}`** — remove one credential:

```python
@router.delete("/auth/mfa/webauthn/credentials/{credential_id_b64}", status_code=204)
async def webauthn_delete_credential(
    credential_id_b64: str,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> Response:
    identity, role = current_user
    user_id = identity.removeprefix("token:")
    cred = await redis.hgetall(_credential_key(credential_id_b64))
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    if cred.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Credential does not belong to this user")
    pipe = redis.pipeline()
    pipe.delete(_credential_key(credential_id_b64))
    pipe.srem(_user_credentials_key(user_id), credential_id_b64)
    await pipe.execute()
    logger.info(
        "mfa | event=webauthn_credential_deleted | user=%s | credential_id=%s",
        user_id, credential_id_b64,
    )
    from fastapi.responses import Response as _Resp
    return _Resp(status_code=204)
```

Helper functions already available: `_credential_key(credential_id_b64)` and
`_user_credentials_key(user_id)`.  Redis keys written:
- `mgmt:webauthn:credential:{id}` (Hash) — deleted
- `mgmt:webauthn:user:{user_id}:credentials` (SET) — member removed via `SREM`

**Acceptance criteria**:
- DELETE returns 204 and removes both the Hash key and the SET entry.
- DELETE on a non-existent credential returns 404.
- DELETE on another user's credential returns 403 (test: seed credential for user B,
  authenticate as user A, attempt delete).
- GET lists all credential IDs + `created_at` for the authenticated user.
- Tests cover all paths using `fakeredis`.

---

## Gap 4 — SSO-Delegated MFA Not Implemented

**Files**: `management/api/routes/saml.py`, `management/api/routes/oidc.py`

**Problem**: When a user authenticates via SAML or OIDC, the IdP may have already
enforced MFA.  The current implementation still requires the user to complete TOTP
or WebAuthn after SSO login, even when the IdP has asserted MFA.

**Important implementation note**: `_set_mfa_verified` is defined in
`management/api/routes/mfa_totp.py` (line 76) but is a module-private function
(underscore-prefixed, not exported).  Do NOT import it cross-module.  Instead,
implement the MFA session mark inline using the exported `mfa_session_key` function
from `management.api.auth`:

```python
# In saml.py and oidc.py — add to existing auth import:
from ..auth import _create_access_token, _client_ip, mfa_session_key
```

**Fix**:

1. Add env var guard (check at top of `saml_acs` / `oidc_callback`, after role mapping):

   ```python
   trust_idp_mfa = os.environ.get("MANAGEMENT_SSO_TRUST_IDP_MFA", "false").lower() == "true"
   ```

2. In `saml_acs`, detect IdP-asserted MFA using `auth.get_last_authn_contexts()` after
   `auth.is_authenticated()` returns True:

   ```python
   idp_asserted_mfa = False
   if trust_idp_mfa:
       authn_contexts = auth.get_last_authn_contexts() or []
       MFA_CONTEXTS = {
           "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract",
           "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken",
           # Note: PasswordProtectedTransport is single-factor — do NOT include it
       }
       idp_asserted_mfa = bool(set(authn_contexts) & MFA_CONTEXTS)
   ```

3. In `oidc_callback`, detect IdP-asserted MFA from the ID token `amr` claim:

   ```python
   idp_asserted_mfa = False
   if trust_idp_mfa:
       amr = claims.get("amr") or []
       if isinstance(amr, str):
           amr = [amr]
       idp_asserted_mfa = bool(set(amr) & {"mfa", "otp", "hwk", "swk"})
   ```

4. After `token = _create_access_token(...)` and before the cookie is set, mark MFA
   verified if the IdP asserted it:

   ```python
   _MFA_SESSION_TTL = 8 * 3600
   if idp_asserted_mfa:
       await redis.set(mfa_session_key(token), "verified", ex=_MFA_SESSION_TTL)
       logger.info("sso | event=idp_mfa_trusted | user=%s | provider=saml|oidc", sub_or_nameid)
   ```

   `token` here is the string returned by `_create_access_token(...)` — it is
   available locally in both `saml_acs` and `oidc_callback` before the cookie is set.

**Acceptance criteria**:
- With `MANAGEMENT_SSO_TRUST_IDP_MFA=true` and a SAML response containing an MFA
  authn context, `mgmt:mfa:session:{sha256(token)}` exists in Redis after login.
- With the flag `false` (default), the key is not set.
- Same for OIDC with `amr` claim containing `"mfa"`.
- Tests mock the authn context / `amr` claim and assert Redis state.

---

## Gap 5 — SAML / OIDC Integration Test Markers Missing

**Files**:
- `/home/sean/LLM/JA4proxy4/pyproject.toml` (root-level, NOT under `management/`)
- `management/tests/test_saml.py`
- `management/tests/test_oidc.py`

**Problem**: The `integration` pytest marker is not registered, so future live-IdP
tests would produce `PytestUnknownMarkWarning`.

**Fix**:

1. In `pyproject.toml`, append to the existing `markers` list under
   `[tool.pytest.ini_options]` (the list already contains `"live_services: ..."`):

   ```toml
   markers = [
       "live_services: requires live Go/Python proxy and Redis; excluded from make test (use make test-live)",
       "integration: requires live external IdP (Okta, Entra ID, Keycloak); set OKTA_METADATA_URL or ENTRA_OIDC_DISCOVERY_URL",
   ]
   ```

2. Add placeholder integration tests at the **bottom** of `management/tests/test_saml.py`:

   ```python
   import os
   import pytest

   @pytest.mark.integration
   @pytest.mark.skipif(
       not os.environ.get("OKTA_METADATA_URL"),
       reason="OKTA_METADATA_URL not set — live Okta test skipped",
   )
   async def test_saml_live_okta_login():
       """Placeholder: end-to-end login against live Okta SAML IdP.

       To run: OKTA_METADATA_URL=https://... pytest -m integration
       """
       pytest.skip("Not yet implemented — stub for future live-IdP test")
   ```

3. Add placeholder integration tests at the **bottom** of `management/tests/test_oidc.py`:

   ```python
   @pytest.mark.integration
   @pytest.mark.skipif(
       not os.environ.get("ENTRA_OIDC_DISCOVERY_URL"),
       reason="ENTRA_OIDC_DISCOVERY_URL not set — live Entra ID test skipped",
   )
   async def test_oidc_live_entra_login():
       """Placeholder: end-to-end login against live Microsoft Entra ID OIDC.

       To run: ENTRA_OIDC_DISCOVERY_URL=https://login.microsoftonline.com/... pytest -m integration
       """
       pytest.skip("Not yet implemented — stub for future live-IdP test")
   ```

**Acceptance criteria**:
- `pytest -m "not integration"` produces no `PytestUnknownMarkWarning` and skips both
  placeholder tests.
- `pytest -m integration` without `OKTA_METADATA_URL` / `ENTRA_OIDC_DISCOVERY_URL`
  skips both tests (not fails).

---

## Gap 6 — Group-to-Role Mapping via config/proxy.yml Not Wired

**Files**: `management/api/routes/saml.py`, `management/api/routes/oidc.py`

**Problem**: Role mapping is read only from env vars (`MANAGEMENT_SAML_ROLE_MAPPING`,
`MANAGEMENT_OIDC_ROLE_MAPPING`).  The Phase 79 spec also requires honouring the
`sso.role_mapping` section of `config/proxy.yml`.

**Important context**: The management service currently has NO reader for
`config/proxy.yml`.  There is no shared config-loader module.  The proxy config
file is mounted read-only inside Docker at `/config/proxy.yml`.  This is the only
path the management container will ever see it at.

**Fix**:

1. Add `pyyaml` to `management/requirements.txt`:
   ```
   pyyaml>=6.0.0  # phase-100: proxy.yml SSO role mapping
   ```

2. Add a module-level config reader to a new file
   `management/api/proxy_config.py`:

   ```python
   """Read-only accessor for config/proxy.yml (mounted at /config/proxy.yml in Docker)."""
   import logging
   import os
   import time
   from typing import Any

   try:
       import yaml
   except ImportError:
       yaml = None  # type: ignore

   logger = logging.getLogger(__name__)

   _CONFIG_PATH = os.environ.get("MANAGEMENT_PROXY_CONFIG_PATH", "/config/proxy.yml")
   _cache: tuple[dict, float] | None = None
   _CACHE_TTL = 60.0  # reload at most once per minute


   def _load_proxy_config() -> dict:
       """Load proxy.yml with 60s caching.  Returns {} if file missing or unreadable."""
       global _cache
       now = time.monotonic()
       if _cache is not None and now - _cache[1] < _CACHE_TTL:
           return _cache[0]
       if yaml is None:
           return {}
       try:
           with open(_CONFIG_PATH) as f:
               data = yaml.safe_load(f) or {}
           _cache = (data, now)
           return data
       except FileNotFoundError:
           logger.debug("proxy_config | config not found at %s", _CONFIG_PATH)
           return {}
       except Exception as exc:
           logger.warning("proxy_config | load_failed | path=%s | error=%s", _CONFIG_PATH, exc)
           return {}


   def get_sso_role_mapping() -> dict[str, str]:
       """Return merged SSO role mapping: config.yml base + env var overrides.

       Env var (JSON) takes precedence over config.yml entries for the same group.
       This function is used by both saml.py and oidc.py.
       """
       config = _load_proxy_config()
       base: dict[str, Any] = (config.get("sso") or {}).get("role_mapping") or {}
       return {str(k): str(v) for k, v in base.items()}
   ```

3. In `_map_role` in **both** `saml.py` and `oidc.py`, load the config-file mapping
   and merge with the env var mapping (env var wins):

   ```python
   from ..proxy_config import get_sso_role_mapping

   def _map_role(groups: list[str]) -> Optional[Role]:
       # Env var mapping (JSON)
       env_raw = os.environ.get("MANAGEMENT_SAML_ROLE_MAPPING", "{}")  # or OIDC variant
       try:
           env_mapping: dict = json.loads(env_raw)
       except json.JSONDecodeError:
           env_mapping = {}

       # Config-file base; env var overrides
       role_mapping: dict = {**get_sso_role_mapping(), **env_mapping}
       # ... rest of function unchanged
   ```

   Config structure in `config/proxy.yml` (`# phase-100` comment required):
   ```yaml
   sso:                       # phase-100
     role_mapping:            # phase-100
       "SOC-Analysts": analyst       # phase-100
       "Security-Admins": admin      # phase-100
   ```

**Hot-reload**: `get_sso_role_mapping()` caches for 60s and reloads on next call after
expiry.  No explicit SIGHUP wiring is needed at this stage — the proxy.yml hot-reload
path in the proxy itself does not affect the management container.

**Acceptance criteria**:
- Role mapping in `config/proxy.yml` is honoured when env var is absent.
- Env var entry for the same group overrides config file entry.
- Missing or malformed `config/proxy.yml` silently falls back to env-var-only mapping.
- Tests set `MANAGEMENT_PROXY_CONFIG_PATH` to a temp file with a known mapping and
  assert the correct role is returned.

---

## Gap 7 — OpenAPI 3.1 Spec (`docs/api/openapi.yaml`)

**Status**: Deferred from Phase 79 C10.

**Why this matters**: The Terraform provider (Phase 83) and SDK generation tooling
consume this spec.  FastAPI auto-generates OpenAPI 3.0.x at `/api/docs`; the
requirement is a committed, static 3.1 file.

**Fix**:

1. Create `management/scripts/export_openapi.py`:

   ```python
   #!/usr/bin/env python3
   """Export the management API OpenAPI 3.1 spec to docs/api/openapi.yaml.

   Usage:
       MANAGEMENT_TEST_MODE=1 python management/scripts/export_openapi.py
   """
   import json
   import sys
   import os
   import yaml

   # Ensure management package is importable
   sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
   os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")

   from management.api.main import app

   schema = app.openapi()
   # FastAPI generates OpenAPI 3.0.x — bump to 3.1.0
   schema["openapi"] = "3.1.0"

   output_path = os.path.join(
       os.path.dirname(__file__), "../../docs/api/openapi.yaml"
   )
   os.makedirs(os.path.dirname(output_path), exist_ok=True)
   with open(output_path, "w") as f:
       yaml.dump(schema, f, allow_unicode=True, sort_keys=False)

   print(f"Written: {output_path}")
   ```

2. Create `docs/api/` directory if it does not exist.

3. Run the script and commit the generated file:
   ```bash
   MANAGEMENT_TEST_MODE=1 python management/scripts/export_openapi.py
   git add docs/api/openapi.yaml management/scripts/export_openapi.py
   ```

4. Add a Makefile target at the bottom of `Makefile`:
   ```makefile
   ## Phase 100 targets
   openapi-spec:
   	MANAGEMENT_TEST_MODE=1 python management/scripts/export_openapi.py
   ```

**Note on 3.0 → 3.1 differences**: The main schema change is the `openapi` version
field.  For strict 3.1 compliance, `nullable: true` fields should become
`type: ["string", "null"]` — but this is an optional cleanup; the version bump alone
satisfies the downstream tooling requirement for Phase 83/84.

**Acceptance criteria**:
- `docs/api/openapi.yaml` exists and contains `openapi: 3.1.0`.
- All Phase 79 routes are present: verify these paths appear in the spec:
  - `/auth/login`, `/auth/logout`
  - `/auth/mfa/totp/setup`, `/auth/mfa/totp/verify`
  - `/auth/mfa/webauthn/register/begin`, `/auth/mfa/webauthn/register/complete`
  - `/auth/mfa/webauthn/auth/begin`, `/auth/mfa/webauthn/auth/complete`
  - `/auth/sso/saml/login`, `/auth/sso/saml/acs`, `/auth/sso/metadata`
  - `/auth/sso/oidc/login`, `/auth/sso/oidc/callback`
- File is valid YAML (parseable with `yaml.safe_load`).
- `make openapi-spec` regenerates the file without errors.

---

## Implementation Order

| Priority | Gap | Effort | Blocker |
|----------|-----|--------|---------|
| P0 | Gap 2 — SSO audit events | ~30 min | None |
| P0 | Gap 1 — OIDC JWKS signature | ~2–3h | Need `cryptography` for test key gen |
| P1 | Gap 3 — WebAuthn credential DELETE | ~1h | None |
| P1 | Gap 4 — SSO-delegated MFA | ~2h | None |
| P2 | Gap 5 — Integration test markers | ~20 min | None |
| P2 | Gap 7 — OpenAPI spec | ~30 min | None |
| P3 | Gap 6 — config.yml role mapping | ~3–4h | Requires `pyyaml` dep |

---

## New Test File Locations

| Gap | Test additions |
|-----|----------------|
| Gap 1 | `management/tests/test_oidc.py` — new section for JWKS tests |
| Gap 2 | `management/tests/test_saml.py` and `test_oidc.py` — assert audit entry |
| Gap 3 | `management/tests/test_webauthn.py` — new section for list/delete |
| Gap 4 | `management/tests/test_saml.py` and `test_oidc.py` — MFA trust flag tests |
| Gap 5 | Bottom of `test_saml.py` and `test_oidc.py` |
| Gap 6 | `management/tests/test_proxy_config.py` (new file) |
| Gap 7 | No test; run `make openapi-spec` and inspect output |

---

## Dependencies

- Phase 79 (must be COMPLETE first — this phase closes its gaps)
- Phase 83 (Terraform provider) benefits from Gap 7 (OpenAPI spec)
- Phase 84 (Compliance Reporting) benefits from Gap 2 (audit events)

---

## Close-Out Checklist

- [ ] All 7 gaps implemented (or explicitly re-deferred with justification in notes)
- [ ] `make test-unit` passes
- [ ] `CHANGELOG.md` prepended
- [ ] `docs/phases/manifest.yaml` status set to `COMPLETE`
- [ ] `python3 scripts/sync-roadmap.py` run — commit TODO.md + PROJECT_STATUS.md
- [ ] Branch pushed: `git push origin claude/phase-100-sso-mfa-gap-closure`

---

*Created: 2026-04-07*
*Source: Phase 79 C7–C9 critical review*
*Revised: 2026-04-07 — added per-function detail, correct import paths, test patterns*
