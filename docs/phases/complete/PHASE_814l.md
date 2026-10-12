# Pentest: Cryptography and Secrets

> Sub-phase 814l of the Phase 814 penetration testing programme (`PHASE_814.md` §5).
> Preceded by Phase 814k (Data Layer — Redis, Analytics Stream, Backup/Restore).

## 1. Goal

Execute an adversarial penetration test of JA4proxy's cryptography, secrets, authentication tokens, and TLS lockdown posture:
1. **JWT & Identity Assertion Integrity**: Audit JWT creation, signing, algorithm validation (none algorithm, symmetric/asymmetric confusion, kid injection), expiry, and clock-skew handling across Management API, OIDC, and SAML endpoints.
2. **Replay Windows & Single-Use Semantics**: Test whether SAML assertions, OAuth state parameters, WebAuthn MFA challenges, and control-plane HMAC tokens can be replayed or reused concurrently across sessions.
3. **Constant-Time Verification**: Verify constant-time comparison is strictly applied across all HMAC and credential validation sites (webhook delivery, pub/sub, GetDial, CSRF, login, and EDL).
4. **CSPRNG Sourcing**: Verify all cryptographic keys, nonces, session identifiers, and salt generation derive from cryptographically secure pseudorandom number generators (`secrets` in Python, `crypto/rand` in Go) with zero fallback to pseudo-random engines.
5. **Committed Defaults & Boot Guards**: Conduct a systemic audit across all configuration files, environment templates, and compose definitions for committed default credentials, and verify boot guards fail closed against all known defaults in production.
6. **TLS Lockdown**: Verify TLS version and cipher suite lockdown for Management listener sidecars, Redis mTLS/TLS connections, and confirm the proxy path remains pure passthrough without terminating TLS.

---

## 2. Scope

### In Scope
- `management/api/routes/saml.py`: SAML authentication response handling, assertion lifetime, assertion replay detection, and RelayState nonce verification.
- `management/api/routes/oidc.py`: OIDC ID token validation, algorithm allowlisting, and OAuth state single-use consumption.
- `management/api/routes/webauthn.py`: WebAuthn registration/authentication challenges and single-use validation.
- `management/api/main.py`: `_enforce_strong_secrets()` and startup credential validation for JWT, admin credentials, and Redis passwords.
- `internal/config/loader.go`: `ValidateRedisAuth()` and rejection of known-default / placeholder passwords for remote connections.
- `deploy/caddy/Caddyfile.management`: Management listener TLS protocol lockdown.
- `docs/security/findings.yaml`: Registration of findings `JA4PROXY-2026-0124`, `JA4PROXY-2026-0125`, `JA4PROXY-2026-0126`.

### Out of Scope
- Go proxy TLS inspection logic (tested in Phase 814h / 814i).
- External IdP infrastructure (tested via authenticated mocks).

---

## 3. Discovered Findings & Threat Vectors

### Finding 1: SAML Assertion Replay Vulnerability in Management API ACS Endpoint (JA4PROXY-2026-0124)
- **Severity**: HIGH (CVSS 7.5 - `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`)
- **Vector**: `management/api/routes/saml.py` receives and validates SAML responses at `/auth/sso/saml/acs`. While XML signature and timestamp validation are performed by `python3-saml`, the service does not persist or verify the unique Assertion ID (`auth.get_last_assertion_id()`), nor is `request_id` passed to `process_response`. An attacker intercepting a valid user's SAML response can initiate a fresh SAML login, obtain a valid RelayState nonce, and replay the victim's signed Assertion within its validity window (`NotOnOrAfter`) to mint an authenticated session as the victim, and even inherit MFA trust if `MANAGEMENT_SSO_TRUST_IDP_MFA` is enabled.
- **Remediation**:
  1. Extract `assertion_id = auth.get_last_assertion_id()` upon successful authentication.
  2. Compute assertion TTL from `auth.get_last_assertion_not_on_or_after()` (or default 600s).
  3. Atomically record `mgmt:saml:assertion:{assertion_id}` in Redis using `SET NX`. If the key already exists, reject the assertion with `401 Unauthorized` ("SAML assertion has already been used (replay detected)").

### Finding 2: Committed-Default Secrets Permitted by Production Boot Guard and Remote Redis Validation (JA4PROXY-2026-0125)
- **Severity**: HIGH (CVSS 7.4 - `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`)
- **Vector**: The Phase 522 boot guard `_enforce_strong_secrets()` in `management/api/main.py` only checked `MANAGEMENT_JWT_SECRET` and `MANAGEMENT_ADMIN_PASSWORD == "changeme"`. It completely omitted checks on `REDIS_PASSWORD` (and passwords inside `REDIS_URL`), allowing the management API to boot in production with committed default credentials (`changeme`, `REPLACE_ME_SECURELY`, `change_me_redis_strong_password`). Similarly, in the Go proxy (`internal/config/loader.go` `ValidateRedisAuth`), remote Redis connections with password `changeme` or template placeholders passed validation. Furthermore, placeholder secrets from `template.env` (`REPLACE_ME_SECURELY`) were not rejected for admin passwords.
- **Remediation**:
  1. In `management/api/main.py`: Expand `_enforce_strong_secrets()` to check `REDIS_PASSWORD` and extracted passwords from `REDIS_URL` against known committed defaults (`changeme`, `REPLACE_ME_SECURELY`, `change_me_redis_strong_password`, `test-fixtures-pw`) when `is_production()` is true. Also reject placeholder passwords (`REPLACE_ME_SECURELY`, `change_me_admin_password`, `admin`, `password`) for `MANAGEMENT_ADMIN_PASSWORD`.
  2. In `internal/config/loader.go`: Expand `ValidateRedisAuth()` to reject known committed defaults (`changeme`, `REPLACE_ME_SECURELY`, `change_me_redis_strong_password`, `test-fixtures-pw`) for non-local Redis hosts unless `JA4PROXY_ALLOW_UNAUTH_REDIS=1`.

### Finding 3: Non-Atomic Single-Use Nonce and Challenge Verification Race Condition (JA4PROXY-2026-0126)
- **Severity**: MEDIUM (CVSS 5.3 - `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Vector**: In `management/api/routes/saml.py` (RelayState nonce), `management/api/routes/oidc.py` (OAuth state), and `management/api/routes/webauthn.py` (MFA challenge), single-use values were read with `redis.get()` followed subsequently by `redis.delete()`. This introduces a TOCTOU race condition where concurrent HTTP requests presenting the identical nonce or challenge can both pass verification before either deletion executes.
- **Remediation**:
  1. Use atomic `redis.getdel(key)` in `saml.py` for RelayState nonce consumption.
  2. Use atomic `redis.getdel(key)` in `oidc.py` for OAuth state consumption.
  3. Use atomic `redis.getdel(key)` in `webauthn.py` `_load_challenge()` for WebAuthn challenge consumption.

---

## 4. Implementation Plan

1. **Fix JA4PROXY-2026-0124 (SAML Assertion Replay)**:
   - In `management/api/routes/saml.py`:
     - After `auth.is_authenticated()`, extract `assertion_id = auth.get_last_assertion_id()`.
     - Calculate TTL from `auth.get_last_assertion_not_on_or_after()` (fallback to 600 seconds).
     - Call `await redis.set(f"mgmt:saml:assertion:{assertion_id}", nameid, ex=ttl, nx=True)`.
     - If `set(..., nx=True)` returns false/None, reject with `HTTPException(401, detail="SAML assertion has already been used (replay detected)")`.
     - Add regression tests verifying replay rejection and two-state revert proof.

2. **Fix JA4PROXY-2026-0125 (Committed-Default Secrets in Boot Guard & Redis Validation)**:
   - In `management/api/main.py`:
     - Add set of known weak/committed placeholder credentials `_COMMITTED_INSECURE_SECRETS`.
     - Check `REDIS_PASSWORD` and URL password in `_build_redis_url()`.
     - Check `MANAGEMENT_ADMIN_PASSWORD` against all placeholders.
   - In `internal/config/loader.go`:
     - Check `cfg.Redis.Password` against known committed defaults (`changeme`, `REPLACE_ME_SECURELY`, etc.) in `ValidateRedisAuth()`.
   - Add comprehensive regression tests in Go and Python.

3. **Fix JA4PROXY-2026-0126 (Atomic Nonce/Challenge Consumption)**:
   - In `management/api/routes/saml.py`: replace separate `get` + `delete` with `await redis.getdel(f"mgmt:saml:nonce:{nonce}")`.
   - In `management/api/routes/oidc.py`: replace separate `get` + `delete` with `await redis.getdel(f"mgmt:oidc:state:{state}")`.
   - In `management/api/routes/webauthn.py`: replace separate `get` + `delete` in `_load_challenge()` with `await redis.getdel(_challenge_key(user_id))`.
   - Add unit tests verifying atomic single-use semantics.

4. **Lockdown Caddy Management Listener**:
   - In `deploy/caddy/Caddyfile.management`: configure `protocols tls1.2 tls1.3`.

---

## 5. Test Strategy & Revert Proofs

- **Regression Unit Tests**:
  - `management/tests/test_pentest_saml_replay_regression.py`: Replay the same signed assertion across two logins with fresh RelayStates; assert second attempt fails with 401 Replay Detected.
  - `management/tests/test_pentest_committed_secrets_boot_guard_regression.py`: Test all permutations of `ENVIRONMENT` against committed secrets for JWT, Admin password, and Redis password.
  - `internal/config/pentest_committed_redis_password_regression_test.go`: Test Go proxy rejection of committed Redis passwords on non-local hosts.
  - `management/tests/test_pentest_atomic_nonces_regression.py`: Verify concurrent calls to `getdel` across SAML, OIDC, and WebAuthn.
- **Two-State Revert Verification**:
  - Execute `scripts/verify_revert.sh` for each finding to prove test sensitivity.

---

## 6. Acceptance Criteria

- [ ] All three findings registered in `findings.yaml` with linked GitHub issues.
- [ ] SAML assertion replay attack fails closed with 401.
- [ ] Management boot guard rejects committed Redis and Admin passwords in production.
- [ ] Go proxy `ValidateRedisAuth` rejects committed default Redis passwords on remote hosts.
- [ ] Single-use nonces and challenges are consumed atomically via `GETDEL`.
- [ ] Caddyfile management listener explicitly restricts to TLS 1.2 and 1.3.
- [ ] Two-state regression tests pass and fail on revert.
- [ ] Expert reviews (Security, Concurrency, Code Quality) all APPROVE.
- [ ] Preflight and CI gates green.
