# Pentest: Management API and UI (WSTG / ASVS L2 / API Top 10)

## Goal

Execute a comprehensive adversarial penetration test of JA4proxy's complete control plane — the Python/FastAPI Management API (`management/api/`), Management Web UI (`management/ui/`), and setup Wizard CLI tools (`internal/wizard/` and `scripts/setup_wizard.py`). Evaluate authorization boundaries (BOLA/BFLA across every role, unauthenticated access, and step-up MFA states), modern authentication mechanics (OIDC token validation with strict `aud`/`iss` binding, WebAuthn challenge/origin binding with clone detection, TOTP replay resistance, and cryptographic SAML assertion signature verification against XML Signature Wrapping), session lifecycle management, request validation (CSRF coverage across all mutating routes, egress SSRF with DNS rebinding and redirect defense, and path traversal), control plane weaponisation safety (infrastructure ban self-DoS, dial manipulation, and webhook relay abuse), and client-side rendering security (XSS, CSP, vendored JS vulnerabilities). Every finding must adhere to the 12-section fix-specification standard (`PROGRAMME.md` §9) and include a verified two-state regression proof.

## Scope

### In Scope
1. **Comprehensive RBAC Matrix Testing (BOLA, BFLA & Step-Up MFA):**
   - Systematically evaluate every route across the complete FastAPI route table across 9 distinct principal states:
     - Unauthenticated
     - Anonymous / malformed token
     - Expired token
     - Revoked token (`mgmt:token:*`)
     - Token minted for incorrect audience / issuer (`aud`/`iss`)
     - `analyst` role
     - `auditor` role
     - `operator` role
     - `admin` role with valid primary JWT but missing / expired step-up MFA session
     - `admin` role with full MFA verification
   - Broken Object Level Authorization (BOLA): verify whether lower-privileged tenants/principals can access, modify, or delete arbitrary configuration, snapshots, API tokens, or audit records.
   - Broken Function Level Authorization (BFLA): verify whether read-only roles (`auditor`, `analyst`) can reach mutating endpoints or trigger privileged operations.
   - Step-Up MFA Enforcement: verify that sensitive administrative actions requiring `require_mfa_verified` (e.g. `POST /api/v1/attack-mode`, `DELETE /api/v1/ip/{ip}/offense`, credential manipulation) strictly fail for non-MFA verified admin sessions.

2. **Authentication Security & Cryptographic Verifications:**
   - **OIDC Discovery & JWT Validation (Absorbed Phase 523 item 1):** Rigorous verification of `aud` (audience) and `iss` (issuer) enforcement — ensure a validly signed token issued by a trusted IdP for a *different* application/client is rejected. Validate that OIDC discovery endpoint configuration rejects SSRF targeting internal cloud metadata.
   - **WebAuthn / Passkeys (Absorbed Phase 523 item 2):** Strict verification of `origin` and `rpId` binding (rejecting port/host mismatches against `MANAGEMENT_WEBAUTHN_ORIGIN`), replay resistance of challenge nonces, single-use challenge consumption in Redis, and authenticator clone detection (`sign_count`).
   - **SAML 2.0 Cryptographic Integrity:** Real cryptographic verification of XML digital signatures using X.509 RSA test IdP keys. Rigorous testing of assertion signature wrapping (XSW 1–8), untrusted cert injection, replay of `RelayState` nonces, and expiration handling with `MANAGEMENT_SAML_STRICT=true`. (Strict prohibition on mock assertion verifications).
   - **TOTP / MFA:** Replay testing within the 30-second window, rate limiting on failed attempts, and brute-force resistance.

3. **Session Lifecycle & Token State Management:**
   - Cookie flags: `HttpOnly`, `Secure`, `SameSite=Lax/Strict`, and path scoping.
   - Session fixation and logout invalidation (guaranteeing immediate revocation in Redis `mgmt:token:*`).
   - Token revocation propagation across distributed proxy/management instances.

4. **Input Validation, CSRF Blind Spots & Egress SSRF:**
   - **Full CSRF Audit:** Audit anti-CSRF protections across *all* state-mutating routes (`POST`, `PUT`, `DELETE`, `PATCH`). Specifically test sensitive mutating endpoints outside the `/api/v1/` prefix (such as `DELETE /auth/mfa/webauthn/credentials/{id}`, `POST /auth/mfa/webauthn/register/complete`, and `POST /auth/mfa/totp/verify`) that rely on session cookies but may bypass `/api/v1/` middleware.
   - **SSRF (Server-Side Request Forgery) & DNS Rebinding:** Adversarial testing of outbound HTTP integrations (`webhooks.py`, `threat_intel.py`, `edl.py`, OIDC discovery endpoints):
     - Internal IP representations (RFC 1918, link-local `169.254.169.254`, IPv6 `[::1]`, IPv4-mapped IPv6 `[::ffff:127.0.0.1]`, decimal/hex notation).
     - DNS rebinding (hosts resolving to public IP on check and loopback/private on connection).
     - HTTP redirect following (asserting redirects to private/internal endpoints are blocked).
   - **Injection Flaws:**
     - Path traversal in configuration backups, snapshot exports, and file-serving routes (`config_ops.py`, `snapshots.py`).
     - Command / template injection in configuration reload and shell-assisted workflows.
     - Header injection and log poisoning (CRLF in audit trails).

5. **Control Plane Weaponisation & Operational Safety:**
   - **Infrastructure Ban Weaponisation (Self-DoS):** Test whether an attacker or low-privileged role can inject bans targeting default gateways, internal DNS resolvers, loopback `127.0.0.1`, `0.0.0.0/0`, or administrator subnets, causing self-inflicted proxy outages.
   - **Dial Weaponisation (False-Positive Avalanche):** Test whether a non-admin role can trigger Attack Mode or modify dialing thresholds (`POST /api/v1/attack-mode`), forcing proxy dialing to 75/100 and inducing widespread false-positive blocking of legitimate traffic.
   - **Outbound Webhook Relay & Amplification:** Test whether webhook configurations can be abused by operators to target third parties or internal cluster components with high-frequency notification floods.

6. **UI & Client-Side Security:**
   - Stored and reflected Cross-Site Scripting (XSS) in all fields rendering untrusted client data (SNI, JA4, User-Agent, Country, Client Certificate DN).
   - Content Security Policy (CSP) headers, frame ancestors (`X-Frame-Options: DENY`), and MIME sniffing controls (`X-Content-Type-Options: nosniff`).
   - Vulnerability scan of vendored third-party frontend JavaScript libraries (`make scan-js` / npm audit).

7. **Audit Trail Integrity:**
   - Verify whether `management:policy_audit` logs can be truncated, bypassed, or forged by any administrative action or concurrent API call.

8. **Setup Wizard Security:**
   - Audit `internal/wizard/` and `scripts/setup_wizard.py` for local file permissions on generated secrets, sensitive credential exposure on stdout/logs, and insecure default password generation.

### Out of Scope
- Direct exploitation of external production IdPs (Okta, Keycloak, Azure AD) — tests execute against mock IdP fixtures within the isolated test range.
- Go proxy dataplane TLS parsing (covered in Phase 814h).
- CI/CD workflow and supply chain attacks (covered in Phase 814f).
- Physical or social engineering attacks against operators.

---

## Personas & Threat Profiles

- **P4: Malicious/Compromised Operator (Insider Threat / Privilege Escalation):**
  - Holds valid credentials for a lower role (`auditor` or `analyst`) or an administrative session lacking step-up MFA.
  - Objective: Escalate to full `admin`, bypass MFA step-up, alter detection rules to allow covert exfiltration, or trigger operational self-DoS via gateway banning.
- **P5: Unauthenticated External Attacker (Perimeter Access):**
  - Reaches the management port (e.g. exposed 8080/8443 or forwarded port).
  - Objective: Bypass authentication via OIDC/SAML flaw, forge session cookies, perform SSRF to pivot into internal cloud metadata, or inject XSS to hijack operator sessions.

---

## Implementation Plan

### Step 1: Automated Full-Matrix RBAC Fuzzer & BOLA/BFLA Scanner
1. Author `tests/adversarial/mgmt/test_rbac_full_matrix.py`:
   - Inspect FastAPI runtime route table (`from management.api.main import app; app.routes`) to guarantee 100% discovery of dynamic routes (resolving `JoinedStr` canonical list endpoints and helper dependency wrappers like `require_admin`).
   - Issue requests across all 9 principal states with valid, invalid, manipulated JWT payloads, and missing MFA sessions.
   - Assert strict 401/403 responses on unauthorized access and verify zero privilege leakage.
2. Author specific BOLA tests across object access endpoints (`/api/v1/snapshots/{id}`, `/api/v1/tokens/{id}`, `/api/v1/rules/{id}`).

### Step 2: Advanced Auth & Cryptographic Deep Dive
1. Author `tests/adversarial/mgmt/test_auth_cryptographic_deepdive.py`:
   - **OIDC:** Mint valid RS256 JWTs with mismatched `aud` (e.g. `aud: other-service`) and mismatched `iss`. Assert immediate 401 rejection. Test OIDC discovery URL injection with loopback and metadata addresses.
   - **WebAuthn:** Inject assertions from mismatched origins (e.g. `http://localhost:8080` vs configured 8090) and attempt challenge replay. Test authenticator clone detection with decremented `sign_count`.
   - **SAML:** Generate real RSA test IdP keys and construct raw XML assertions with altered assertions wrapped outside the signature envelope (XSW 1–8) against `/auth/sso/saml/acs` with `MANAGEMENT_SAML_STRICT=true`. Assert cryptographic verification failure.
   - **TOTP:** Attempt replay of identical TOTP tokens within and across time steps; attempt brute-force token spray and assert exponential backoff / lockout.

### Step 3: CSRF Blind Spots, Egress SSRF, DNS Rebinding & Injection Harness
1. Author `tests/adversarial/mgmt/test_ssrf_and_injection.py`:
   - **CSRF:** Probe mutating non-`/api/v1/` routes (`DELETE /auth/mfa/webauthn/credentials/{id}`, etc.) with session cookies but without CSRF tokens.
   - **SSRF & DNS Rebinding:** Test webhook creation and threat intel download routes against `http://169.254.169.254/latest/meta-data/`, `http://127.0.0.1:6379/`, alternative IP encodings (IPv6, decimal, hex), DNS rebinding servers, and HTTP 302 redirects.
   - **Path Traversal:** Test traversal strings (`../../../../etc/passwd`, `..%2f..%2f`) across snapshot, backup, and static file routes.

### Step 4: Control Plane Weaponisation Safety Suite
1. Author `tests/adversarial/mgmt/test_control_plane_weaponisation.py`:
   - Probe `/api/v1/bans`, `/api/v1/attack-mode`, and `/api/v1/offense`:
     - Assert that triggering ban enforcement strictly validates target IPs to reject default gateways, loopback `127.0.0.1`, `0.0.0.0/0`, and operator CIDRs.
     - Assert that raising dial via Attack Mode requires full admin role with verified step-up MFA.
     - Validate webhook notification limits to prevent reflection or amplification loops against internal services.

### Step 5: Web UI Client-Side & XSS Audit
1. Author `tests/adversarial/mgmt/test_ui_xss_and_csp.py`:
   - Inject persistent XSS payloads (`<script>alert(1)</script>`, `javascript:...`, `onerror=...`) into fields logged and displayed in the UI:
     - Client SNI, JA4, User-Agent, Country, Client Certificate Subject.
   - Assert HTML escaping in all Jinja/FastAPI templates and proper DOM-safe insertion in frontend JavaScript.
   - Assert strict CSP headers: `default-src 'self'`, `script-src 'self'`, no unsafe-inline or unsafe-eval.
   - Run `make scan-js` to check all vendored dependencies against the National Vulnerability Database.

### Step 6: Setup Wizard Security Review
1. Author `tests/adversarial/mgmt/test_wizard_security.py`:
   - Verify permission masks on files generated by `scripts/setup_wizard.py` and `internal/wizard/` (`0600` for keys/secrets).
   - Verify zero leakage of credentials to stdout or unencrypted logs.

### Step 7: Finding Registration & Verification
1. For every confirmed vulnerability:
   - Register finding via `python3 scripts/findings_register.py add ...` allocating canonical `JA4PROXY-2026-XXXX`.
   - Provide a formal 12-section fix specification adhering to `PROGRAMME.md` §9.
   - Provide an executable regression test in `tests/adversarial/` or `tests/unit/`.
   - Validate regression tests via `scripts/verify_revert.sh` (must fail before fix, pass after fix).

---

## Test Strategy

1. **Local Test Execution (Containerized):**
   - Execute all Python adversarial and pentest suites inside `ja4proxy-tools` (Python 3.14 pinned) via `make test-adversarial` or `docker run`.
2. **Isolation & Range Parity:**
   - Validate range setup via `make pentest-range` to ensure verified zero-egress during SSRF and control plane probes.
3. **Regression Proof:**
   - Validate regression tests using `scripts/verify_revert.sh` to ensure every test fails on vulnerable code and passes on secure code.
4. **Preflight CI Gate:**
   - Must achieve 100% green on `make preflight` and `make lint-phases`.

---

## Acceptance Criteria

1. 100% of discovered routes in the FastAPI runtime route table are evaluated across all 9 RBAC/MFA principal matrices with automated test coverage.
2. OIDC `aud`/`iss` validation and WebAuthn origin/challenge bindings are verified with zero bypasses.
3. SAML XML signature wrapping and assertion tampering tests execute against real cryptographic parsers with 100% rejection.
4. All state-mutating endpoints (including `/auth/mfa/*`) are protected against CSRF.
5. SSRF defenses across webhooks, threat feeds, and EDL integrations prevent all access to local, loopback, and metadata endpoints (including via DNS rebinding and HTTP redirects).
6. Operational safety controls prevent banning default gateways, loopback, or broadcast ranges, and dial manipulation requires verified step-up MFA.
7. Web UI templates and API data rendering are proven immune to XSS, and CSP headers meet industry best practices.
8. Setup wizard credentials and files conform to least-privilege permissions (`0600`).
9. All findings are formally registered in `docs/security/findings.yaml` with 12-section fix specifications and regression test paths.
10. Full preflight suite (`make preflight`) passes with 0 failures, 0 lint errors, and 0 warnings.
