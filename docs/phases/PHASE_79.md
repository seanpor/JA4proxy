# Phase 79: Management API v2, RBAC & Enterprise Identity

> **This is the critical dependency for every other enterprise phase (80–86).**
> Nothing in the enterprise integration stack is possible without a stable,
> well-designed REST API and a proper identity layer. Do this first.

---

## 1. Overview

Phase 13 delivered the Management UI backend API (FastAPI, single-admin JWT cookies,
Jinja2 frontend). This phase upgrades it to a production-grade API designed explicitly
for enterprise integration: machine-readable, stable, fully authenticated, role-scoped,
and audit-logged.

**What changes from Phase 13:**

| Concern | Phase 13 | Phase 79 |
|---------|----------|----------|
| Auth model | Single admin, cookie JWT | Bearer tokens (API) + cookie JWT (browser), 4 roles |
| Identity | Hard-coded env-var username | SAML 2.0 + OIDC SSO with group-to-role mapping |
| MFA | None | TOTP (required) + WebAuthn/FIDO2 (required for Admin/Operator) |
| Resources | Plain Redis strings | UUID-keyed resources with `managed_by` field |
| API surface | 10 endpoints | 22+ endpoints; RFC 7807 errors throughout |
| Nodes | Not tracked | Heartbeat-based node registry |
| Webhooks | None | Webhook subscription management |

**What does NOT change:** the existing Phase 13/51/52 endpoints
(`/api/v1/lists/...`, `/api/v1/bans/...`, `/api/v1/dial`, etc.) remain fully
operational. Phase 79 adds the new canonical routes alongside them; the old routes are
deprecated but not removed. The Jinja2 frontend continues to work unchanged.

---

## 2. Management REST API

### 2.1 Design Principles

- **Stable IDs**: every resource has a stable UUID. Tags and names are mutable; IDs
  are not. JA4 fingerprints remain the natural lookup key but each entry also carries
  a UUID for Terraform state tracking.
- **Full read-back on create/update**: every mutating response returns the full
  resource state. Terraform and SOAR tools require this.
- **Sensible HTTP semantics**: `PUT` for full replacement, `PATCH` for partial update,
  `DELETE` is idempotent (no error on already-deleted resource).
- **Versioned**: all Phase 79 endpoints under `/api/v1/`. Breaking changes increment
  to `/api/v2/`. Old Phase 13 routes (`/api/v1/lists/...`) are deprecated aliases.
- **Machine-first**: every response is JSON. No HTML error pages. Error bodies follow
  RFC 7807 Problem Details: `{ "type", "title", "status", "detail", "instance" }`.

### 2.2 Resource Catalogue

#### Allowlist / Blocklist / Watchlist

| Endpoint | Methods | Description |
|----------|---------|-------------|
| `/api/v1/allowlist` | GET, POST | List / add JA4 fingerprint or IP allowlist entries |
| `/api/v1/allowlist/{id}` | GET, DELETE | Get or remove a specific entry by UUID |
| `/api/v1/blocklist` | GET, POST | List / add JA4 fingerprint blocklist entries |
| `/api/v1/blocklist/{id}` | GET, DELETE | Get or remove a specific entry by UUID |
| `/api/v1/watchlist` | GET, POST, DELETE | Elevated-monitoring tier (no block, extra logging) |

#### Bans

| Endpoint | Methods | Description |
|----------|---------|-------------|
| `/api/v1/bans` | GET, POST | List active bans / add a ban with TTL |
| `/api/v1/bans/{ip}` | GET, DELETE | Get or release a specific ban |
| `/api/v1/bans/cidr/{cidr}` | GET, POST, DELETE | CIDR-level bans |

#### Configuration & Control

| Endpoint | Methods | Description |
|----------|---------|-------------|
| `/api/v1/dial` | GET, PATCH | Read or update the dial setting (Operator+ role) |
| `/api/v1/config` | GET, PATCH | Read or hot-reload editable config fields |
| `/api/v1/config/validate` | POST | Validate a proposed config body without applying |

#### Observability

| Endpoint | Methods | Description |
|----------|---------|-------------|
| `/api/v1/health` | GET | Basic health (LB health checks — no auth required) |
| `/api/v1/health/deep` | GET | Deep health: Redis connectivity, signal modules, cert expiry |
| `/api/v1/ready` | GET | Readiness: GeoIP loaded, config valid, Redis reachable |
| `/api/v1/metrics/summary` | GET | JSON summary of key metrics (dashboards, not Prometheus scrape) |
| `/api/v1/connections` | GET | Query `ja4proxy:events` stream (`?ip=`, `?ja4=`, `?since=`, `?limit=`) |
| `/api/v1/fingerprints/{ja4}` | GET | Fingerprint detail: history, associated IPs, risk signals |
| `/api/v1/fingerprints/{ja4}/history` | GET | Timeline of all connections using this fingerprint |

#### Infrastructure

| Endpoint | Methods | Description |
|----------|---------|-------------|
| `/api/v1/nodes` | GET | All proxy nodes in the deployment, health and version |
| `/api/v1/nodes/{host}/reload` | POST | Trigger config reload on a specific node via Redis pub/sub |

#### Identity / Admin

| Endpoint | Methods | Description |
|----------|---------|-------------|
| `/api/v1/audit` | GET | Audit log entries (`?since=`, `?actor=`, `?action=`) |
| `/api/v1/tokens` | GET, POST | List / create API tokens (Admin role only) |
| `/api/v1/tokens/{id}` | GET, DELETE | Inspect or revoke a token |
| `/api/v1/tokens/{id}/rotate` | POST | Rotate a token (returns new token, grace period for old) |
| `/api/v1/webhooks` | GET, POST | List / create webhook subscriptions |
| `/api/v1/webhooks/{id}` | GET, PUT, DELETE | Inspect, update, or delete a subscription |

### 2.3 Terraform-Friendly Design Requirements

The Terraform provider (Phase 83) depends on:
- **Deterministic `GET` after `POST`**: a resource must be immediately readable by its
  UUID after creation. No eventual consistency windows.
- **`managed_by` field** on every mutable resource: `"terraform"`, `"operator"`,
  `"api"`, `"analytics"`. Allows the Terraform provider to detect out-of-band changes.
- **`?managed_by=terraform` filter** on `GET /api/v1/allowlist` (and blocklist,
  watchlist) so the provider can enumerate only resources it owns.

### 2.4 Resource Model (UUID + managed_by)

All mutable resources share a common envelope:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "entry": "t13d1516h2_8daaf6152771_b186095e22b6",
  "managed_by": "operator",
  "note": "Known good scanner from security team",
  "created_at": "2026-04-07T10:00:00Z",
  "created_by": "alice@corp.com",
  "expires_at": null
}
```

**Redis storage (dual-write pattern):**
- `allowlist:entry:{uuid}` → Redis Hash: full resource data
- `allowlist:idx` → Redis SET of UUIDs (for enumeration)
- `ja4:whitelist` → Redis SET of raw fingerprint strings (kept in sync — the proxy
  still reads this for O(1) hot-path lookups)

The proxy is never changed to read UUIDs. The management API maintains both structures
atomically using a Redis pipeline.

**Migration on first startup:** entries already in `ja4:whitelist`, `ja4:blacklist`,
and `static:allowlist` with no corresponding `allowlist:entry:*` Hash are migrated
automatically. Their UUID is `uuid5(NAMESPACE_DNS, entry_string)`. Their `managed_by`
is `"legacy"`. Migration is idempotent; it sets a `allowlist:migrated` flag to skip
on subsequent startups.

---

## 3. API Authentication

### 3.1 Bearer Tokens (API clients)

All non-browser API access uses `Authorization: Bearer <token>` headers.

Token requirements:
- Scoped to exactly one role (Auditor, Analyst, Operator, or Admin)
- Mandatory expiry: configurable at issuance, maximum 365 days
- The raw token is shown only once at creation time; stored as bcrypt hash in Redis
- Rotatable: `POST /api/v1/tokens/{id}/rotate` returns a new token and invalidates the
  old one after a configurable grace period (default 60 seconds for in-flight requests)
- Every API call attributable to the specific token ID in the audit log

**Redis storage:**
- `mgmt:token:{id}` → Redis Hash: `{id, role, name, hash, created_at, expires_at, last_used_at}`
- `mgmt:token:idx` → Redis SET of token IDs

### 3.2 Session Auth (browser/UI)

Short-lived JWTs (15-minute expiry, 8-hour refresh window). Session tokens are
`httpOnly`, `SameSite=Strict` cookies. CSRF protection via double-submit cookie pattern.

**Fix from Phase 13:** `SameSite=lax` in `auth.py:280` → `SameSite=Strict`.

### 3.3 Auth Middleware

A single FastAPI middleware resolves the caller identity before route handlers run:

1. If `Authorization: Bearer <token>` header present → validate bearer token → resolve role
2. Else if `token` cookie present → validate JWT → resolve role from JWT payload
3. Else → 401

Each route handler declares its minimum role via a dependency:
```python
Depends(require_role(Role.OPERATOR))
```

**Fix from Phase 13:** CORS middleware must include `PATCH` in allowed methods.

---

## 4. SSO — SAML 2.0 and OIDC

Enterprise procurement requires corporate IdP integration. This is a hard gate.

### 4.1 Required Identity Providers

> **GAP — Phase 79**: Okta Developer account and Microsoft Entra ID (M365 Dev Program)
> accounts could not be provisioned. SAML 2.0 integration tests against live IdPs are
> deferred. All SAML/OIDC code will be implemented and unit-tested with mocks; live IdP
> integration tests are marked `@pytest.mark.integration` and skipped until credentials
> are available. OIDC tests against Keycloak Docker **are** CI-runnable and are not
> blocked.

| IdP | Protocol | Test method | Status |
|-----|----------|-------------|--------|
| Okta | SAML 2.0 + OIDC | Okta Developer sandbox | **GAP — no account** |
| Microsoft Entra ID | OIDC | M365 Dev Program sandbox | **GAP — no account** |
| Ping Identity | SAML 2.0 | Generic SAML (same code path as Okta) | Covered by mock |
| Generic SAML 2.0 | SAML 2.0 | Mock IdP in tests | Implemented |
| Generic OIDC | OIDC | Keycloak 24.x in Docker | CI-runnable |

### 4.2 Group-to-Role Mapping

```yaml
# config/proxy.yml
sso:
  provider: okta                    # okta | entra | keycloak | generic_saml | generic_oidc
  metadata_url: "https://dev-12345678.okta.com/app/ja4proxy/sso/saml/metadata"
  oidc_discovery_url: "https://dev-12345678.okta.com/.well-known/openid-configuration"
  client_id: "0oa..."               # OIDC only
  client_secret_env: "OIDC_CLIENT_SECRET"  # read from env, not config file
  role_mapping:
    "SOC-Analysts": analyst
    "SecOps-Operators": operator
    "Security-Admins": admin
    "Audit-Team": auditor
  default_role: null                # null = deny unmapped users
```

When a user is removed from an AD/Okta group, their access is revoked at next login.

### 4.3 Implementation Libraries

- **SAML 2.0**: `python3-saml` (OneLogin) — do not implement SAML from scratch.
  Requires `xmlsec1` system binary in the management container Dockerfile.
- **OIDC**: `authlib>=1.3.0` — handles discovery, PKCE, token validation.
- **SAML session state**: `mgmt:saml:nonce:{nonce}` → String with 5-min TTL
- **OIDC state**: `mgmt:oidc:state:{state}` → String with 5-min TTL

### 4.4 SSO Routes

| Route | Description |
|-------|-------------|
| `GET /auth/sso/saml/login` | Redirect to IdP SAML login |
| `POST /auth/sso/saml/acs` | SAML Assertion Consumer Service (IdP posts here) |
| `GET /auth/sso/oidc/login` | Start OIDC authorization code + PKCE flow |
| `GET /auth/sso/oidc/callback` | OIDC callback; exchange code for tokens |
| `GET /auth/sso/metadata` | Serve SAML SP metadata XML to the IdP |

---

## 5. RBAC — Four Roles

Segregation of duties required for PCI-DSS and SOC 2 evidence. The four-role model
is the minimum viable set.

| Role | Permissions |
|------|-------------|
| **Auditor** | Read-only: all data, export audit logs. Cannot see API token values (only metadata). Cannot modify anything. |
| **Analyst** | Auditor permissions + query connection history and fingerprint timelines. |
| **Operator** | Analyst permissions + add/remove allowlist/blocklist/watchlist entries, add/release bans. Cannot change dial, config, bypass toggles, API tokens, webhooks, or SSO config. |
| **Admin** | Full access: all Operator permissions plus dial changes, config hot-reload, bypass toggles, token management, webhook management, SSO config, user management. |

**Key separation:** Operator cannot change the dial or disable security bypasses.
This is the PCI-DSS 6.6 / SOC 2 CC6.6 segregation of duties evidence.

### 5.1 Role Enforcement

All endpoints enforce role at handler level via `Depends(require_role(role))`.
No superuser that bypasses checks. The local bootstrap admin user has the Admin role.

---

## 6. MFA Enforcement

| Role | MFA requirement |
|------|----------------|
| Admin | Mandatory — cannot be disabled by any config or admin action |
| Operator | Mandatory — cannot be disabled |
| Analyst | Configurable — default required |
| Auditor | Configurable — default optional |

### 6.1 TOTP (Time-based One-Time Password)

- Library: `pyotp>=2.9.0`
- QR code generation: `qrcode[pil]>=7.4.2`
- Setup flow: `GET /auth/mfa/totp/setup` → returns QR code PNG + backup codes
- Verify flow: `POST /auth/mfa/totp/verify` → validates 6-digit code
- TOTP secret stored in `mgmt:totp:{user_id}` → String, encrypted at rest using
  the `MANAGEMENT_MFA_ENCRYPTION_KEY` env var (Fernet)
- Backup codes: 8 one-time codes, bcrypt-hashed, stored in `mgmt:totp:backup:{user_id}`

### 6.2 WebAuthn / FIDO2 (Hardware Keys)

- Library: `py_webauthn>=2.0.0`
- Supports: YubiKey, Titan, any FIDO2 authenticator
- Required for financial services customers

**Registration flow:**
1. `POST /auth/mfa/webauthn/register/begin` → returns challenge JSON (stored in
   `mgmt:webauthn:challenge:{user_id}` with 5-min TTL)
2. Browser calls `navigator.credentials.create()` and POSTs attestation response
3. `POST /auth/mfa/webauthn/register/complete` → verifies attestation, stores credential

**Authentication flow:**
1. `POST /auth/mfa/webauthn/auth/begin` → returns challenge JSON
2. Browser calls `navigator.credentials.get()` and POSTs assertion response
3. `POST /auth/mfa/webauthn/auth/complete` → verifies assertion, issues session token

**Redis storage:**
- `mgmt:webauthn:challenge:{session_id}` → String (JSON), 5-min TTL
- `mgmt:webauthn:credential:{credential_id}` → Hash: `{user_id, public_key, sign_count, created_at}`
- `mgmt:webauthn:user:{user_id}:credentials` → SET of credential IDs

**SSO-delegated MFA:** if the IdP enforces MFA (Okta Verify, Entra ID Authenticator),
JA4proxy trusts the IdP's MFA assertion. No additional MFA challenge is presented.

### 6.3 MFA Routes

| Route | Description |
|-------|-------------|
| `GET /auth/mfa/totp/setup` | Return QR code and backup codes for TOTP enrollment |
| `POST /auth/mfa/totp/verify` | Verify a 6-digit TOTP code |
| `POST /auth/mfa/webauthn/register/begin` | Begin WebAuthn credential registration |
| `POST /auth/mfa/webauthn/register/complete` | Complete WebAuthn credential registration |
| `POST /auth/mfa/webauthn/auth/begin` | Begin WebAuthn authentication |
| `POST /auth/mfa/webauthn/auth/complete` | Complete WebAuthn authentication |

---

## 7. Append-Only Audit Trail

Every API and UI action is written to an append-only audit log.

- **No role can delete or edit entries**, including Admin
- Every entry contains: `timestamp` (UTC ms precision), `actor_id` (email or token ID),
  `actor_ip`, `action_type`, `resource_type`, `resource_id`, `before_value` (JSON),
  `after_value` (JSON), `session_id`, `role`
- Stored in `management:audit_log` Redis Stream, no TTL, maxlen=100,000
- When maxlen reached: oldest entries archived to `audit_archive/YYYY-MM-DD.jsonl`
  flat files (never deleted)
- Exportable via `GET /api/v1/audit?format=jsonl` or `?format=csv` (required for SOC 2)

---

## 8. Node Heartbeat & Registry

The proxy heartbeat allows `GET /api/v1/nodes` to return live cluster state without
requiring a service registry sidecar.

**Proxy side (new):** every proxy instance writes a heartbeat every 30 seconds:
```
HSET mgmt:node:{hostname}:{port}  host {hostname}  port {port}  \
     version {git_sha}  started_at {iso8601}  last_seen {iso8601}  \
     connections_total {int}
EXPIRE mgmt:node:{hostname}:{port} 60
```

**Management API side:** `GET /api/v1/nodes` does `SCAN mgmt:node:*` and reads each
Hash. A node missing a heartbeat for >60s is absent from the response (TTL expired).
`POST /api/v1/nodes/{host}/reload` publishes to the `proxy:control` Redis pub/sub
channel; all proxy instances with that hostname pick it up and run SIGHUP logic.

---

## 9. Webhook Subscriptions

```json
{
  "id": "uuid",
  "url": "https://siem.corp/ingest",
  "events": ["ban.created", "dial.changed", "allowlist.added"],
  "secret": "sha256 HMAC signing key (shown once)",
  "active": true,
  "created_at": "...",
  "managed_by": "operator"
}
```

**Redis storage:**
- `webhook:{id}` → Hash: all fields except secret (stored bcrypt-hashed)
- `webhook:idx` → SET of webhook IDs

Webhook delivery is handled by an async background task (Phase 80 integration).
Phase 79 only implements the subscription CRUD endpoints.

---

## 10. IdP Account Setup Guide

### 10.1 Okta Developer (Free, No Credit Card)

1. Go to `developer.okta.com/signup`
2. Sign up with your email — you get a sandbox tenant (e.g., `dev-XXXXXXXX.okta.com`)
3. In the Okta admin console: **Applications → Create App Integration → SAML 2.0**
   - Single sign-on URL: `http://localhost:8090/auth/sso/saml/acs`
   - Audience URI (SP Entity ID): `ja4proxy`
   - Attribute statements: add `email` and `groups` mappings
4. Download the IdP metadata XML → path goes in `config/proxy.yml`
5. For OIDC: **Applications → Create App Integration → OIDC → Web Application**
   - Redirect URI: `http://localhost:8090/auth/sso/oidc/callback`
   - Note client ID and secret

### 10.2 Microsoft Entra ID (No Credit Card Path)

1. Go to `developer.microsoft.com/microsoft-365/dev-program`
2. Join the M365 Developer Program (free, requires Microsoft account)
3. Set up an **Instant Sandbox** — gives a 90-day renewable E5 tenant with full Entra ID
4. In the Azure portal: **App registrations → New registration**
   - Redirect URI: `http://localhost:8090/auth/sso/oidc/callback`
   - Note client ID; create a client secret under **Certificates & secrets**
5. For SAML: **Enterprise Applications → Create your own → Integrate any other application**

### 10.3 CI / Automated Testing

OIDC integration tests in CI use **Keycloak 24.x in Docker** — no external account
required:
```yaml
# docker-compose.test.yml
keycloak:
  image: quay.io/keycloak/keycloak:24.0
  command: start-dev
  environment:
    KEYCLOAK_ADMIN: admin
    KEYCLOAK_ADMIN_PASSWORD: admin
  ports: ["8180:8080"]
```

SAML tests that require a live IdP are decorated `@pytest.mark.integration` and are
**skipped in CI unless** `OKTA_METADATA_URL` and `OKTA_CLIENT_SECRET` env vars are
present. They run in the `integration` Makefile target, not `test-unit`.

---

## 11. New Dependencies

Add to `management/requirements.txt` (with `# phase-79` comment):

```
python3-saml>=1.16.0      # phase-79: SAML 2.0 (requires xmlsec1 system package)
authlib>=1.3.0             # phase-79: OIDC / OAuth 2.0
httpx>=0.27.0              # phase-79: OIDC HTTP calls (already present, confirm version)
pyotp>=2.9.0               # phase-79: TOTP MFA
qrcode[pil]>=7.4.2         # phase-79: TOTP setup QR codes
py_webauthn>=2.0.0         # phase-79: WebAuthn / FIDO2
cryptography>=42.0.0       # phase-79: Fernet encryption for TOTP secrets
```

Add to management container `Dockerfile`:
```dockerfile
RUN apt-get install -y xmlsec1 libxmlsec1-dev   # required by python3-saml
```

---

## 12. Implementation Methodology

This phase uses a **four-agent TDD workflow** for every feature cluster:

1. **Test Agent** — writes failing tests first (unit + integration). Tests must make
   meaningful assertions; the Critical Review Agent will challenge every test.
2. **Code Agent** — implements only enough code to make the failing tests pass.
   No gold-plating.
3. **Docs Agent** — updates `docs/REDIS_SCHEMA.md`, `CHANGELOG.md`, OpenAPI spec,
   and inline docstrings after each cluster passes.
4. **Critical Review Agent ("So What?" agent)** — challenges every test written by
   the Test Agent with: "Does this test actually verify behaviour, or does it always
   pass? What would a developer need to break to make this test fail?" Any test that
   cannot answer this question is rewritten before the Code Agent sees it.

**Feature clusters (implement in order):**

1. Bearer token infrastructure (token CRUD, bcrypt storage, auth middleware)
2. RBAC role enforcement (4 roles, all existing endpoints re-gated)
3. Resource model migration (UUID + managed_by for allowlist/blocklist/watchlist/bans)
4. New REST endpoints (allowlist, blocklist, watchlist, connections, fingerprints, nodes, webhooks)
5. Audit trail enhancements (role field, before/after values, JSONL/CSV export)
6. TOTP MFA (setup, verify, backup codes, Fernet encryption)
7. WebAuthn / FIDO2 (registration, authentication, credential storage)
8. SAML 2.0 SSO (Okta sandbox)
9. OIDC SSO (Keycloak Docker CI + Okta/Entra optional)
10. OpenAPI 3.1 spec generation and commit

---

## 13. Dependencies and Sequencing

This phase must be complete before any of the following phases can begin:

| Phase | Why it depends on Phase 79 |
|-------|---------------------------|
| 80 (SIEM) | Webhook endpoints require authenticated API tokens |
| 81 (SOAR) | All SOAR actions require Operator-scoped tokens |
| 82 (Policy/Governance) | Policy apply endpoint requires Operator auth |
| 83 (Terraform/CLI) | Both require stable, token-authenticated API |
| 84 (Compliance) | Audit log export requires audit API endpoint |
| 87 (CMDB) | CMDB registration calls the API |

---

## 14. Acceptance Criteria

### Authentication & Tokens
- [ ] REQ-079-01: Bearer token auth enforced on all non-health endpoints. Verified by:
      `management/tests/test_tokens.py::test_bearer_valid_token_grants_access`
- [ ] REQ-079-02: Tokens: scoped to role, mandatory expiry, rotatable, bcrypt-stored. Verified by:
      `management/tests/test_tokens.py::test_bcrypt_hash_stored_not_plaintext`
- [ ] REQ-079-03: Token rotation: new token issued, old token valid for 60s grace period. Verified by:
      `management/tests/test_tokens.py::test_rotate_token_old_token_works_during_grace_period`
- [ ] REQ-079-04: `POST /api/v1/tokens` requires Admin role. Verified by:
      `management/tests/test_tokens.py::test_create_token_requires_auth`

### RBAC
- [ ] REQ-079-05: All four roles enforced at handler level with test coverage. Verified by:
      `management/tests/test_rbac.py::test_require_role_auditor_accepts_all_roles`
- [ ] REQ-079-06: Operator cannot PATCH dial, config, or manage tokens. Verified by:
      `management/tests/test_rbac.py::test_operator_cannot_delete_tokens`
- [ ] REQ-079-07: Auditor can only read; every write attempt returns 403. Verified by:
      `management/tests/test_rbac.py::test_auditor_delete_ban_403_regardless_of_ban_existence`
- [ ] REQ-079-08: Admin can perform all operations. Verified by:
      `management/tests/test_rbac.py::test_put_dial_admin_token_succeeds`

### Resource Model
- [ ] REQ-079-09: `managed_by` field present on all mutable resources. Verified by:
      `management/tests/test_resource_model.py::test_hash_record_has_all_required_fields`
- [ ] REQ-079-10: UUID present on all mutable resources. Verified by:
      `management/tests/test_resource_model.py::test_entry_id_is_stable_uuid4_format`
- [ ] REQ-079-11: `?managed_by=terraform` filter working on `GET /api/v1/allowlist`. Verified by:
      `management/tests/test_resource_model.py::test_managed_by_terraform_filter_excludes_operator_entries`
- [ ] REQ-079-12: Migration runs on startup and promotes legacy plain-string entries. Verified by:
      `management/tests/test_resource_model.py::test_migration_runs_on_startup_for_existing_entries`

### API Surface
- [ ] REQ-079-13: All endpoints in §2.2 implemented and returning RFC 7807 errors on failure. Verified by: `[MANUAL-REVIEW]`
- [ ] REQ-079-14: `GET /api/v1/connections` queries `ja4proxy:events` stream with filters. Verified by:
      `management/tests/test_new_endpoints.py::test_get_connections_filter_by_ip`
- [ ] REQ-079-15: `GET /api/v1/nodes` returns live node list from heartbeat keys. Verified by:
      `management/tests/test_new_endpoints.py::test_get_nodes_returns_live_nodes`
- [ ] REQ-079-16: `POST /api/v1/nodes/{host}/reload` publishes to `proxy:control` channel. Verified by:
      `management/tests/test_new_endpoints.py::test_post_node_reload_publishes_to_channel`
- [ ] REQ-079-17: Old Phase 13 routes (`/api/v1/lists/...`) still return 200 (backward compat). Verified by:
      `management/tests/test_resource_model.py::test_old_list_routes_still_return_200`

### MFA
- [ ] REQ-079-18: TOTP setup flow: QR code returned, secret Fernet-encrypted in Redis. Verified by:
      `management/tests/test_totp.py::test_totp_setup_stores_encrypted_secret`
- [ ] REQ-079-19: TOTP verify: valid code passes, invalid code returns 401. Verified by:
      `management/tests/test_totp.py::test_totp_verify_wrong_code_returns_401`
- [ ] REQ-079-20: TOTP backup codes: 8 codes generated, each single-use, bcrypt-hashed. Verified by:
      `management/tests/test_totp.py::test_backup_code_is_single_use`
- [ ] REQ-079-21: WebAuthn registration flow: challenge issued, attestation verified, credential stored. Verified by:
      `management/tests/test_webauthn.py::test_webauthn_register_complete_stores_credential`
- [ ] REQ-079-22: WebAuthn authentication flow: challenge issued, assertion verified. Verified by:
      `management/tests/test_webauthn.py::test_webauthn_auth_complete_valid_returns_200`
- [ ] REQ-079-23: Admin and Operator roles cannot log in without completing MFA. Verified by:
      `management/tests/test_totp.py::test_admin_without_mfa_cannot_change_dial`
- [ ] REQ-079-24: SSO-delegated MFA: no additional challenge if IdP asserts MFA satisfied. Verified by:
      `management/tests/test_oidc.py::test_oidc_callback_idp_mfa_amr_sets_session_key`

### SSO
- [ ] REQ-079-25: SAML 2.0 SP code implemented; unit-tested with mock IdP responses. Verified by:
      `management/tests/test_saml.py::test_saml_acs_valid_response_sets_cookie`
- [ ] REQ-079-26: OIDC login flow working against Keycloak Docker container (CI-runnable). Verified by:
      `management/tests/test_oidc.py::test_oidc_login_redirects_to_idp`
- [ ] REQ-079-27: Group-to-role mapping configured via `config/proxy.yml`. Verified by:
      `management/tests/test_saml.py::test_saml_map_role_from_proxy_config`
- [ ] REQ-079-28: Users not in any mapped group are denied access (`default_role: null`). Verified by:
      `management/tests/test_saml.py::test_map_role_unknown_no_default_returns_none`
- [ ] REQ-079-29: SAML tests marked `@pytest.mark.integration`, skipped without `OKTA_METADATA_URL`. Verified by:
      `management/tests/test_saml.py::test_saml_live_okta_login`
- [ ] REQ-079-30: **GAP**: Live Okta SAML test — deferred (no account; revisit when provisioned). Verified by: `[MANUAL-REVIEW]`
- [ ] REQ-079-31: **GAP**: Live Entra ID OIDC test — deferred (no account; revisit when provisioned). Verified by: `[MANUAL-REVIEW]`

### Audit Trail
- [ ] REQ-079-32: Every mutating action logged with role, before/after values. Verified by:
      `management/tests/test_audit_enhanced.py::test_audit_entry_has_before_and_after_values`
- [ ] REQ-079-33: No role can delete audit entries (DELETE on `management:audit_log` returns 403). Verified by:
      `management/tests/test_audit_enhanced.py::test_audit_log_has_no_delete_endpoint`
- [ ] REQ-079-34: `GET /api/v1/audit?format=jsonl` returns valid JSONL. Verified by:
      `management/tests/test_audit_enhanced.py::test_get_audit_jsonl_each_line_is_valid_json`
- [ ] REQ-079-35: `GET /api/v1/audit?format=csv` returns valid CSV with header row. Verified by:
      `management/tests/test_audit_enhanced.py::test_get_audit_csv_header_row`

### Observability
- [ ] REQ-079-36: `GET /api/v1/health/deep` returns cert expiry warnings for certs ≤ 30 days out. Verified by: `[MANUAL-REVIEW]`
- [ ] REQ-079-37: `GET /api/v1/health` requires no auth (LB health check). Verified by:
      `management/tests/test_health.py::test_health_is_public`

### Documentation
- [ ] REQ-079-38: All new Redis keys documented in `docs/REDIS_SCHEMA.md`. Verified by: `[MANUAL-REVIEW]`
- [ ] REQ-079-39: `docs/api/openapi.yaml` committed (OpenAPI 3.1). Verified by: `[MANUAL-REVIEW]`
- [ ] REQ-079-40: `CHANGELOG.md` updated with standard Phase 79 entry. Verified by: `[MANUAL-REVIEW]`
- [ ] REQ-079-41: `management/requirements.txt` updated with Phase 79 dependencies commented. Verified by: `[MANUAL-REVIEW]`
