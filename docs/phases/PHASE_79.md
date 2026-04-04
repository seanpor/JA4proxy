# Phase 79: Management API v2, RBAC & Enterprise Identity

> **This is the critical dependency for every other enterprise phase (80–86).**
> Nothing in the enterprise integration stack is possible without a stable,
> well-designed REST API and a proper identity layer. Do this first.

---

## 1. Overview

Phase 13 defined the Management UI backend API but was deferred. This phase delivers
a production-grade API designed explicitly for enterprise integration: machine-readable,
stable, fully authenticated, and audit-logged. It also delivers the identity layer
(SSO, RBAC, MFA) required before any enterprise customer will allow the product onto
their network.

The API is the integration surface for: Terraform provider (Phase 83), SOAR platforms
(Phase 81), SIEM webhooks (Phase 80), ChatOps bots, CMDB registration, and the
`ja4proxy-cli` binary.

---

## 2. Management REST API

### 2.1 Design Principles

- **Stable IDs**: every resource has a stable, opaque identifier (UUID or fingerprint
  string). Tags and names are mutable; IDs are not.
- **Full read-back on create/update**: every mutating response returns the full
  resource state, not just an acknowledgement. Terraform and SOAR tools require this.
- **Sensible HTTP semantics**: `PUT` for full replacement, `PATCH` for partial update,
  `DELETE` is idempotent (no error on already-deleted resource).
- **Versioned**: all endpoints under `/api/v1/`. Breaking changes increment to `/api/v2/`.
- **Machine-first**: every response is JSON. No HTML error pages. Error bodies follow
  RFC 7807 Problem Details format: `{ "type", "title", "status", "detail", "instance" }`.

### 2.2 Resource Catalogue

| Endpoint | Methods | Description |
|----------|---------|-------------|
| `/api/v1/allowlist` | GET, POST | List / add JA4 fingerprint or IP allowlist entries |
| `/api/v1/allowlist/{id}` | GET, DELETE | Get or remove a specific entry |
| `/api/v1/blocklist` | GET, POST | List / add JA4 fingerprint blocklist entries |
| `/api/v1/blocklist/{id}` | GET, DELETE | Get or remove a specific entry |
| `/api/v1/bans` | GET, POST | List active bans / add a ban with TTL |
| `/api/v1/bans/{ip}` | GET, DELETE | Get or release a specific ban |
| `/api/v1/bans/cidr/{cidr}` | GET, POST, DELETE | CIDR-level bans |
| `/api/v1/watchlist` | GET, POST, DELETE | Elevated-monitoring tier (no block, extra logging) |
| `/api/v1/dial` | GET, PATCH | Read or update the dial setting (requires Operator role) |
| `/api/v1/config` | GET, PATCH | Read or hot-reload editable config fields |
| `/api/v1/config/validate` | POST | Validate a proposed config body without applying |
| `/api/v1/health` | GET | Basic health (used by LB health checks) |
| `/api/v1/health/deep` | GET | Deep health: Redis connectivity, signal modules, cert expiry |
| `/api/v1/ready` | GET | Readiness: GeoIP loaded, config valid, Redis reachable |
| `/api/v1/metrics/summary` | GET | JSON summary of key metrics (for dashboards, not Prometheus scrape) |
| `/api/v1/connections` | GET | Query connection history (`?ip=`, `?ja4=`, `?since=`, `?limit=`) |
| `/api/v1/fingerprints/{ja4}` | GET | Fingerprint detail: history, associated IPs, risk signals |
| `/api/v1/fingerprints/{ja4}/history` | GET | Timeline of all connections using this fingerprint |
| `/api/v1/nodes` | GET | All proxy nodes in the deployment, with health and version |
| `/api/v1/nodes/{host}/reload` | POST | Trigger SIGHUP on a specific node |
| `/api/v1/audit` | GET | Audit log entries (`?since=`, `?actor=`, `?action=`) |
| `/api/v1/tokens` | GET, POST | List / create API tokens (Admin role only) |
| `/api/v1/tokens/{id}` | GET, DELETE | Inspect or revoke a token |
| `/api/v1/webhooks` | GET, POST, DELETE | Manage webhook subscriptions |

### 2.3 Terraform-Friendly Design Requirements

The Terraform provider (Phase 83) depends on the API having:
- Deterministic `GET` after `POST` — a resource must be immediately readable by its
  ID after creation. No eventual consistency windows.
- `managed_by` field on every mutable resource: `"terraform"`, `"operator"`, `"api"`,
  `"analytics"`. This allows the Terraform provider to distinguish IaC-owned resources
  from out-of-band entries, solving the state drift problem.
- `GET /api/v1/allowlist` must support filtering by `?managed_by=terraform` so the
  provider can enumerate only the resources it owns.

---

## 3. API Authentication

### 3.1 API Tokens

All non-browser API access uses bearer tokens. Token requirements:

- Scoped to a role (Auditor, Analyst, Operator, or Admin)
- Mandatory expiry: maximum 365 days, configurable at issuance
- Rotatable: `POST /api/v1/tokens/{id}/rotate` returns a new token and invalidates the
  old one after a configurable grace period (default 60 seconds — allows in-flight
  requests to complete)
- Every API call attributable to a specific token ID in the audit log
- Tokens stored as bcrypt hashes — the plaintext is shown only at creation time

### 3.2 Session Authentication (UI)

Browser sessions use short-lived JWTs (15-minute expiry, 8-hour refresh window).
Session tokens are httpOnly, SameSite=Strict cookies. CSRF protection via double-submit
cookie pattern.

---

## 4. SSO — SAML 2.0 and OIDC

Enterprise IT security policy rejects tools that cannot integrate with the corporate
IdP. This is a hard procurement gate, not a nice-to-have.

### 4.1 Required Identity Providers

| IdP | Protocol | Priority |
|-----|----------|----------|
| Okta | SAML 2.0 + OIDC | Critical — plurality enterprise IdP |
| Microsoft Entra ID (Azure AD) | SAML 2.0 + OIDC | Critical — Microsoft-shop mandate |
| Ping Identity | SAML 2.0 + OIDC | High — financial services standard |
| Generic SAML 2.0 | SAML 2.0 | Covers all others |
| Generic OIDC | OIDC | Covers Keycloak, Auth0, etc. |

### 4.2 Group-to-Role Mapping

The IdP integration must support **group-based role assignment**:

```yaml
# config/proxy.yml — SSO role mapping
sso:
  provider: okta
  metadata_url: "https://company.okta.com/app/ja4proxy/sso/saml/metadata"
  role_mapping:
    "CN=SOC-Analysts,OU=Groups,DC=corp": analyst
    "CN=SecOps-Operators,OU=Groups,DC=corp": operator
    "CN=Security-Admins,OU=Groups,DC=corp": admin
    "CN=Audit-Team,OU=Groups,DC=corp": auditor
  default_role: null   # null = deny access to unmapped users
```

Active Directory group membership maps to JA4proxy roles without any per-user
configuration in the product. When a user is removed from an AD group, their access is
revoked at next login — no manual deprovisioning required.

### 4.3 Implementation Notes

Use an established library — **python-saml** (OneLogin) for SAML,
**authlib** for OIDC. Do not implement SAML or OIDC from scratch. Plan 6-8 weeks
including testing against real IdP tenants (Okta developer account, Entra ID free tier).

---

## 5. RBAC — Four Roles

Segregation of duties is required for PCI-DSS and SOC 2 compliance evidence. The
four-role model is the minimum viable set.

| Role | Permissions |
|------|-------------|
| **Auditor** | Read-only access to all data. Export audit logs. Cannot change any configuration or lists. Cannot see API token values (only metadata). |
| **Analyst** | Read dashboards. Query connection history and fingerprint timelines. Cannot modify any list, ban, or configuration. |
| **Operator** | Add/remove entries from allowlist, blocklist, watchlist. Add/release bans. Cannot change dial, config, bypass toggles, or manage API tokens. |
| **Admin** | Full access: all Operator permissions plus dial changes, config hot-reload, bypass toggle management, API token management, webhook management, SSO config. |

Key separation: the **Operator/Admin boundary** is the segregation of duties evidence.
An Operator cannot change the dial or disable security bypasses — only an Admin can.
This maps directly to PCI-DSS 6.6 control evidence and SOC 2 CC6.6.

### 5.1 Role Enforcement

All API endpoints enforce role checks at the handler level. There is no superuser
role that bypasses checks. Even the local admin user created at initial setup has the
Admin role — the role model applies universally.

---

## 6. MFA Enforcement

| Role | MFA requirement |
|------|----------------|
| Admin | Mandatory — enforced, cannot be disabled |
| Operator | Mandatory — enforced, cannot be disabled |
| Analyst | Configurable — default required |
| Auditor | Configurable — default optional |

Supported MFA methods:
- **TOTP** (Google Authenticator, Authy, 1Password) — required baseline
- **WebAuthn / FIDO2** (hardware keys: YubiKey, Titan) — required for financial services
- **SSO-delegated MFA** — if the IdP enforces MFA, JA4proxy trusts it

---

## 7. Append-Only Audit Trail

Every UI and API action is written to an append-only audit log. Requirements:

- **No role can delete or edit audit entries**, including Admin
- Every entry contains: `timestamp` (UTC, millisecond precision), `actor_id`
  (user email or token ID), `actor_ip`, `action_type`, `resource_type`,
  `resource_id`, `before_value` (JSON), `after_value` (JSON), `session_id`
- Stored in a dedicated Redis Stream (`management:audit_log`) with no TTL
- Exportable via `GET /api/v1/audit` as JSONL or CSV (required for SOC 2 auditor)
- Maximum 100,000 entries before the oldest are archived to flat file (never deleted)

---

## 8. Dependencies and Sequencing

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

## 9. Acceptance Criteria

- [ ] All endpoints in §2.2 implemented and tested
- [ ] Every endpoint returns RFC 7807 error bodies on failure
- [ ] `managed_by` field present on all mutable resources
- [ ] Bearer token auth enforced on all non-health endpoints
- [ ] Tokens: scoped to role, mandatory expiry, rotatable, bcrypt-stored
- [ ] SAML 2.0 SSO working against Okta developer tenant
- [ ] OIDC SSO working against Entra ID (Azure AD) tenant
- [ ] Group-to-role mapping configured via `config/proxy.yml`
- [ ] All four roles enforced at handler level with test coverage
- [ ] Admin and Operator roles require MFA (TOTP + WebAuthn)
- [ ] Audit trail: every mutating action logged, no role can delete entries
- [ ] Audit log exportable as JSONL and CSV via API
- [ ] `GET /api/v1/health/deep` returns cert expiry warnings ≤ 30 days
- [ ] API documented in OpenAPI 3.1 spec committed to `docs/api/openapi.yaml`
- [ ] Integration tests against real Okta and Entra ID tenants
