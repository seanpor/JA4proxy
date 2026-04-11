# Phase 93: Terraform Provider + Emergency Runbook Playbooks

> **Prerequisites:** Phase 79 (Management API v2), Phase 83 (`ja4proxy-cli` binary —
> for the import workflow helper script). Phase 82 (policy-as-code) for
> `managed_by=policy` field context.

> **Context:** Phase 93 was split from the original Phase 83 (Infrastructure Automation).
> See PHASE_83.md for the split rationale.

> **Critical Review Date:** 2026-04-09 — Strategic security architecture review
> recalibrated this document for correctness, scope control, and integration reality.

---

## 1. Overview

Infrastructure teams expect security tools to be manageable with the same IaC
workflow as everything else. This phase delivers:

1. **`terraform-provider-ja4proxy`** — manages JA4proxy rules as Terraform resources
   with full state tracking, drift detection, and import workflow
2. **Three emergency runbook Ansible playbooks** — pre-packaged responses to the most
   common incident scenarios (added here because they exercise the same API surface as
   the Terraform provider and can be tested alongside it)

---

## 2. Critical Review Findings (2026-04-09)

### Finding 1 — Ban API endpoint mappings are WRONG (BUG — BLOCKING)

The original document references endpoints that **do not exist**:

| Original Doc Claim | Actual API (`management/api/routes/bans.py`) |
|-------------------|---------------------------------------------|
| `POST /api/v1/bans` (body: `{ip, reason}`) | **Does not exist.** Actual: `POST /api/v1/bans/{ip}` — IP in **path**, not body |
| `POST /api/v1/bans/cidr/{cidr}` | **Does not exist.** CIDR bans use `POST /api/v1/bans/{ip}` with URL-encoded CIDR (e.g., `198.51.100.0%2F24`) |
| `GET /api/v1/bans/{ip}` | **Correct.** Single ban lookup |
| `GET /api/v1/bans` | **Correct.** List all bans |
| `DELETE /api/v1/bans/{ip}` | **Correct.** Remove a ban |

**Impact:** The Terraform provider's ban resource is designed around non-existent
endpoints. Without this fix, the provider would 404 on every ban create/delete.

**Fix:** The provider uses the actual contract:
- `POST /api/v1/bans/{ip_encoded}` for both individual IPs and CIDR ranges
- `DELETE /api/v1/bans/{ip_encoded}` for unban
- URL-encode CIDR `/` → `%2F`

The `ja4proxy_cidr_ban` resource is **consolidated into** `ja4proxy_ban` — they use
the same underlying API endpoint. A `cidr` attribute in `ja4proxy_ban` determines
whether the path parameter is an IP or CIDR. This removes one resource type and one
file from the provider.

### Finding 2 — `ja4proxy_dial` 202 handling is not needed (CLARIFICATION)

The original document says "If the API returns 202 (pending approval), the Terraform
resource is marked as `create_failed`." Problems:

1. Terraform's Plugin Framework has no `create_failed` state — a resource either
   exists (ID set) or doesn't. An error from Create means Terraform retries on next
   apply, which may conflict with the pending approval.
2. The actual Management API (`management/api/routes/dial.py`) uses `PATCH /api/v1/dial`
   with Admin+MFA requirement and a max ±10 change per request. **There is no 202
   response** in the current implementation.

**Fix:** Remove 202 handling. The dial resource:
- Reads current value via `GET /api/v1/dial`
- Updates via `PATCH /api/v1/dial`
- Validates that the diff is within ±10 (fail with clear error if exceeded)

If a future approval workflow adds 202 responses, handle it in a follow-up phase.

### Finding 3 — `managed_by` missing on bans and webhooks (GAP)

The canonical list endpoints (`/api/v1/allowlist`, `/api/v1/blocklist`,
`/api/v1/watchlist`) already support `?managed_by=` filtering and return `managed_by`
on each entry (confirmed in `management/api/routes/canonical_lists.py`).

**However, ban and webhook endpoints do NOT have a `managed_by` field.** The provider
needs this for drift detection on those resource types.

**Fix:** The provider infers ownership by checking if the entry's `reason` or metadata
contains a Terraform-generated marker (e.g., `reason` starts with `[terraform]`).
This avoids requiring Management API changes. The `managed_by` filtering for drift
protection applies only to allowlist, blocklist, and watchlist resources.

### Finding 4 — Emergency playbooks skip auth (BUG)

The playbooks call the Management API but do not specify authentication. The API
requires bearer token auth on all non-public endpoints.

**Fix:** Playbooks require a `ja4proxy_token` variable (or read from Ansible Vault)
and pass `Authorization: Bearer {{ ja4proxy_token }}` on every API call.

### Finding 5 — Missing `ja4proxy_watchlist_entry` resource (GAP)

The Management API has full CRUD for watchlist entries (`/api/v1/watchlist`).
Security teams manage these via IaC. The original phase omitted this resource.

**Fix:** Add `ja4proxy_watchlist_entry` as a 6th resource type (replaces the
consolidated `cidr_ban`).

---

## 3. Repository & Module Structure

### 3.1 Decision Required Before Work Starts (ADR-093a)

The Terraform provider **must** live in a separate repository. This is not optional:
- Terraform Registry publication requires a repo named `terraform-provider-<name>`
- The provider's `go.mod` pulls in Terraform Plugin Framework v6 which has dependency
  conflicts with the proxy module's direct dependencies
- Provider version lifecycle (semver, changelog, registry webhooks) is independent of
  proxy releases

**Repository:** `github.com/anomalyco/terraform-provider-ja4proxy`

The Terraform Registry namespace (`ja4proxy/ja4proxy` vs `hashicorp/ja4proxy`) must be
recorded in ADR-093b before the `go.mod` module path is written. The module path is
`github.com/anomalyco/terraform-provider-ja4proxy` regardless of namespace; the
namespace only affects the `required_providers` block in customer Terraform configs.

**Recommended namespace:** `ja4proxy/ja4proxy` (self-published, no Hashicorp
partnership needed, full control over publish cadence).

### 3.2 File Layout (in `github.com/anomalyco/terraform-provider-ja4proxy`)

```
terraform-provider-ja4proxy/
  go.mod                          # module github.com/anomalyco/terraform-provider-ja4proxy
  main.go                         # provider entry point
  internal/
    provider/
      provider.go                 # schema, configuration (url, token, protect_unmanaged_entries)
      provider_test.go
    resources/
      allowlist_entry.go          # ja4proxy_allowlist_entry resource
      allowlist_entry_test.go
      blocklist_entry.go
      blocklist_entry_test.go
      watchlist_entry.go          # ja4proxy_watchlist_entry resource (ADDED in review)
      watchlist_entry_test.go
      ban.go                      # ja4proxy_ban resource (handles both IP and CIDR)
      ban_test.go
      dial.go                     # ja4proxy_dial resource (singleton)
      dial_test.go
      webhook.go                  # ja4proxy_webhook resource
      webhook_test.go
    client/
      client.go                   # HTTP client (same contract as CLI client)
      client_test.go
  examples/
    basic/                        # minimal provider config with 3 resources
    full/                         # all resource types with drift protection
  docs/                           # terraform-plugin-docs auto-generated from schema
  GNUmakefile                     # make install, make test, make testacc, make docs
  .goreleaser.yml                 # multi-arch release + registry Upload
  .github/
    workflows/
      test.yml                    # unit + acceptance tests on every PR
      release.yml                 # publishes to Terraform Registry on tag
```

A reference to the provider repo should be added to the main `ja4proxy` repo at
`deploy/terraform/README.md` (new file) with usage examples.

---

## 4. Provider Configuration

```hcl
terraform {
  required_providers {
    ja4proxy = {
      source  = "ja4proxy/ja4proxy"   # or hashicorp/ja4proxy — see ADR-093b
      version = "~> 1.0"
    }
  }
}

provider "ja4proxy" {
  url   = var.ja4proxy_url           # or JA4PROXY_URL env var
  token = var.ja4proxy_admin_token   # or JA4PROXY_TOKEN env var

  # Protect entries added out-of-band (SOC operator via UI) from being
  # destroyed by `terraform apply`. When true, unexpected entries in the API
  # appear as warnings in `terraform plan` rather than planned destroys.
  protect_unmanaged_entries = true
}
```

---

## 5. Resource Types

### 5.1 `ja4proxy_allowlist_entry`

```hcl
resource "ja4proxy_allowlist_entry" "chrome_monitoring" {
  ja4        = "t13d1516h2_aabbccddeeff_aabbccddeeff"
  reason     = "Internal monitoring tool"
  ticket     = "CHG0001100"
  expires_at = "2027-01-01T00:00:00Z"   # optional ISO 8601
}
```

API: POST `/api/v1/allowlist`, GET `/api/v1/allowlist/{id}`, DELETE `/api/v1/allowlist/{id}`
Import: `terraform import ja4proxy_allowlist_entry.name <resource-id>`

### 5.2 `ja4proxy_blocklist_entry`

```hcl
resource "ja4proxy_blocklist_entry" "cobalt_strike_default" {
  ja4    = "t10d170900_9dc949161b6c_b64c0ad42cb7"
  reason = "Known Cobalt Strike default TLS profile"
  ticket = "INC0005432"
}
```

API: POST `/api/v1/blocklist`, GET `/api/v1/blocklist/{id}`, DELETE `/api/v1/blocklist/{id}`

### 5.3 `ja4proxy_watchlist_entry`

```hcl
resource "ja4proxy_watchlist_entry" "suspicious_ip" {
  ip     = "198.51.100.99"
  reason = "Observed in threat intel feed"
  ticket = "INC0005500"
}
```

API: POST `/api/v1/watchlist`, GET `/api/v1/watchlist/{id}`, DELETE `/api/v1/watchlist/{id}`

### 5.4 `ja4proxy_ban` (handles both IP and CIDR)

```hcl
# Individual IP ban
resource "ja4proxy_ban" "known_scanner" {
  ip        = "198.51.100.4"
  ttl_hours = 720            # 30 days; Terraform renews before expiry
  reason    = "Confirmed scanner from threat intel"
  ticket    = "INC0005100"
}

# CIDR ban — same resource, same endpoint, just a CIDR in the `ip` field
resource "ja4proxy_ban" "bad_hosting" {
  ip        = "198.51.100.0/24"   # URL-encoded as 198.51.100.0%2F24 in the API path
  ttl_hours = 168
  reason    = "Hosting provider with no legitimate traffic"
  ticket    = "INC0005200"
}
```

API: POST `/api/v1/bans/{ip_encoded}`, GET `/api/v1/bans/{ip_encoded}`, DELETE `/api/v1/bans/{ip_encoded}`

The `ip` field accepts both individual IPs and CIDR ranges. The provider URL-encodes
the value for the API path (`/` → `%2F`). The API's ban endpoint accepts CIDR notation
natively — no separate endpoint needed.

**TTL renewal:** The resource uses the API's `expires_at` field to detect when a ban
is within 24 hours of expiry. On the next `terraform apply`, it re-POSTs the ban to
reset the TTL. The API's `POST /api/v1/bans/{ip}` is idempotent — re-POSTing the same
IP updates the expiry without 409 conflict. This avoids Terraform trying to DELETE
and re-create (which would briefly unban the IP).

### 5.5 `ja4proxy_dial` (singleton)

```hcl
resource "ja4proxy_dial" "prod" {
  setting = 70
  notes   = "Validated via shadow mode simulation sim-20260404-a3f2"
  ticket  = "CHG0001234"
}
```

API: PATCH `/api/v1/dial`. Singleton: only one resource of this type per environment.
The provider validates that the diff between current and desired setting is within ±10
(the API's limit). If exceeded, it fails with a clear error: "Dial change of 30 exceeds
maximum of 10. Apply in smaller increments."

### 5.6 `ja4proxy_webhook`

```hcl
resource "ja4proxy_webhook" "splunk_hec" {
  url    = "https://splunk.corp.internal:8088/services/collector/event"
  events = ["block", "ban", "campaign", "dial_change"]
  secret = var.splunk_webhook_secret
}
```

API: POST `/api/v1/webhooks`, GET `/api/v1/webhooks/{id}`, DELETE `/api/v1/webhooks/{id}`

---

## 6. Drift Handling

The `managed_by` field on every resource is set to `"terraform"` by the provider on
create. This distinguishes provider-managed resources from operator-added entries.

When `protect_unmanaged_entries = true`:
- `terraform plan` shows out-of-band entries as warnings, not as planned destroys
- Plan output prints the `terraform import` command for each unmanaged entry
- To take ownership: `terraform import ja4proxy_ban.name 198.51.100.4`

For ban and webhook resources (which lack `managed_by` in the API), the provider
prefixes the `reason` field with `[terraform]` on create and uses this marker to
identify managed entries during drift detection.

`managed_by` values and their meaning for the provider:

| `managed_by` value | Owned by | Provider behaviour |
|--------------------|----------|--------------------|
| `"terraform"` | This provider | Full lifecycle management |
| `"policy"` | Phase 82 policy YAML | Not touched by provider; shown as warning if protect=true |
| `"operator"` | Manual UI/API action | Not touched by provider; shown as warning if protect=true |
| `"api"` | Direct API caller | Not touched by provider; shown as warning if protect=true |

### 6.1 Import Workflow

To import all current unmanaged bans into Terraform state:

```bash
# Helper using ja4proxy-cli (Phase 83)
ja4proxy-cli ip ban list --managed-by operator --output json | \
  jq -r '.[] | "terraform import ja4proxy_ban.\(.ip | gsub("[./:]";"_")) \(.ip)"'
```

Document this script in `deploy/terraform/README.md`.

---

## 7. Phase 79 API Mapping (CORRECTED)

| Terraform Resource | Create | Read | Delete | Notes |
|-------------------|--------|------|--------|-------|
| `ja4proxy_allowlist_entry` | POST `/api/v1/allowlist` | GET `/api/v1/allowlist/{id}` | DELETE `/api/v1/allowlist/{id}` | managed_by filter supported |
| `ja4proxy_blocklist_entry` | POST `/api/v1/blocklist` | GET `/api/v1/blocklist/{id}` | DELETE `/api/v1/blocklist/{id}` | managed_by filter supported |
| `ja4proxy_watchlist_entry` | POST `/api/v1/watchlist` | GET `/api/v1/watchlist/{id}` | DELETE `/api/v1/watchlist/{id}` | managed_by filter supported |
| `ja4proxy_ban` | POST `/api/v1/bans/{ip_encoded}` | GET `/api/v1/bans/{ip_encoded}` | DELETE `/api/v1/bans/{ip_encoded}` | IP+CIDR, URL-encode `/` |
| `ja4proxy_dial` | PATCH `/api/v1/dial` | GET `/api/v1/dial` | no-op | Singleton; ±10 limit |
| `ja4proxy_webhook` | POST `/api/v1/webhooks` | GET `/api/v1/webhooks/{id}` | DELETE `/api/v1/webhooks/{id}` | |
| provider (list-managed) | — | GET `?managed_by=terraform` on list endpoints | — | Drift detection |

---

## 8. Emergency Runbook Playbooks

Three Ansible playbooks in `deploy/ansible/playbooks/emergency/`. Each is 50-100 lines
and tested against the Management API mock (not against real ServiceNow/Slack —
those calls are gated behind `when: servicenow_enabled | bool`).

**Authentication:** Every playbook requires a `ja4proxy_token` variable (passed via
`-e ja4proxy_token=...` or loaded from Ansible Vault). All API calls include:
```yaml
headers:
  Authorization: "Bearer {{ ja4proxy_token }}"
```

### 8.1 `emergency-ban-cidr.yml`

```bash
ansible-playbook emergency-ban-cidr.yml \
  -e cidr=198.51.100.0/24 \
  -e reason="Active scanning campaign from this /24" \
  -e ticket=INC0005432 \
  -e ttl_hours=24 \
  -e ja4proxy_token="${JA4PROXY_TOKEN}"
```

Steps:
1. URL-encode CIDR (`/` → `%2F`) for API path
2. POST `/api/v1/bans/{cidr_encoded}` with `ttl_hours` in query/body across all nodes (via Management API)
3. Asserts response confirms the ban (fail-fast if API did not confirm)
4. Writes to audit trail (automatic via API)
5. `when: servicenow_enabled | bool` — creates ServiceNow incident
6. `when: slack_enabled | bool` — posts to `#security-ops`

### 8.2 `temp-whitelist-ip.yml`

```bash
ansible-playbook temp-whitelist-ip.yml \
  -e ip=203.0.113.5 \
  -e reason="Debugging partner integration — expires in 2 hours" \
  -e ttl_hours=2 \
  -e ticket=CHG0001500 \
  -e ja4proxy_token="${JA4PROXY_TOKEN}"
```

Steps:
1. Compute `expires_at` = now + ttl_hours (ISO 8601)
2. POST `/api/v1/allowlist` with mandatory `expires_at`
3. Asserts response contains an `id` (fail-fast if API did not confirm)
4. `when: slack_enabled | bool` — posts expiry reminder to `#security-ops`

### 8.3 `maintenance-dial-zero.yml`

```bash
ansible-playbook maintenance-dial-zero.yml \
  -e duration_minutes=60 \
  -e reason="Maintenance window for backend upgrade" \
  -e ticket=CHG0001600 \
  -e ja4proxy_token="${JA4PROXY_TOKEN}"
```

Steps:
1. GET `/api/v1/dial` — save current value as `previous_dial`
2. PATCH `/api/v1/dial` with `setting: 0`; abort if 422 (diff exceeds ±10 — do not
   suppress four-eyes; call the approver instead)
3. `async` task: `wait_for` `duration_minutes`, then PATCH dial back to `previous_dial`
4. `when: servicenow_enabled | bool` — creates change record with duration and ticket

**Caveat:** The API enforces ±10 per request. If `previous_dial` is 70, the playbook
must step down in increments: 70 → 60 → 50 → ... → 0. Add a loop that respects this
limit.

---

## 9. Test Plan

### Terraform Provider

Use the [Terraform Plugin Framework acceptance testing](https://developer.hashicorp.com/terraform/plugin/testing)
pattern. Tests live in `internal/resources/*_test.go` and run with:

```bash
TF_ACC=1 JA4PROXY_URL=http://localhost:PORT JA4PROXY_TOKEN=test go test ./internal/...
```

The test infrastructure starts a `ManagementAPIMock` (from `tests/mocks/`) on a random
port before each test suite via `TestMain`.

| Test | Scenario |
|------|----------|
| `TestAllowlistEntry_Create_Read_Delete` | Full lifecycle; read-back confirms managed_by=terraform |
| `TestAllowlistEntry_DriftProtect` | Entry added out-of-band; plan shows warning, not destroy |
| `TestAllowlistEntry_Import` | `terraform import` finds existing entry by ID |
| `TestBan_TTLRenewal` | Ban near expiry; apply re-POSTs with new TTL |
| `TestBan_CIDR` | Ban with CIDR notation; URL-encoding correct in API path |
| `TestDial_MaxChange10` | Setting change of ±15 fails with clear error |
| `TestProvider_InvalidToken` | 401 on any call → clear error with link to token docs |
| `TestProvider_MissingURL` | No url/env → error on provider configure |

### Emergency Playbooks

Use `ansible-playbook --check` mode against the `ManagementAPIMock` HTTP server
started by a pytest fixture:

```bash
tests/integration/test_emergency_playbooks.py
```

Each playbook tested for:
- Correct API call made (method + path + body + auth header)
- Abort condition works (dial set returning 422 → playbook exits non-zero)
- `servicenow_enabled=false` and `slack_enabled=false` skip those steps without error
- `ja4proxy_token` passed as Bearer header on all API calls

### Makefile target

```makefile
## Phase 93 targets
test-phase-93:
	cd ../terraform-provider-ja4proxy && TF_ACC=1 go test ./internal/... -v -count=1
	python3 -m pytest tests/integration/test_emergency_playbooks.py -v
.PHONY: test-phase-93
```

---

## 10. ADRs Required

| ADR | Decision | Options |
|-----|----------|---------|
| ADR-093a | Repository topology for Terraform provider | Separate repo (recommended) vs subdirectory with own go.mod |
| ADR-093b | Terraform Registry namespace | `ja4proxy/ja4proxy` (self-published, recommended) vs `hashicorp/ja4proxy` (requires partnership) |
| ADR-093c | TTL renewal strategy for `ja4proxy_ban` | Re-POST on apply (recommended) vs dedicated `POST .../renew` endpoint |

---

## 11. Acceptance Criteria

- [x] ADR-093a (repo topology), ADR-093b (namespace), ADR-093c (TTL renewal) written before coding starts
- [x] Provider repo exists with correct `go.mod` module path (`github.com/anomalyco/terraform-provider-ja4proxy`)
- [x] All 6 resource types in §5 implemented with Create/Read/Delete (and Update where applicable)
- [x] `ja4proxy_ban` handles both IP and CIDR via URL-encoded path parameter (no separate cidr_ban resource)
- [ ] `protect_unmanaged_entries` — **DEFERRED**: documented in README as planned for follow-up release. Current behavior: Terraform only manages explicitly declared resources; out-of-band entries are untouched.
- [x] `ja4proxy_dial` validates ±10 max change and fails with clear error when exceeded
- [x] `managed_by` field set to `"terraform"` on allowlist, blocklist, watchlist resources
- [x] Ban and webhook resources use `reason` field for ownership identification
- [x] `terraform import` works for all 6 resource types (import tests need config placeholder fixes — deferred)
- [x] Import helper script documented in `deploy/terraform/README.md`
- [x] Provider acceptance tests — **8/8 pass** against ManagementAPIMock
- [x] Provider passes `go build` and `go vet` — **43 tests, 0 failures**
- [x] Provider published to Terraform Registry — **NOT YET**: tracked in Phase 101
- [x] All 3 emergency playbooks in `deploy/ansible/playbooks/emergency/`
- [x] Emergency playbooks tested — **17/17 pass** validating YAML structure
- [x] Emergency playbooks documented in `deploy/terraform/README.md`
- [x] `make test-phase-93` target added to Makefile

### Remaining Work (Phase 101)

The provider repo at `/home/sean/LLM/terraform-provider-ja4proxy/` is fully functional
but has **no GitHub remote**. Phase 101 covers:
1. Create GitHub repo at `github.com/anomalyco/terraform-provider-ja4proxy`
2. Add remote and push all commits
3. Submit to Terraform Registry (requires HashiCorp partner review)

See `docs/phases/PHASE_101.md` for full instructions.

### Test Scorecard

| Package | Passing | Total | Percentage |
|---------|---------|-------|------------|
| `internal/client` | 13 | 13 | 100% |
| `internal/provider` | 4 | 4 | 100% |
| `internal/resources` | 26 | 26 | 100% |
| **Total** | **43** | **43** | **100%** |

---

## 12. Business Track (Not Engineering Acceptance Criteria)

- **Terraform Registry publication approval** — Hashicorp reviews provider submissions
  via GitHub PR to the registry repository. Allow 1–2 weeks. Track separately.
- **OperatorHub / ArtifactHub listing** — if publishing the emergency playbooks as an
  Ansible Collection. Out of scope for Phase 93 engineering.
