# Phase 93: Terraform Provider + Emergency Runbook Playbooks

> **Prerequisites:** Phase 79 (Management API v2), Phase 83 (`ja4proxy-cli` binary —
> for the import workflow helper script). Phase 82 (policy-as-code) for
> `managed_by=policy` field context.

> **Context:** Phase 93 was split from the original Phase 83 (Infrastructure Automation).
> See PHASE_83.md for the split rationale.

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

## 2. Repository & Module Structure

### 2.1 Decision Required Before Work Starts (ADR-093a)

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

### 2.2 File Layout (in `github.com/anomalyco/terraform-provider-ja4proxy`)

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
      ban.go                      # ja4proxy_ban resource
      ban_test.go
      cidr_ban.go                 # ja4proxy_cidr_ban resource
      cidr_ban_test.go
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
  .goreleaser.yml                 # multi-arch release + registry upload
  .github/
    workflows/
      test.yml                    # unit + acceptance tests on every PR
      release.yml                 # publishes to Terraform Registry on tag
```

A reference to the provider repo should be added to the main `ja4proxy` repo at
`deploy/terraform/README.md` (new file) with usage examples.

---

## 3. Provider Configuration

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

## 4. Resource Types

### 4.1 `ja4proxy_allowlist_entry`

```hcl
resource "ja4proxy_allowlist_entry" "chrome_monitoring" {
  ja4        = "t13d1516h2_aabbccddeeff_aabbccddeeff"
  reason     = "Internal monitoring tool"
  ticket     = "CHG0001100"
  expires_at = "2027-01-01T00:00:00Z"   # optional ISO 8601
}
```

API: POST `/api/v1/allowlist`, DELETE `/api/v1/allowlist/{id}`
Import: `terraform import ja4proxy_allowlist_entry.name <entry-id>`

### 4.2 `ja4proxy_blocklist_entry`

```hcl
resource "ja4proxy_blocklist_entry" "cobalt_strike_default" {
  ja4    = "t10d170900_9dc949161b6c_b64c0ad42cb7"
  reason = "Known Cobalt Strike default TLS profile"
  ticket = "INC0005432"
}
```

API: POST `/api/v1/blocklist`, DELETE `/api/v1/blocklist/{id}`

### 4.3 `ja4proxy_ban`

```hcl
resource "ja4proxy_ban" "known_scanner" {
  ip        = "198.51.100.4"
  ttl_hours = 720            # 30 days; Terraform renews before expiry
  reason    = "Confirmed scanner from threat intel"
  ticket    = "INC0005100"
}
```

API: POST `/api/v1/bans`, DELETE `/api/v1/bans/{ip}`

**TTL renewal:** The resource uses the API's `expires_at` field to detect when a ban
is within 24 hours of expiry. On the next `terraform apply`, it re-POSTs the ban to
reset the TTL. This avoids Terraform trying to DELETE and re-create (which would
briefly unban the IP).

### 4.4 `ja4proxy_cidr_ban`

```hcl
resource "ja4proxy_cidr_ban" "bad_hosting" {
  cidr      = "198.51.100.0/24"
  ttl_hours = 168
  reason    = "Hosting provider with no legitimate traffic"
  ticket    = "INC0005200"
}
```

API: POST `/api/v1/bans/cidr/{cidr}`, DELETE `/api/v1/bans/cidr/{cidr}`

### 4.5 `ja4proxy_dial` (singleton)

```hcl
resource "ja4proxy_dial" "prod" {
  setting = 70
  notes   = "Validated via shadow mode simulation sim-20260404-a3f2"
  ticket  = "CHG0001234"
}
```

API: PATCH `/api/v1/dial`. Singleton: only one resource of this type per environment.
If the API returns 202 (pending approval), the Terraform resource is marked as
`create_failed` and the plan output shows the decision_id. CI/CD must check for
pending approvals before marking the pipeline successful.

### 4.6 `ja4proxy_webhook`

```hcl
resource "ja4proxy_webhook" "splunk_hec" {
  url    = "https://splunk.corp.internal:8088/services/collector/event"
  events = ["block", "ban", "campaign", "dial_change"]
  secret = var.splunk_webhook_secret
}
```

API: POST `/api/v1/webhooks`, DELETE `/api/v1/webhooks/{id}`

---

## 5. Drift Handling

The `managed_by` field on every resource is set to `"terraform"` by the provider on
create. This distinguishes provider-managed resources from operator-added entries.

When `protect_unmanaged_entries = true`:
- `terraform plan` shows out-of-band entries as warnings, not as planned destroys
- Plan output prints the `terraform import` command for each unmanaged entry
- To take ownership: `terraform import ja4proxy_ban.name 198.51.100.4`

`managed_by` values and their meaning for the provider:

| `managed_by` value | Owned by | Provider behaviour |
|--------------------|----------|--------------------|
| `"terraform"` | This provider | Full lifecycle management |
| `"policy"` | Phase 82 policy YAML | Not touched by provider; shown as warning if protect=true |
| `"operator"` | Manual UI/API action | Not touched by provider; shown as warning if protect=true |
| `"api"` | Direct API caller | Not touched by provider; shown as warning if protect=true |

### 5.1 Import Workflow

To import all current unmanaged bans into Terraform state:

```bash
# Helper using ja4proxy-cli (Phase 83)
ja4proxy-cli ip ban list --managed-by operator --output json | \
  jq -r '.[] | "terraform import ja4proxy_ban.\(.ip | gsub("[./:]";"_")) \(.ip)"'
```

Document this script in `deploy/terraform/README.md`.

---

## 6. Phase 79 API Mapping

| Terraform Resource | Create | Read | Delete | Notes |
|-------------------|--------|------|--------|-------|
| `ja4proxy_allowlist_entry` | POST `/api/v1/allowlist` | GET `/api/v1/allowlist/{id}` | DELETE `/api/v1/allowlist/{id}` | |
| `ja4proxy_blocklist_entry` | POST `/api/v1/blocklist` | GET `/api/v1/blocklist/{id}` | DELETE `/api/v1/blocklist/{id}` | |
| `ja4proxy_ban` | POST `/api/v1/bans` | GET `/api/v1/bans/{ip}` | DELETE `/api/v1/bans/{ip}` | TTL renewal on plan |
| `ja4proxy_cidr_ban` | POST `/api/v1/bans/cidr/{cidr}` | GET `/api/v1/bans/cidr/{cidr}` | DELETE `/api/v1/bans/cidr/{cidr}` | |
| `ja4proxy_dial` | PATCH `/api/v1/dial` | GET `/api/v1/dial` | no-op | Singleton; 202 → create_failed |
| `ja4proxy_webhook` | POST `/api/v1/webhooks` | GET `/api/v1/webhooks/{id}` | DELETE `/api/v1/webhooks/{id}` | |
| provider (list-managed) | — | GET `?managed_by=terraform` on each list endpoint | — | Drift detection |

---

## 7. Emergency Runbook Playbooks

Three Ansible playbooks in `deploy/ansible/playbooks/emergency/`. Each is 50-100 lines
and tested against the Management API mock (not against real ServiceNow/Slack —
those calls are gated behind `when: servicenow_enabled | bool`).

### 7.1 `emergency-ban-cidr.yml`

```bash
ansible-playbook emergency-ban-cidr.yml \
  -e cidr=198.51.100.0/24 \
  -e reason="Active scanning campaign from this /24" \
  -e ticket=INC0005432 \
  -e ttl_hours=24
```

Steps:
1. POST `/api/v1/bans/cidr/{cidr}` across all nodes (via Management API)
2. Writes to audit trail (automatic via API)
3. `when: servicenow_enabled | bool` — creates ServiceNow incident
4. `when: slack_enabled | bool` — posts to `#security-ops`

### 7.2 `temp-whitelist-ip.yml`

```bash
ansible-playbook temp-whitelist-ip.yml \
  -e ip=203.0.113.5 \
  -e reason="Debugging partner integration — expires in 2 hours" \
  -e ttl_hours=2 \
  -e ticket=CHG0001500
```

Steps:
1. POST `/api/v1/allowlist` with mandatory `expires_at` (now + ttl_hours)
2. Asserts response contains an `id` (fail-fast if API did not confirm)
3. `when: slack_enabled | bool` — posts expiry reminder to `#security-ops`

### 7.3 `maintenance-dial-zero.yml`

```bash
ansible-playbook maintenance-dial-zero.yml \
  -e duration_minutes=60 \
  -e reason="Maintenance window for backend upgrade" \
  -e ticket=CHG0001600
```

Steps:
1. GET `/api/v1/dial` — save current value as `previous_dial`
2. PATCH `/api/v1/dial` with `setting: 0`; abort if 202 (approval required — do not
   suppress four-eyes; call the approver instead)
3. `async` task: `wait_for` `duration_minutes`, then PATCH dial back to `previous_dial`
4. `when: servicenow_enabled | bool` — creates change record with duration and ticket

---

## 8. Test Plan

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
| `TestDial_PendingApproval` | Mock returns 202; resource marked create_failed |
| `TestProvider_InvalidToken` | 401 on any call → clear error with link to token docs |
| `TestProvider_MissingURL` | No url/env → error on provider configure |

### Emergency Playbooks

Use `ansible-playbook --check` mode against the `ManagementAPIMock` HTTP server
started by a pytest fixture:

```bash
tests/integration/test_emergency_playbooks.py
```

Each playbook tested for:
- Correct API call made (method + path + body)
- Abort condition works (dial set returning 202 → playbook exits non-zero)
- `servicenow_enabled=false` and `slack_enabled=false` skip those steps without error

### Makefile target

```makefile
## Phase 93 targets
test-phase-93:
	cd ../terraform-provider-ja4proxy && TF_ACC=1 go test ./internal/... -v -count=1
	python3 -m pytest tests/integration/test_emergency_playbooks.py -v
.PHONY: test-phase-93
```

---

## 9. ADRs Required

| ADR | Decision | Options |
|-----|----------|---------|
| ADR-093a | Repository topology for Terraform provider | Separate repo (recommended) vs subdirectory with own go.mod |
| ADR-093b | Terraform Registry namespace | `ja4proxy/ja4proxy` (self-published, recommended) vs `hashicorp/ja4proxy` (requires partnership) |
| ADR-093c | TTL renewal strategy for `ja4proxy_ban` | Re-POST on apply (recommended) vs dedicated `POST .../renew` endpoint |

---

## 10. Acceptance Criteria

- [ ] ADR-093a (repo topology), ADR-093b (namespace), ADR-093c (TTL renewal) written before coding starts
- [ ] Provider repo exists with correct `go.mod` module path
- [ ] All 6 resource types in §4 implemented with Create/Read/Delete (and Update where applicable)
- [ ] `protect_unmanaged_entries = true` suppresses destroys of non-terraform entries and prints import commands
- [ ] `ja4proxy_dial` correctly handles 202 response (resource marked create_failed, decision_id in error message)
- [ ] `managed_by` field set to `"terraform"` on all resources created by the provider
- [ ] `terraform import` works for all 6 resource types
- [ ] Import helper script documented in `deploy/terraform/README.md`
- [ ] All 7 provider acceptance tests pass (using ManagementAPIMock)
- [ ] Provider passes `tfproviderlint` and `terraform validate` on all example configs
- [ ] Provider published to Terraform Registry (submission initiated; engineering gate is passing `tfproviderlint` + acceptance tests)
- [ ] All 3 emergency playbooks in `deploy/ansible/playbooks/emergency/`
- [ ] Each playbook tested: correct API call made, abort on 202, optional steps skipped when disabled
- [ ] Emergency playbooks documented in `docs/runbooks/emergency_playbooks.md`
- [ ] `make test-phase-93` passes

---

## 11. Business Track (Not Engineering Acceptance Criteria)

- **Terraform Registry publication approval** — Hashicorp reviews provider submissions
  via GitHub PR to the registry repository. Allow 1–2 weeks. Track separately.
- **OperatorHub / ArtifactHub listing** — if publishing the emergency playbooks as an
  Ansible Collection. Out of scope for Phase 93 engineering.
