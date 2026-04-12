# Phase 102 — Phase 93 Gap Closure: Drift Detection, Import, Docs, CI

> **Status:** PROPOSED
> **Size:** MEDIUM
> **Dependencies:** Phase 93 (sub-phases 93.1–93.7 — scaffold is in place)
> **Parent:** Phase 93 (Terraform Provider + Emergency Runbook Playbooks)
> **Why a new phase:** Phase 93 delivered the scaffold (6 resource types, HTTP client,
> 3 Ansible playbooks, static playbook tests). But the phase doc's §11 Acceptance
> Criteria has ~40% of items marked DEFERRED, PARTIAL, or NOT YET. This phase closes
> every remaining gap so the provider is production-ready, not just buildable.

## Sub-phase index

| ID | Sub-phase | Area | Size | Depends on |
|---|---|---|---|---|
| **102a** | Provider config: `protect_unmanaged_entries` field | `internal/provider/` | XS | none |
| **102b** | Drift detection on allowlist/blocklist/watchlist | `internal/resources/` | S | 102a |
| **102c** | `[terraform]` reason prefix on ban + webhook | `internal/resources/` | XS | 102a |
| **102d** | Ban resource: `ticket` + `ttl_hours` fields, 24h expiry detection | `internal/resources/ban.go` | S | 102c |
| **102e** | Dial resource: `ticket`, `notes` fields | `internal/resources/dial.go` | XS | none |
| **102f** | ADRs: ADR-093a (repo topology), ADR-093b (namespace), ADR-093c (TTL) | `docs/decisions/` | XS | none |
| **102g** | CI workflows + `tfproviderlint` + release pipeline | `.github/workflows/` | S | 102f |
| **102h** | Documentation: `deploy/terraform/README.md` refresh, `docs/runbooks/emergency_playbooks.md` | docs/ | XS | none |

Two engineers can parallelise: one takes 102b+102c+102d+102e (Go code), the other
takes 102a+102f+102g+102h (config, ADRs, CI, docs).

---

## 1. Context — what Phase 93 actually delivered

A thorough code audit of the `terraform-provider/` tree and `deploy/ansible/` reveals:

### ✅ Already implemented (do NOT re-do)

| Component | Files | Quality |
|-----------|-------|---------|
| **HTTP client** | `internal/client/client.go` (~300 lines) | Solid. Bearer auth, URL-encoding, 429 retry, health check, all CRUD methods |
| **Provider schema** | `internal/provider/provider.go` | Compiles, validates url/token, health-checks on configure |
| **`ja4proxy_ban`** | `internal/resources/ban.go` + `_test.go` | 6 tests pass. IP+CIDR unified, URL-encoding via `urlWithEncodedPath`, TTL refresh via Update |
| **`ja4proxy_allowlist_entry`** | `internal/resources/allowlist_entry.go` + `_test.go` | ImportState implemented, `managed_by` defaults to `"terraform"`, immutable update (delete+recreate) |
| **`ja4proxy_blocklist_entry`** | `internal/resources/blocklist_entry.go` + `_test.go` | Same pattern as allowlist, import working |
| **`ja4proxy_watchlist_entry`** | `internal/resources/watchlist_entry.go` + `_test.go` | Same pattern, import working |
| **`ja4proxy_dial`** | `internal/resources/dial.go` + `_test.go` | 6 tests pass. Singleton guard, boundary values (0/100), mock validates ±10 delta |
| **`ja4proxy_webhook`** | `internal/resources/webhook.go` + `_test.go` | 6 tests pass. Import working, secret returned on create only, preserve-in-state on read |
| **3 Ansible playbooks** | `deploy/ansible/playbooks/emergency/*.yml` | Bearer auth, conditional ServiceNow/Slack, dial stepping, abort-on-422 |
| **Playbook static tests** | `tests/integration/test_emergency_playbooks.py` (14 tests) | YAML-parsing tests verify structure, auth, endpoints |
| **`deploy/terraform/README.md`** | exists | Has quick-start, resource table, import examples, drift protection blurb |
| **`make test-phase-93`** | Makefile:1203 | Runs `go test ./internal/...` + pytest on playbook tests |
| **`docs/runbooks/emergency_playbooks.md`** | exists | Created by Phase 93 merge |

### ❌ Gaps this phase must close

#### G1 — `protect_unmanaged_entries` not in provider schema (BLOCKING)

**File:** `internal/provider/provider.go`

The provider schema has only `api_url` and `api_token`. The `protect_unmanaged_entries`
field described in §4 of PHASE_93.md does not exist. Without it:
- No drift detection
- No "warning instead of destroy" for out-of-band entries
- The entire SOC 2 compliance story for IaC ownership is broken

**Fix:** Add `protect_unmanaged_entries` (bool, optional, default false) to
`ja4proxyProviderModel` and `Schema()`. Pass it to resources via `Configure`.

**Steps:**
1. Add `ProtectUnmanagedEntries *bool` to `ja4proxyProviderModel` struct in `internal/provider/provider.go`.
2. Add `protect_unmanaged_entries` to the provider `Schema()` map with type `types.BoolType`, `Optional: true`, and `Computed: true` with a default of `false`.
3. In the `Configure` method, pass the resolved value to the resource config (via `resp.DataSourceData` or `resp.ResourceData`) so all resources can read it.
4. Add two unit tests: `TestProvider_ProtectUnmanagedEntries_Default` (verifies default is `false`) and `TestProvider_ProtectUnmanagedEntries_True` (verifies `true` is accepted and propagated).
5. Run `go test ./internal/provider/... -v -count=1` — must pass with zero failures.

**Out of scope:** This sub-phase does not implement drift detection logic or modify any resource files — it only adds the provider config schema field and wiring.

---

#### G2 — Drift detection not implemented on allowlist/blocklist/watchlist (BLOCKING)

**Files:** `internal/resources/allowlist_entry.go`, `blocklist_entry.go`, `watchlist_entry.go`

The `Read` method fetches the entry by ID and returns it. It does **not** check
whether the entry still exists in the API's list of `managed_by=terraform` entries.
If an operator deletes the entry via the UI, Terraform won't detect the drift until
the next plan — and even then, it will just try to re-create, which may conflict
with the `protect_unmanaged_entries` policy.

**Fix:** In each resource's `Read` method, after fetching by ID:
1. If the entry is gone from the API, check `protect_unmanaged_entries`:
   - If `false`: call `resp.State.RemoveResource(ctx)` (current behavior)
   - If `true`: add a diagnostic warning but keep the resource in state
2. During `PlanModify`, if `protect_unmanaged_entries` is true and an out-of-band
   entry is found, emit a warning rather than planning a destroy.

The actual drift-detection loop requires a `DataSource` that lists all managed
entries. This is the hardest part of the phase.

**Implementation approach:**
- Add a data source `ja4proxy_managed_entries` that calls `GET /api/v1/{list}?managed_by=terraform`
- During `terraform plan`, the provider compares the data source results against
  state and emits warnings for discrepancies
- This is a **data source**, not a resource — it runs at plan time, not apply time

**Steps:**
1. Create `internal/data_sources/managed_entries.go` implementing `ja4proxy_managed_entries` data source that calls `GET /api/v1/{list}?managed_by=terraform` for each list type (allowlist, blocklist, watchlist).
2. Register the data source in `internal/provider/provider.go` via `Datasource()` method.
3. In each list resource's `Read` method (`allowlist_entry.go`, `blocklist_entry.go`, `watchlist_entry.go`), after fetching by ID: if the entry is gone and `protect_unmanaged_entries` is `false`, call `resp.State.RemoveResource(ctx)`; if `true`, add a diagnostic warning but keep the resource in state.
4. Add a `PlanModifier` that checks `protect_unmanaged_entries` during plan: if an out-of-band entry is detected, emit a warning instead of planning a destroy.
5. Write `TestAllowlistEntry_DriftWarning` (and equivalent for blocklist/watchlist) — delete entry out-of-band, run plan, assert warning diagnostic is emitted.
6. Run `go test ./internal/resources/... -v -count=1` — must pass with zero failures.

**Out of scope:** This sub-phase does not introduce new resource types. It implements Read-time drift detection only — plan-time drift warnings via the data source are covered but full plan-time drift scanning across all entries is limited to what the data source provides.

---

#### G3 — `[terraform]` reason prefix not applied to ban + webhook (HIGH)

**Files:** `internal/resources/ban.go`, `webhook.go`

The Phase 93 critical review (Finding 3) decided that since the ban and webhook
API endpoints don't have a `managed_by` field, the provider should prefix the
`reason` with `[terraform]` for ownership identification.

**What exists:** The `ban` resource sends `reason` as-is from the Terraform config.
The `webhook` resource doesn't have a `reason` field at all — it uses the API's
`managed_by` field (which the API returns, but the provider doesn't set on create).

**Fix:**
- **Ban:** On Create, prefix the reason: `"[terraform] " + plan.Reason`. On Read,
  strip the prefix when populating state. On Delete, no change needed.
- **Webhook:** The API already has `managed_by` on webhooks. The provider should
  set it on create by including it in the POST body. Check if the API accepts
  `managed_by` in the create request — if not, fall back to prefixing `url` or
  a custom header field.

**Steps:**
1. In `internal/resources/ban.go`, modify the `Create` method to prefix the reason: `"[terraform] " + plan.Reason` before sending the POST body to the API.
2. In the `Read` method, detect the `[terraform] ` prefix on the returned reason and strip it before populating state so the user sees their original value.
3. In `internal/resources/webhook.go`, add `managed_by` to the POST body on create with value `"terraform"`. If the API does not accept `managed_by`, document the fallback in the resource schema description.
4. Add `TestBan_TicketAndReason` — create a ban, assert the API receives `[terraform] ` prefixed reason.
5. Add `TestBan_ReadStripsPrefix` — create a ban with prefix, read back, assert state contains unprefixed reason.
6. Add `TestWebhook_ManagedBySet` — create a webhook, assert `managed_by = "terraform"` is in the POST body.
7. Run `go test ./internal/resources/... -v -count=1` — must pass with zero failures.

**Out of scope:** This sub-phase does not add new fields to the ban or webhook resources and does not change the Management API contract — it only modifies how the provider formats outgoing requests and parses incoming responses.

---

#### G4 — Ban resource missing `ticket` and `ttl_hours` fields (HIGH)

**File:** `internal/resources/ban.go`

The Phase 93 doc (§5.4) shows `ticket` as an attribute and uses `ttl_hours` in
the HCL example. The actual schema has:
- `ip` (string, required)
- `ttl` (int64, required) — **in seconds, not hours**
- `reason` (string, required)
- No `ticket` field

**Fix:**
- Add `ticket` (string, optional) to the schema
- Add `ttl_hours` (int64, optional) as an alternative to `ttl`. If `ttl_hours`
  is set, compute `ttl = ttl_hours * 3600`. One of `ttl` or `ttl_hours` must
  be provided (validate at plan time).
- Store `ticket` in the reason string or as a separate API field if the API
  supports it.

**Steps:**
1. Add `ticket` (string, optional) to the ban resource schema in `internal/resources/ban.go`.
2. Add `ttl_hours` (int64, optional) to the ban resource schema as an alternative to `ttl`.
3. Add a `PlanModifier` or validation function that requires exactly one of `ttl` or `ttl_hours` — error if both or neither are set.
4. In the `Create` method: if `ttl_hours` is set, compute `ttl = ttl_hours * 3600` before sending to the API. If `ticket` is set, append it to the reason string (e.g., `"[terraform] <reason> (ticket: <ticket>)"`) or send as a separate field if the API supports it.
5. In the `Read` method, populate `ttl_hours` from `ttl / 3600` and populate `ticket` from state or parse from reason if stored there.
6. In the `Update` method, apply the same `ttl_hours` → `ttl` conversion logic.
7. Write `TestBan_TicketField` — create a ban with `ticket`, assert it appears in state.
8. Write `TestBan_TTLHours` — create a ban with `ttl_hours = 24`, assert the API receives `ttl = 86400`.
9. Run `go test ./internal/resources/... -v -count=1` — must pass with zero failures.

**Out of scope:** This sub-phase does not implement TTL auto-detection at 24h (that is 102h) and does not modify the Management API endpoint — the provider adapts to the existing API.

---

#### G5 — Dial resource missing `ticket` and `notes` (MEDIUM)

**File:** `internal/resources/dial.go`

The Phase 93 doc (§5.5) shows `ticket` and `notes` attributes. The actual schema
only has `value`.

**Fix:**
- Add `ticket` (string, optional) — include in the PATCH body if the API accepts it
- Add `notes` (string, optional) — same
- If the API's `PATCH /api/v1/dial` doesn't accept these fields, store them as
  Terraform-only metadata (computed state, not sent to API). Document this
  limitation.

**Steps:**
1. Add `ticket` (string, optional) to the dial resource schema in `internal/resources/dial.go`.
2. Add `notes` (string, optional) to the dial resource schema.
3. In the `Create`/`Update` method, attempt to include `ticket` and `notes` in the PATCH body. If the API returns a 400/422 indicating unknown fields, silently omit them and store them as Terraform-only state (set in state but not sent to API).
4. In the `Read` method, preserve `ticket` and `notes` from prior state (they are Terraform-only if the API does not accept them).
5. Add a schema description note on both fields documenting whether they are sent to the API or stored locally only.
6. Write `TestDial_TicketAndNotes` — create a dial with `ticket` and `notes`, assert both appear in state.
7. Run `go test ./internal/resources/... -v -count=1` — must pass with zero failures.

**Out of scope:** This sub-phase does not modify the dial Management API. If the API does not accept `ticket` or `notes`, the limitation is documented in the schema — the API is not changed to support them.

---

#### G6 — No ADRs written (MEDIUM)

**Required by PHASE_93.md §10.** None of the three ADRs exist:

| ADR | Decision | Recommendation |
|-----|----------|---------------|
| ADR-093a | Repository topology | Keep in-tree during development (`terraform-provider/`), extract to separate repo before Registry publication. Document the extraction procedure. |
| ADR-093b | Terraform Registry namespace | `ja4proxy/ja4proxy` (self-published). No HashiCorp partnership needed. |
| ADR-093c | TTL renewal strategy for `ja4proxy_ban` | Re-POST on apply (already implemented via `Update`). The API's idempotent POST resets the TTL. No dedicated `/renew` endpoint needed. |

**Steps:**
1. Create `docs/decisions/ADR-093a-repository-topology.md` documenting the decision to keep the provider in-tree during development (`terraform-provider/`) and extract to a separate repo before Registry publication. Include the extraction procedure.
2. Create `docs/decisions/ADR-093b-terraform-registry-namespace.md` documenting the decision to use `ja4proxy/ja4proxy` namespace (self-published, no HashiCorp partnership).
3. Create `docs/decisions/ADR-093c-ttl-renewal-strategy.md` documenting the decision to re-POST on apply for TTL renewal (API's idempotent POST resets TTL, no dedicated `/renew` endpoint needed).
4. Follow the ADR template in `docs/decisions/` (if one exists) or use standard ADR format: Context, Decision, Consequences, Status.
5. Verify all three ADRs are referenced from `docs/decisions/README.md` (or the index file used by the project).

**Out of scope:** This sub-phase is documentation-only — no code changes, no CI modifications, and no Terraform Registry submission (that is an external process tracked separately).

---

#### G7 — No CI workflows for terraform-provider (MEDIUM)

**Required by PHASE_93.md §9 success criteria.** The provider has no `.github/workflows/`
directory. The Phase 93 manifest (93.5) requires:
- `.github/workflows/test.yml` — unit + acceptance tests on every PR
- `.github/workflows/release.yml` — publishes to Terraform Registry on tag

**Fix:** Create both workflows. The test workflow should:
1. `go test ./internal/... -v -count=1` (unit tests, no mock server needed)
2. `TF_ACC=1 go test ./internal/... -v -count=1` (acceptance tests against
   in-process mock servers — the existing mock servers in `*_test.go` files
   are sufficient)
3. `go vet ./...`
4. `golangci-lint run` (if a `.golangci.yaml` is added to the provider)

The release workflow should use goreleaser/goreleaser-action to build multi-arch
binaries and push to the Terraform Registry.

**Steps:**
1. Create `.github/workflows/terraform-provider-test.yml` with jobs for: `go vet ./...`, `go test ./internal/... -v -count=1`, `TF_ACC=1 go test ./internal/... -v -count=1` (acceptance tests), and `golangci-lint run` (if `.golangci.yaml` exists in the provider tree). Trigger on `pull_request` targeting the provider directory.
2. Add optional `tfproviderlint` step: run `go install github.com/bflad/tfproviderlint/cmd/tfproviderlintx@latest` and `tfproviderlintx ./...`. If the tool reports violations, document any suppressions with justification.
3. Create `.github/workflows/terraform-provider-release.yml` using `goreleaser/goreleaser-action`. Trigger on `push` of tags matching `v*`. Configure to build multi-arch binaries (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64) and publish to the Terraform Registry via the Registry API.
4. Ensure both workflows use the correct Go version (read from `go.mod` or pin explicitly).
5. Test the test workflow locally by pushing to a branch and verifying the Actions run passes.
6. Run `make test-phase-93` locally — must exit 0.

**Out of scope:** This sub-phase does not introduce new resource types (102b–102e handle those) and does not write ADRs (that is 102f). Terraform Registry submission is configured here but the actual Registry review/approval process is external to this phase.

---

#### G8 — Ban TTL renewal lacks 24h near-expiry detection (LOW)

**File:** `internal/resources/ban.go`

The `Update` method re-POSTs the ban to refresh the TTL, but it doesn't
automatically detect when a ban is within 24 hours of expiry. The Phase 93
doc (§5.4) says:

> "On the next `terraform apply`, it re-POSTs the ban to reset the TTL."

This works if the user runs `terraform apply` regularly, but there's no
automated detection. The `Read` method gets `ttl_remaining` from the API
but doesn't use it to trigger a refresh.

**Fix:** In `Read`, if `ttl_remaining <= 86400` (24h), mark the resource
as "needs refresh" by setting a private state flag. On the next `PlanModify`,
if the flag is set and the config hasn't changed, plan an Update to refresh
the TTL. This is an optimization — not required for correctness, since
the user can always run `terraform apply -refresh-only`.

---

#### G9 — `docs/runbooks/emergency_playbooks.md` needs content audit (LOW)

**File:** `docs/runbooks/emergency_playbooks.md`

This file was created by the Phase 93 merge. Verify it covers:
- All 3 playbooks with usage examples
- Prerequisites (Ansible, `ja4proxy_token`, optional ServiceNow/Slack vars)
- Safety constraints (dial ±10 stepping, abort-on-422)
- Troubleshooting (common failure modes)

Update any sections that don't match the actual playbook content.

**Steps:**
1. Read `docs/runbooks/emergency_playbooks.md` in full.
2. Read each of the 3 Ansible playbooks in `deploy/ansible/playbooks/emergency/*.yml`.
3. Verify the doc covers each playbook with: name, purpose, required variables, usage example command, and expected output.
4. Verify the doc lists prerequisites: Ansible installation, `ja4proxy_token`, optional ServiceNow/Slack variables.
5. Verify the doc documents safety constraints: dial ±10 stepping, abort-on-422 behavior.
6. Verify the doc includes a troubleshooting section with common failure modes (auth errors, 422 responses, network timeouts, missing variables).
7. Update any sections that are inaccurate, incomplete, or don't match the actual playbook files.
8. Run `python3 -m pytest tests/integration/test_emergency_playbooks.py -v` — all 14 tests must pass.

**Out of scope:** This sub-phase is an audit-only exercise — no new playbook content is written beyond what already exists in the Ansible YAML files, and no code changes are made. If gaps are found between the doc and the playbooks, the doc is updated to match the playbooks (the playbooks themselves are not modified).

---

## 2. Acceptance criteria

### Code

- [ ] `protect_unmanaged_entries` field present in provider schema with default `false`
- [ ] `managed_by = "terraform"` verified on create for allowlist, blocklist, watchlist
- [ ] `[terraform]` reason prefix on ban resource (create and read)
- [ ] Webhook resource sets `managed_by` on create (or documents fallback)
- [ ] Ban resource has `ticket` field
- [ ] Ban resource supports `ttl_hours` as alternative to `ttl`
- [ ] Dial resource has `ticket` and `notes` fields
- [ ] All existing tests still pass
- [ ] New tests added for drift detection, ticket fields, ttl_hours conversion

### Documentation

- [ ] ADR-093a (repo topology) written and merged
- [ ] ADR-093b (namespace) written and merged
- [ ] ADR-093c (TTL renewal) written and merged
- [ ] `deploy/terraform/README.md` updated with `protect_unmanaged_entries` usage
- [ ] `docs/runbooks/emergency_playbooks.md` audited and updated

### CI/CD

- [ ] `.github/workflows/terraform-provider-test.yml` exists and runs on PR
- [ ] `.github/workflows/terraform-provider-release.yml` exists for tag-based releases
- [ ] `tfproviderlint` exits 0 (or documented as deferred with justification)
- [ ] `make test-phase-93` passes with zero failures

### Manifest

- [ ] `docs/phases/manifest.yaml`: Phase 93 sub-phases 93.1–93.7 marked COMPLETE
- [ ] Phase 102 marked COMPLETE
- [ ] `python3 scripts/sync-roadmap.py` run
- [ ] `make lint-phases` exits 0

---

## 3. Test strategy

### Go unit tests (in `terraform-provider/internal/resources/`)

| Test | What it verifies |
|------|-----------------|
| `TestBan_TicketField` | `ticket` accepted in config, stored in state |
| `TestBan_TTLHours` | `ttl_hours = 24` → `ttl = 86400` sent to API |
| `TestBan_TicketAndReason` | `[terraform]` prefix applied to reason |
| `TestBan_ReadStripsPrefix` | `[terraform] ` stripped from reason on read |
| `TestDial_TicketAndNotes` | `ticket` and `notes` accepted in config |
| `TestProvider_ProtectUnmanagedEntries_Default` | defaults to `false` |
| `TestProvider_ProtectUnmanagedEntries_True` | accepted and passed to resources |

### Go acceptance tests

The existing mock servers in `*_test.go` already support acceptance testing.
Add:
- `TestAllowlistEntry_DriftWarning` — entry deleted out-of-band, warning emitted
- `TestWebhook_ManagedBySet` — `managed_by = "terraform"` in API request body

### Python tests

No new Python tests needed — the playbook static tests (14 tests) are complete.
The `make test-phase-93` target already runs them.

---

## 4. Out of scope

- Terraform Registry publication (requires separate HashiCorp review process)
- Moving the provider to a separate GitHub repository (tracked by ADR-093a as a
  post-completion action)
- `ja4proxy_cidr_ban` resource (consolidated into `ja4proxy_ban` in Phase 93 review)
- Management API changes (the provider adapts to the existing API, not vice versa)
- Ansible playbook runtime tests against a live Management API (static YAML tests
  is the current bar; live tests require a running API instance)
- Phase 94 (Kubernetes Operator) — separate phase, separate repo

---

## 5. Implementation order

1. **102a** — Add `protect_unmanaged_entries` to provider schema (30 min)
2. **102f** — Write the 3 ADRs (1 hour, can be done in parallel with 102a)
3. **102c** — Add `[terraform]` prefix to ban reason (30 min)
4. **102d** — Add `ticket` + `ttl_hours` to ban resource (1 hour)
5. **102e** — Add `ticket` + `notes` to dial resource (30 min)
6. **102b** — Drift detection data source + warnings (2 hours, hardest item)
7. **102g** — CI workflows (1 hour)
8. **102h** — Doc audit + README updates (30 min)

Total estimated effort: ~6 hours of focused work.
