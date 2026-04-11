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

---

#### G6 — No ADRs written (MEDIUM)

**Required by PHASE_93.md §10.** None of the three ADRs exist:

| ADR | Decision | Recommendation |
|-----|----------|---------------|
| ADR-093a | Repository topology | Keep in-tree during development (`terraform-provider/`), extract to separate repo before Registry publication. Document the extraction procedure. |
| ADR-093b | Terraform Registry namespace | `ja4proxy/ja4proxy` (self-published). No HashiCorp partnership needed. |
| ADR-093c | TTL renewal strategy for `ja4proxy_ban` | Re-POST on apply (already implemented via `Update`). The API's idempotent POST resets the TTL. No dedicated `/renew` endpoint needed. |

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
