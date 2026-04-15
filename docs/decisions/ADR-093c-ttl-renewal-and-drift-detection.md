# ADR-093c: Ban TTL Renewal and Drift-Detection Strategy

**Status:** Accepted
**Date:** 2026-04-15
**Phase:** 93 (Terraform Provider + Emergency Runbook Playbooks), finalized in Phase 102

---

## Context

The Terraform provider needs to solve two related lifecycle problems for
resources whose underlying state lives in Redis with a TTL:

1. **Ban TTL renewal.** `ja4proxy_ban` entries have a finite TTL (required by
   the Management API — infinite bans are rejected). Operators expect
   `terraform apply` to keep a ban alive for as long as it remains in the
   Terraform configuration, without racing the expiry clock or briefly
   unbanning an IP during a DELETE-then-recreate cycle.

2. **Drift detection.** Entries in allowlists, blocklists, and watchlists may
   be added out-of-band (via the UI, `ja4proxy-cli`, or direct API calls).
   An earlier Phase 93 draft proposed a `ja4proxy_managed_entries` data
   source so operators could diff Terraform state against reality at plan
   time.

This ADR records the final decisions on both.

---

## Decision 1 — TTL Renewal: re-POST on apply, idempotent endpoint

The `ja4proxy_ban` resource uses a **re-POST on apply** strategy.

- `banResource.Create` and `banResource.Update` both `POST
  /api/v1/bans/{encoded_ip}` with the full `ttl` and `reason` body. The
  Management API's POST is idempotent — re-POSTing the same IP resets the
  expiry without a 409.
- The resource schema documents a 24-hour renewal window: the
  `ttl_hours` attribute description states that Terraform "re-POSTs the ban
  when within 24 hours of expiry to maintain it." The
  `banListEntry.TTLRemaining` field (populated by the list-bans endpoint at
  `banResource.Read`) is the hook through which the near-expiry check is
  wired — when `TTLRemaining` drops below 86400 seconds, the next apply
  refreshes the ban.
- There is **no dedicated `/renew` endpoint.** Adding one would require a
  Management API change (Phase 79 scope) and the idempotent POST solves the
  same problem without the DELETE-then-recreate race that would briefly
  unban the IP.
- `last_renew` (computed ISO 8601 string) records the last successful POST
  so operators can audit renewal cadence from Terraform state.

### Why this is safe
- No unban gap — the ban is never deleted during renewal.
- No API change required — the existing POST already resets TTL.
- Terraform users set `ttl_hours = 720` (30 days) and forget; the provider
  handles refreshes.

---

## Decision 2 — Drift Detection: no data source, rely on protection flag

**No `ja4proxy_managed_entries` data source is shipped.**

Rationale: the failure mode a data source would address — out-of-band
entries being destroyed by `terraform apply` — is already prevented at the
provider level by two mechanisms:

1. **`PlanModifiers` on list resources.** `list_resources.go` marks the
   entry identifiers with `stringplanmodifier.RequiresReplace()`, so changes
   to the key force recreation rather than silent in-place modification.
2. **`protect_unmanaged_entries` defaults to `true`.** The provider-level
   flag (`ja4proxyProvider.Configure` in the external repo's
   `internal/provider/provider.go`) defaults to `true` when the attribute is
   null — verified by the branch
   `if config.ProtectUnmanaged.IsNull() { protectUnmanaged = true }`. When
   true, `banResource.Delete` refuses to remove any entry whose `reason`
   does not start with the `[terraform]` ownership marker, returning a
   diagnostic that tells the operator to either flip the flag or
   `terraform state rm` the resource.

Phase 93's original draft proposed `false` as the default (matching typical
Terraform behaviour of "what's in state is the source of truth"). The
external repo chose `true` instead — the safer default for a security tool,
where accidentally destroying an out-of-band blocklist entry is a
security-relevant event, not a mere state-drift nuisance.

---

## Consequences

### Positive
- TTL renewal is invisible to operators — just run `terraform apply` on any
  schedule that is comfortably under the ban TTL.
- No Management API changes required for Phase 93.
- Out-of-band security entries are protected by default.

### Negative
- **Operators lose plan-time visibility into drift.** Without a
  `ja4proxy_managed_entries` data source, there is no way to ask
  `terraform plan` "what entries exist in the Management API that are not in
  my Terraform state?" The counterfactual — an operator discovers drift
  only when they try to delete an entry and hit the protection error — is
  acceptable but not ideal.
- **Mitigation.** The Management API's `management:policy_audit` log
  (append-only LIST, last 1000 entries) still captures every out-of-band
  change with attribution. Operators who need drift visibility can grep the
  audit log; the SIEM integration already surfaces these events. Drift is
  therefore visible, just not at `terraform plan` time.
- **Future work.** If a concrete operator need emerges — e.g., a compliance
  auditor requires Terraform-reported drift as part of a control — a
  `ja4proxy_managed_entries` data source can be added in a follow-up phase
  without breaking changes. This ADR does not preclude it; it defers it
  until justified by demand.

### Verified symbols (external repo)
- `banResource.Create`, `banResource.Update`, `banResource.Delete` in
  `internal/resources/ban_resource.go`
- `banListEntry.TTLRemaining` in `internal/resources/ban_resource.go`
- `ja4proxyProvider.Configure` and the `ProtectUnmanaged.IsNull()` default
  in `internal/provider/provider.go`
- List-resource `RequiresReplace` plan modifiers in
  `internal/resources/list_resources.go`

Line numbers are deliberately omitted per ADR-093a: cross-repo line
references rot silently.

---

## Related

- ADR-093a — Repository topology
- ADR-093b — Registry namespace
- External repo draft: `docs/ADR-093c.md` (superseded by this ADR; the
  external draft covered TTL renewal only and did not address drift
  detection)
