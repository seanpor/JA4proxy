# ADR-094c: ManagedBy Enum Extension for Kubernetes Operator

**Status:** Accepted
**Date:** 2026-04-12
**Phase:** 94a (Kubernetes Operator + NetBox + ServiceNow CMDB)

---

## Context

The `ManagedBy` enum at `management/api/models.py:238` defines the source of truth
for canonical list entries (allowlist, blocklist, watchlist). Its values are:
`terraform`, `operator`, `api`, `analytics`, `legacy`, `migration`, `feed`.

Phase 94 introduces a Kubernetes operator that reconciles CRD specs against the
Management API. The operator needs its own `managed_by` discriminator so that:

1. Operator-managed entries can be filtered independently from terraform-managed,
   policy-managed, and CLI-managed entries.
2. The operator's reconciliation loop can diff its spec against
   `GET /api/v1/allowlist?managed_by=operator_k8s` without seeing entries managed
   by other systems.
3. Audit trails can distinguish operator-initiated changes from human-initiated
   changes via the API or terraform.

The original enum had no value representing the Kubernetes operator. POSTing
`managed_by=operator-k8s` (or any unrecognised value) returned HTTP 422.

Two options were considered:

| | Option A: Add `operator_k8s` | Option B: Reuse `operator` + `subsystem` field |
|---|---|---|
| **Schema change** | Single enum value addition | New `subsystem` field on ResourceCreate/ResourceResponse |
| **Filtering** | `?managed_by=operator_k8s` works out of the box | Requires new query param `?subsystem=k8s` plus code changes |
| **Clarity** | Immediately clear in audit logs and API responses | Ambiguous: `operator` could mean CLI operator or K8s operator |
| **Backward compat** | Additive only — no breaking change | New field defaults to `null`; all existing callers unaffected |
| **Complexity** | Minimal — one line of code + tests | Moderate — new field, new validation, new query logic |

---

## Decision

**Option A: Add `operator_k8s` to the `ManagedBy` enum.**

The value is `operator_k8s` (snake_case) to match the Pydantic/Python naming
convention used by all existing enum values. The hyphenated form `operator-k8s`
was rejected because Pydantic enums use underscores, and the JSON serialisation
would require a custom `__str__` or value mapping to produce hyphens.

---

## Rationale

The `ManagedBy` enum already uses snake_case values that serialise directly to
JSON strings (`terraform`, `analytics`, etc.). Adding `operator_k8s` is consistent
with this pattern. A `subsystem` discriminator would add surface area to the API
contract for a problem that a single enum value solves cleanly.

The existing route handlers at `management/api/routes/canonical_lists.py` already
pass `managed_by` through unchanged — the POST handler reads `body.managed_by.value`
and the GET handler accepts an optional `managed_by` query parameter. No route
logic changes are required.

---

## Consequences

- `management/api/models.py`: `ManagedBy` enum gains `operator_k8s = "operator_k8s"`.
- The Kubernetes operator's reconciliation loop uses `managed_by=operator_k8s`
  when creating or deleting allowlist/blocklist/watchlist entries.
- `GET /api/v1/allowlist?managed_by=operator_k8s` returns only operator-managed
  entries, enabling clean diff-based reconciliation.
- Audit log entries for operator-initiated changes carry `managed_by: operator_k8s`,
  making them trivially filterable in SIEM and compliance reports.
- A separate issue was observed: `src/governance/policy_applier.py` writes
  `managed_by="policy"` which is also not in the enum. This is filed as a
  Phase 101 entry for the policy / Management API owner to triage.
