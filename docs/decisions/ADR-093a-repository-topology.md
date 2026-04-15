# ADR-093a: Terraform Provider Repository Topology

**Status:** Accepted
**Date:** 2026-04-15
**Phase:** 93 (Terraform Provider + Emergency Runbook Playbooks), finalized in Phase 102

---

## Context

Phase 93 delivered a Terraform provider for JA4proxy that manages allowlist,
blocklist, watchlist, ban, dial, and webhook resources through the Management
API. The provider was initially drafted in-tree under `deploy/terraform/` during
early Phase 93 iterations, but it was extracted to a separate repository before
publication:

- **External repo (on-disk):** `/home/sean/LLM/terraform-provider-ja4proxy`
- **External repo (remote):** `github.com/anomalyco/terraform-provider-ja4proxy`
  (module path verbatim from the external `go.mod`)

Two factors forced the split:

1. **Independent versioning.** The provider follows Terraform Registry semver
   conventions (`v1.x.y`, release tags drive goreleaser). That cadence is
   unrelated to the main repo's phase-based release cadence.
2. **Registry publication mechanics.** The Terraform Registry requires a
   dedicated top-level repository with a specific layout (`terraform-provider-*`
   naming, root-level goreleaser config, GPG-signed tags). Nesting it under
   `deploy/terraform/` inside the monorepo would have blocked Registry
   acceptance.

---

## Decision

**The Terraform provider lives in a separate repository.** The contract
boundary between the two repositories is the **Management API** — a versioned,
tested HTTP surface that both sides treat as the stable contract.

- Main repo (`JA4proxy`) owns: architectural decisions, the Management API
  definition, the Ansible runbook playbooks, and user-facing Terraform
  documentation under `deploy/terraform/`.
- External repo (`terraform-provider-ja4proxy`) owns: the provider
  implementation, its own unit and acceptance tests, goreleaser config, and
  its own `CHANGELOG.md`.

Both repos refer to each other by URL or relative path, never by file line
number.

---

## Consequences

### Positive
- Provider can release independently of the proxy core. A provider bugfix does
  not need to wait for a JA4proxy phase close-out.
- Registry publication works out of the box — no monorepo shims.
- Acceptance tests in the provider repo can spin up a disposable JA4proxy
  stack via docker-compose without dragging in the full main-repo test matrix.

### Negative
- Cross-repo coordination overhead. A change to the Management API that
  affects the provider requires a coordinated PR pair.
- Two CI systems to keep green.
- **ADRs in this repo that reference external-repo code must reference
  symbols by name, not line numbers.** Line numbers rot silently across repo
  boundaries — a rename in the external repo produces no diff in this one,
  and the ADR becomes quietly wrong. See ADR-093c for examples of
  symbol-name references (`banResource.Update`, `ja4proxyProvider.Configure`,
  `banListEntry.TTLRemaining`).

### Neutral
- Users install the provider from the Terraform Registry (see ADR-093b for
  namespace choice), not from a checkout of this repo.

---

## Related

- ADR-093b — Terraform Registry namespace selection
- ADR-093c — TTL renewal strategy and drift-detection decision
- `deploy/terraform/README.md` — user-facing quick-start that points at the
  external repo
