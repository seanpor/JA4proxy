# ADR-093b: Terraform Registry Namespace Selection

**Status:** Accepted
**Date:** 2026-04-15
**Phase:** 93 (Terraform Provider + Emergency Runbook Playbooks), finalized in Phase 102

---

## Context

The Terraform Registry requires every published provider to live under a
namespace. Two publication paths are available:

| Path | Requirements | Benefits |
|---|---|---|
| **HashiCorp Partner Programme** | Legal paperwork, partner agreement, HashiCorp review of the integration | Official "Partner" badge on the Registry listing; higher discoverability |
| **Self-publish (community tier)** | GitHub repo, signed release tags, goreleaser manifest, GPG key uploaded to Registry | No legal paperwork; same functional capability as Partner tier |

The provider repository is already named
`github.com/anomalyco/terraform-provider-ja4proxy` (module path verified in
the external `go.mod`), so the self-publish namespace is effectively chosen
by the GitHub org under which the repo sits.

---

## Decision

**Self-publish the provider under the namespace reflected in the external
repo's `go.mod`:** `anomalyco/ja4proxy`. No HashiCorp Partner Programme
status is pursued at this time.

The release process is **goreleaser-driven**, configured in the external
repo's `.github/workflows/release.yml`. Release tags (`v1.x.y`) on the
external repo trigger the workflow, which builds cross-platform binaries,
signs them with the registered GPG key, and uploads them as a GitHub
release — from which the Terraform Registry then ingests them.

---

## Consequences

### Positive
- No legal review cycle blocking release cadence.
- Community-tier providers are fully functional on the Registry — the
  Partner badge is purely cosmetic.
- Release is reproducible and auditable via goreleaser + signed tags.

### Negative
- No Partner badge. Prospective users who filter the Registry for Partner
  providers will not see this one until (and unless) the Partner application
  is pursued in a later phase.
- Users must add the provider with an explicit `source` attribute:

  ```hcl
  terraform {
    required_providers {
      ja4proxy = {
        source  = "anomalyco/ja4proxy"
        version = "~> 1.0"
      }
    }
  }
  ```

  There is no short-form alias for community-tier providers.

### Operational
- Registry submission status: **pending registration** at the time this ADR
  was written. The `anomalyco` org and GPG key exist; the final Registry
  "publish" action has not yet been performed. The namespace above is the
  intended namespace, not a confirmed live listing.
- When the Registry listing goes live, update this ADR with the activation
  date and the public Registry URL.

---

## Related

- ADR-093a — Repository topology (why the provider is in a separate repo)
- ADR-083a — Release tooling for `ja4proxy-cli` (parallel goreleaser pattern)
- External repo: `.github/workflows/release.yml` (release workflow)
