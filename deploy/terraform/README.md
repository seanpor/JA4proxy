# JA4proxy Terraform Provider

Manage JA4proxy security rules via Infrastructure as Code.

## Provider Repository

The Terraform provider lives in a separate repository:
[`github.com/anomalyco/terraform-provider-ja4proxy`](https://github.com/anomalyco/terraform-provider-ja4proxy)

## Quick Start

```hcl
terraform {
  required_providers {
    ja4proxy = {
      source  = "ja4proxy/ja4proxy"
      version = "~> 1.0"
    }
  }
}

provider "ja4proxy" {
  url   = "http://localhost:8090"
  token = var.ja4proxy_token

  # Protect entries added out-of-band from being destroyed.
  # Defaults to true if omitted — see Drift protection below.
  # protect_unmanaged_entries = true
}
```

## Resource Types

| Resource | Purpose |
|----------|---------|
| `ja4proxy_allowlist_entry` | Allowlisted JA4 fingerprints |
| `ja4proxy_blocklist_entry` | Blocklisted JA4 fingerprints |
| `ja4proxy_watchlist_entry` | Watchlisted IPs |
| `ja4proxy_ban` | Banned IPs and CIDRs (unified resource) |
| `ja4proxy_dial` | Risk score dial threshold (singleton) |
| `ja4proxy_webhook` | Event delivery webhooks |

## Import Workflow

To import all existing unmanaged entries into Terraform state:

```bash
# Import all existing bans
ja4proxy-cli ip ban list --output json | \
  jq -r '.[] | "terraform import ja4proxy_ban.\(.ip | gsub("[./:]";"_")) \(.ip)"'

# Import all existing allowlist entries
ja4proxy-cli fingerprint allowlist list --output json | \
  jq -r '.[] | "terraform import ja4proxy_allowlist_entry.\(.id) \(.id)"'

# Import all existing blocklist entries
ja4proxy-cli fingerprint blocklist list --output json | \
  jq -r '.[] | "terraform import ja4proxy_blocklist_entry.\(.id) \(.id)"'
```

## Drift Protection

The provider ships with `protect_unmanaged_entries` defaulting to **`true`** —
the safer default for a security tool. See
[ADR-093c](../../docs/decisions/ADR-093c-ttl-renewal-and-drift-detection.md)
for the rationale.

When `protect_unmanaged_entries = true`:
- Out-of-band entries appear as **warnings** in `terraform plan`, not as planned destroys
- Plan output prints the `terraform import` command for each unmanaged entry
- `managed_by = "terraform"` (and the `[terraform]` reason prefix on bans)
  distinguishes provider-managed resources from operator-added entries
- `terraform apply` refuses to delete entries that lack the `[terraform]`
  ownership marker

### Overriding the default

To allow Terraform to destroy out-of-band entries, pick one:

1. **Disable protection globally** (not recommended for production):

   ```hcl
   provider "ja4proxy" {
     url                       = "http://localhost:8090"
     token                     = var.ja4proxy_token
     protect_unmanaged_entries = false
   }
   ```

2. **Acknowledge orphaning per-resource** — remove the resource from
   Terraform state so the next apply no longer tries to destroy it:

   ```bash
   terraform state rm ja4proxy_ban.<NAME>
   ```

   This leaves the underlying ban in place in the Management API; it is
   simply no longer Terraform's concern.

## Development

See the provider repository's `GNUmakefile` for build and test targets:

```bash
cd terraform-provider-ja4proxy
make test       # unit tests
make testacc    # acceptance tests
make lint       # go vet + gofmt
```

## See also

- [ADR-093a — Terraform provider repository topology](../../docs/decisions/ADR-093a-repository-topology.md)
  explains why the provider code lives in a separate repository and how the
  Management API serves as the cross-repo contract boundary.
- [ADR-093b — Terraform Registry namespace selection](../../docs/decisions/ADR-093b-terraform-registry-namespace.md)
  records the self-publish route and the `anomalyco/ja4proxy` namespace.
- [ADR-093c — Ban TTL renewal and drift-detection strategy](../../docs/decisions/ADR-093c-ttl-renewal-and-drift-detection.md)
  covers the re-POST-on-apply renewal model and the rationale for
  `protect_unmanaged_entries` defaulting to `true`.
