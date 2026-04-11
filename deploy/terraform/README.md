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

  # Protect entries added out-of-band from being destroyed
  protect_unmanaged_entries = true
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

When `protect_unmanaged_entries = true`:
- Out-of-band entries appear as **warnings** in `terraform plan`, not as planned destroys
- Plan output prints the `terraform import` command for each unmanaged entry
- `managed_by = "terraform"` distinguishes provider-managed resources from operator-added entries

## Development

See the provider repository's `GNUmakefile` for build and test targets:

```bash
cd terraform-provider-ja4proxy
make test       # unit tests
make testacc    # acceptance tests
make lint       # go vet + gofmt
```
