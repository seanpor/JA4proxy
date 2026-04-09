# Terraform Provider for JA4proxy

The Terraform provider allows you to manage JA4proxy security rules as
Infrastructure as Code (IaC), integrating with your existing Terraform
workflows.

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
  url   = var.ja4proxy_url
  token = var.ja4proxy_admin_token
}

# Ban a known scanner
resource "ja4proxy_ban" "scanner" {
  ip        = "198.51.100.4"
  ttl_hours = 720
  reason    = "Known threat scanner"
  ticket    = "INC0005100"
}

# Blocklist a malicious JA4 fingerprint
resource "ja4proxy_blocklist_entry" "cobalt_strike" {
  ja4    = "t10d170900_9dc949161b6c_b64c0ad42cb7"
  reason = "Cobalt Strike default TLS profile"
  ticket = "INC0005432"
}

# Set the global sensitivity dial
resource "ja4proxy_dial" "prod" {
  setting = 70
  notes   = "Validated via shadow mode"
  ticket  = "CHG0001234"
}
```

## Provider Repository

The provider source code lives in a separate repository:
`github.com/anomalyco/terraform-provider-ja4proxy`

This is required for Terraform Registry publication and independent release
lifecycles.

## Resource Types

| Resource | Purpose |
|----------|---------|
| `ja4proxy_ban` | Ban an IP address or CIDR range (both use the same resource) |
| `ja4proxy_allowlist_entry` | Add a JA4 fingerprint or IP to the allowlist |
| `ja4proxy_blocklist_entry` | Add a JA4 fingerprint to the blocklist |
| `ja4proxy_watchlist_entry` | Add an IP to the watchlist for monitoring |
| `ja4proxy_dial` | Set the global sensitivity dial (0-100, singleton) |
| `ja4proxy_webhook` | Configure webhook subscriptions for security events |

## Importing Existing Resources

If you have existing bans, allowlist entries, or other resources that were
created outside of Terraform (via the UI or direct API calls), you can import
them:

```bash
# Import a ban
terraform import ja4proxy_ban.scanner 198.51.100.4

# Import a CIDR ban (URL-encode the /)
terraform import 'ja4proxy_ban.bad_subnet' '198.51.100.0%2F24'

# Import an allowlist entry (format: listType/uuid)
terraform import ja4proxy_allowlist_entry.chrome 'allowlist/a1b2c3d4-...'

# Import a webhook
terraform import ja4proxy_webhook.splunk 'webhook-uuid-here'
```

### Bulk Import Helper

To import all current unmanaged bans into Terraform state:

```bash
ja4proxy-cli ip ban list --managed-by operator --output json | \
  jq -r '.[] | "terraform import ja4proxy_ban.\(.ip | gsub("[./:]";"_")) \(.ip)"'
```

## Drift Protection

When `protect_unmanaged_entries = true` (default), the provider will NOT
destroy entries that were added by humans or other systems. Instead, they
appear as warnings in `terraform plan`:

```hcl
provider "ja4proxy" {
  url                     = var.ja4proxy_url
  token                   = var.ja4proxy_admin_token
  protect_unmanaged_entries = true
}
```

## Emergency Playbooks

For incident response scenarios, Ansible playbooks are available at
`deploy/ansible/playbooks/emergency/`:

- `emergency-ban-cidr.yml` — Ban a CIDR range immediately
- `temp-whitelist-ip.yml` — Temporarily whitelist an IP (with auto-expiry)
- `maintenance-dial-zero.yml` — Set dial to 0 for maintenance, then restore

See the playbooks for usage examples. All playbooks require `ja4proxy_token`
for API authentication.

## Testing

```bash
# Run Terraform provider tests
cd terraform-provider && TF_ACC=1 go test ./internal/... -v -count=1

# Run emergency playbook tests
python3 -m pytest tests/integration/test_emergency_playbooks.py -v
```
