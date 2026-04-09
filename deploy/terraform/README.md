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
  api_url   = var.ja4proxy_url
  api_token = var.ja4proxy_admin_token
}

# Ban a known scanner (IP or CIDR)
resource "ja4proxy_ban" "scanner" {
  ip     = "198.51.100.4"
  ttl    = 2592000   # 30 days in seconds
  reason = "Known threat scanner"
}

# Ban a CIDR range
resource "ja4proxy_ban" "bad_subnet" {
  ip     = "198.51.100.0/24"
  ttl    = 604800    # 7 days in seconds
  reason = "Hosting provider with no legitimate traffic"
}

# Blocklist a malicious JA4 fingerprint
resource "ja4proxy_blocklist_entry" "cobalt_strike" {
  entry = "t10d170900_9dc949161b6c_b64c0ad42cb7"
  note  = "Cobalt Strike default TLS profile"
}

# Allowlist a trusted JA4 fingerprint
resource "ja4proxy_allowlist_entry" "internal_monitoring" {
  entry      = "t13d1516h2_aabbccddeeff_aabbccddeeff"
  managed_by = "terraform"
  note       = "Internal monitoring tool"
}

# Watchlist an IP for monitoring
resource "ja4proxy_watchlist_entry" "suspicious_ip" {
  entry = "198.51.100.99"
  note  = "Observed in threat intel feed"
}

# Set the global sensitivity dial (0-100, singleton)
resource "ja4proxy_dial" "prod" {
  value = 70
}

# Configure a webhook for security events
resource "ja4proxy_webhook" "splunk_hec" {
  url    = "https://splunk.corp.internal:8088/services/collector/event"
  events = ["block", "ban", "campaign", "dial_change"]
  active = true
}
```

## Provider Repository

The provider source code lives in a separate repository:
`github.com/anomalyco/terraform-provider-ja4proxy`

This is required for Terraform Registry publication and independent release
lifecycles.

## Resource Types

| Resource | Attributes | Purpose |
|----------|-----------|---------|
| `ja4proxy_ban` | `ip`, `ttl`, `reason` | Ban an IP address or CIDR range |
| `ja4proxy_allowlist_entry` | `entry`, `managed_by`, `note`, `expires_at` | Add a JA4 fingerprint or IP to the allowlist |
| `ja4proxy_blocklist_entry` | `entry`, `note`, `expires_at` | Add a JA4 fingerprint to the blocklist |
| `ja4proxy_watchlist_entry` | `entry`, `note`, `expires_at` | Add an IP to the watchlist for monitoring |
| `ja4proxy_dial` | `value` | Set the global sensitivity dial (0-100, singleton) |
| `ja4proxy_webhook` | `url`, `events`, `active` | Configure webhook subscriptions |

## Attribute Reference

### `ja4proxy_ban`
| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `ip` | string | yes | IP address or CIDR range (e.g., `198.51.100.0/24`) |
| `ttl` | number | yes | Ban duration in seconds (e.g., 86400 = 1 day) |
| `reason` | string | yes | Reason for the ban |

### `ja4proxy_allowlist_entry`
| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `entry` | string | yes | JA4 fingerprint or IP/CIDR |
| `managed_by` | string | no | Owner tag (default: `"terraform"`) |
| `note` | string | no | Free-text note |
| `expires_at` | string | no | ISO 8601 expiry timestamp |

### `ja4proxy_blocklist_entry` / `ja4proxy_watchlist_entry`
Same as allowlist but without `managed_by` (inferred from resource type).

### `ja4proxy_dial`
| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `value` | number | yes | Dial setting (0-100). Changes limited to ±10 per request. |

### `ja4proxy_webhook`
| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | string | yes | Webhook endpoint URL |
| `events` | list(string) | yes | Event types to subscribe to |
| `active` | bool | no | Enable/disable (default: `true`) |

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

**Note:** The `protect_unmanaged_entries` feature documented in the phase
spec is planned for a follow-up release. In the current implementation,
`terraform apply` will manage only resources explicitly declared in your
Terraform config. Resources added out-of-band (via UI or API) are not
touched by Terraform unless you import them first.

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
cd terraform-provider && GOROOT=/snap/go/current go test ./internal/... -v -count=1

# Run emergency playbook tests
python3 -m pytest tests/integration/test_emergency_playbooks.py -v
```
