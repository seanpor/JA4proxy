# Phase 83: Infrastructure Automation — Terraform, CLI & Kubernetes Operator

> **Prerequisite: Phase 79 (Management API with stable IDs and managed_by field).**

---

## 1. Overview

Platform and infrastructure teams expect to manage security tools the same way they
manage everything else — as code, via pipelines, with drift detection. This phase
delivers the infrastructure automation layer:

1. **`ja4proxy-cli`** — Go binary for terminal-based day-2 operations (the highest
   single-tool impact item in the enterprise readiness gap analysis)
2. **Terraform provider** — manages JA4proxy rules as IaC resources
3. **Kubernetes operator + CRDs** — declarative management for OpenShift/K8s deployments
4. **CMDB & NetBox integration** — asset registration and IP management
5. **Emergency runbook playbooks** — pre-packaged Ansible for common incident scenarios

---

## 2. `ja4proxy-cli`

The Management UI is a browser application. Platform engineers and on-call SREs
operate from terminals, especially at 2 AM during incidents. The CLI is the single
most-requested day-2 tool. The CLI stub — with mock API responses for all commands
— **can and should be developed in parallel with Phase 79**, integrating against the
live API once Phase 79 stabilises. The CLI is still listed as depending on Phase 79
because it cannot be fully tested or released without the live API.

### 2.1 Binary Distribution

- Go binary, statically linked, no runtime dependencies
- Ships as: standalone download, container image `ja4proxy-cli:latest`, and
  included in the proxy container image at `/usr/local/bin/ja4proxy-cli`
- Configured via `~/.config/ja4proxy/cli.yaml` or environment variables:
  ```bash
  export JA4PROXY_URL=https://ja4proxy-mgmt.corp.internal
  export JA4PROXY_TOKEN=<operator-scoped-token>
  ```

### 2.2 Command Reference

```
ja4proxy-cli ip lookup <ip>
  → score history, active bans, signal breakdown, last 10 connections

ja4proxy-cli ip ban <ip> [--ttl 1h] [--reason "scanning activity"] [--ticket CHG0001]
  → applies immediately to all nodes, returns ban ID

ja4proxy-cli ip release <ip>
  → releases active ban, requires --confirm flag

ja4proxy-cli ip watchlist add <ip> [--ttl 24h] [--reason "monitoring"]
ja4proxy-cli ip watchlist remove <ip>

ja4proxy-cli allowlist add <ja4-fingerprint> [--reason "..."] [--expires 2027-01-01]
ja4proxy-cli allowlist remove <ja4-fingerprint>
ja4proxy-cli allowlist list

ja4proxy-cli blocklist add <ja4-fingerprint> [--reason "..."]
ja4proxy-cli blocklist remove <ja4-fingerprint>
ja4proxy-cli blocklist list

ja4proxy-cli dial get
ja4proxy-cli dial set <0-100> --confirm --ticket CHG0001234
  → requires --confirm flag; prints shadow mode summary if available

ja4proxy-cli config reload [--node ja4proxy-prod-03]
  → sends SIGHUP to all nodes (or specific node)

ja4proxy-cli health [--all-nodes]
  → table output: node, status, version, dial, redis_latency_ms, uptime

ja4proxy-cli fingerprint <ja4> --history 30d
  → timeline of all connections using this fingerprint across all nodes

ja4proxy-cli policy validate --file ja4proxy-policy.yaml
ja4proxy-cli policy apply --file ja4proxy-policy.yaml [--dry-run]
ja4proxy-cli policy diff --file ja4proxy-policy.yaml

ja4proxy-cli simulation run --dial 80 --days 30
ja4proxy-cli simulation status <sim-id>
ja4proxy-cli simulation report <sim-id> [--format json|table]
```

### 2.3 Output Formats

All commands support `--output json|table|csv`. JSON output enables piping:
```bash
ja4proxy-cli ip lookup 198.51.100.4 --output json | jq '.signals[].name'
```

### 2.4 Implementation Notes

- ~1,000 lines of Go using `cobra` for command structure and `tablewriter` for
  table output. Budget 3-4 weeks.
- Authentication: reads token from environment variable, config file, or
  interactive prompt on first run (stores in OS keychain via `99designs/keyring`)
- All mutating commands (`ban`, `release`, `dial set`) prompt for confirmation
  unless `--confirm` is passed explicitly — prevents accidental changes in scripts
- **Binary distribution security:** All CLI binary releases must include:
  - GPG signature (detached `.asc` file) signed with the project's release key
  - SLSA provenance attestation (level 2 minimum: build on hosted CI, provenance uploaded to GitHub release)
  - SHA-256 checksums file (`checksums.txt`)
  - These are required for enterprise security teams that validate binaries before deployment. Document the signing process in `docs/developer/RELEASE_PROCESS.md`.

---

## 3. Terraform Provider

### 3.1 Provider Overview

`terraform-provider-ja4proxy` authenticates to the Management API using an
Admin-scoped API token and manages JA4proxy rules as Terraform resources.
Published to the Terraform Registry under `hashicorp/ja4proxy` (or
`ja4proxy/ja4proxy` if open-source independent).

### 3.1.1 Registry Namespace — Decision Required Before Work Starts

The Terraform Registry namespace determines the provider import path in all customer Terraform configs (`required_providers { ja4proxy = { source = "<namespace>/ja4proxy" } }`). This cannot be changed post-publication without breaking existing customers.

**Decision options:**
- `hashicorp/ja4proxy` — requires Hashicorp partnership; use for commercial/partner-published providers
- `ja4proxy/ja4proxy` — self-published; recommended for open-source; full control over publish cadence

**Action required:** Decide and record the namespace in `docs/decisions/ADR-NNN.md` before writing any Terraform provider code. The namespace must also be reflected in the `go.mod` module path for the provider.

### 3.2 Resource Types

```hcl
# Dial setting (one per environment)
resource "ja4proxy_dial" "prod" {
  setting    = 70
  notes      = "Validated via shadow mode simulation sim-20260404-a3f2"
  ticket     = "CHG0001234"
}

# JA4 fingerprint allowlist entry
resource "ja4proxy_allowlist_entry" "chrome_monitoring" {
  ja4         = "t13d1516h2_aabbccddeeff_aabbccddeeff"
  reason      = "Internal monitoring tool"
  ticket      = "CHG0001100"
  expires_at  = "2027-01-01T00:00:00Z"   # optional
}

# JA4 fingerprint blocklist entry
resource "ja4proxy_blocklist_entry" "cobalt_strike_default" {
  ja4    = "t10d170900_9dc949161b6c_b64c0ad42cb7"
  reason = "Known Cobalt Strike default TLS profile"
  ticket = "INC0005432"
}

# IP ban (with TTL — Terraform manages renewal)
resource "ja4proxy_ban" "known_scanner" {
  ip         = "198.51.100.4"
  ttl_hours  = 720   # 30 days; Terraform renews before expiry
  reason     = "Confirmed scanner from threat intel"
  ticket     = "INC0005100"
}

# CIDR ban
resource "ja4proxy_cidr_ban" "bad_hosting" {
  cidr       = "198.51.100.0/24"
  ttl_hours  = 168
  reason     = "Hosting provider with no legitimate traffic"
  ticket     = "INC0005200"
}

# Webhook subscription
resource "ja4proxy_webhook" "splunk_hec" {
  url    = "https://splunk.corp.internal:8088/services/collector/event"
  events = ["block", "ban", "campaign", "dial_change"]
  secret = var.splunk_webhook_secret
}
```

### 3.3 Drift Handling

The `managed_by` field on every resource (set to `"terraform"` by the provider on
create) allows drift detection:

```hcl
provider "ja4proxy" {
  url   = "https://ja4proxy-mgmt.corp.internal"
  token = var.ja4proxy_admin_token

  # Protect entries added out-of-band (by SOC operator in UI) from being
  # destroyed by terraform apply
  protect_unmanaged_entries = true   # converts unexpected destroys to warnings
}
```

When `protect_unmanaged_entries = true`:
- `terraform plan` shows out-of-band entries as warnings, not as planned destroys
- To take ownership of an out-of-band entry: `terraform import ja4proxy_ban.name 198.51.100.4`
- Import command is printed to stdout for all unmanaged entries in plan output

### 3.4 Import Workflow

```bash
# List all current bans not managed by Terraform
ja4proxy-cli ip ban list --managed-by operator --output json | \
  jq -r '.[] | "terraform import ja4proxy_ban.\(.ip | gsub("[./]";"_")) \(.ip)"'
```

---

## 4. Kubernetes Operator

For enterprises running OpenShift or Kubernetes using the DaemonSet topology
documented in Phase 76 (§5.3).

### 4.1 Custom Resource Definitions

```yaml
# ja4proxy-config.yaml
apiVersion: ja4proxy.io/v1alpha1
kind: JA4ProxyConfig
metadata:
  name: prod-config
spec:
  dial: 70
  bypassToggles:
    alpnBrowserBypass: true
    spamhausBypass: true
  redisUrl: "redis://redis.ja4proxy.svc.cluster.local:6379"
  # Fields marked requiresRestart: true in the CRD schema cannot be hot-reloaded
---
apiVersion: ja4proxy.io/v1alpha1
kind: JA4ProxyAllowlist
metadata:
  name: monitoring-tools
  namespace: security
spec:
  fingerprints:
    - ja4: "t13d1516h2_aabbccddeeff_aabbccddeeff"
      reason: "Internal monitoring"
      ticket: "CHG0001100"
---
apiVersion: ja4proxy.io/v1alpha1
kind: JA4ProxyDial
metadata:
  name: prod-dial
spec:
  setting: 70
  requiresApproval: true   # triggers four-eyes workflow before applying
```

### 4.2 Operator Reconciliation

- Watches Kubernetes API for changes to JA4proxy CRDs
- Pushes changes to JA4proxy via the Management API (not by restarting pods)
- Reconciliation loop: every 30 seconds + immediate on CRD change event
- Admission webhook validates CRDs at apply time (dial 0-100, valid JA4 format,
  required fields) — errors surface in `kubectl apply` output immediately

### 4.3 DaemonSet Safety

```yaml
# In the operator-managed DaemonSet spec
spec:
  template:
    metadata:
      annotations:
        # Prevent cluster autoscaler from evicting proxy pods
        cluster-autoscaler.kubernetes.io/safe-to-evict: "false"
```

ArgoCD health checks should target `GET /api/v1/health/deep` rather than pod
readiness alone. A pod that is `Running` but with Redis unreachable is not healthy.
Configure a custom ArgoCD health check resource in `deploy/helm/ja4proxy/templates/`.

---

## 5. CMDB & NetBox Integration

### 5.1 ServiceNow CMDB Auto-Registration

Add to the Ansible post-deploy role (50 lines):

```yaml
- name: Register JA4proxy node in ServiceNow CMDB
  servicenow.itsm.configuration_item:
    name: "{{ inventory_hostname }}"
    short_description: "JA4proxy TLS Security Proxy"
    asset_tag: "JA4PROXY-{{ inventory_hostname }}"
    install_status: "installed"
    ip_address: "{{ ansible_host }}"
    u_version: "{{ ja4proxy_image_tag }}"
    u_upstream_lb: "{{ upstream_lb_host }}"
    u_downstream_backend: "{{ backend_host }}"
    u_environment: "{{ deploy_environment }}"
    u_last_deployed: "{{ ansible_date_time.iso8601 }}"
    u_config_checksum: "{{ config_checksum.stdout }}"
  delegate_to: localhost
```

### 5.2 NetBox Inbound Integration (IP Management)

Read trusted CIDR ranges from NetBox rather than static config — network engineers
maintain CIDRs in NetBox (where they already manage IP space):

```python
# src/config/netbox_loader.py
async def load_trusted_cidrs_from_netbox(netbox_url: str, token: str) -> list[str]:
    """Fetch trusted upstream CIDRs tagged 'ja4proxy-trusted' from NetBox."""
    async with aiohttp.ClientSession() as session:
        resp = await session.get(
            f"{netbox_url}/api/ipam/prefixes/?tag=ja4proxy-trusted",
            headers={"Authorization": f"Token {token}"},
        )
        data = await resp.json()
        return [p["prefix"] for p in data["results"]]
```

Called at startup and on SIGHUP. Falls back to `config/proxy.yml` static list if
NetBox is unreachable (fail-open). The integration is opt-in:

```yaml
# config/proxy.yml
trusted_upstream_sources:
  netbox:
    enabled: true
    url: "https://netbox.corp.internal"
    token: "${NETBOX_API_TOKEN}"
    tag: "ja4proxy-trusted"
    refresh_on_sighup: true
  static_cidrs:
    - "10.0.0.0/8"   # always trusted regardless of NetBox
```

---

## 6. Emergency Runbook Playbooks

Three Ansible playbooks that every enterprise deployer needs within six months.
Each is 50-100 lines, pre-packaged in `deploy/ansible/playbooks/emergency/`.

### 6.1 `emergency-ban-cidr.yml`

```bash
ansible-playbook emergency-ban-cidr.yml \
  -e cidr=198.51.100.0/24 \
  -e reason="Active scanning campaign from this /24" \
  -e ticket=INC0005432 \
  -e ttl_hours=24
```

Actions: calls `POST /api/v1/bans/cidr/{cidr}` across all nodes via Management API,
logs to audit trail, creates ServiceNow incident if configured, posts to Slack.

### 6.2 `temp-whitelist-ip.yml`

```bash
ansible-playbook temp-whitelist-ip.yml \
  -e ip=203.0.113.5 \
  -e reason="Debugging partner integration — temporary, expires in 2 hours" \
  -e ttl_hours=2 \
  -e ticket=CHG0001500
```

Actions: adds allowlist entry with mandatory TTL, schedules automatic removal via
AAP scheduled job, sends Slack notification to `#security-ops` with expiry reminder.

### 6.3 `maintenance-dial-zero.yml`

```bash
ansible-playbook maintenance-dial-zero.yml \
  -e duration_minutes=60 \
  -e reason="Maintenance window for backend upgrade" \
  -e ticket=CHG0001600
```

Actions: sets dial to 0 across all nodes, logs to audit trail, schedules automatic
restoration after `duration_minutes`, creates ServiceNow change record. Restoration
posts to `#security-ops` confirming dial was re-applied.

---

## 7. Acceptance Criteria

- [ ] Terraform Registry namespace recorded in ADR before provider development starts
- [ ] CLI binary releases include GPG signature, SLSA provenance attestation, and SHA-256 checksums
- [ ] CLI stub with mock API responses developed and tested independently of Phase 79 API availability
- [ ] `ja4proxy-cli` binary: all commands in §2.2 implemented and tested
- [ ] CLI: `--output json|table|csv` for all read commands
- [ ] CLI: mutating commands require `--confirm` unless flag passed
- [ ] CLI distributed as binary download + container image + embedded in proxy image
- [ ] Terraform provider: all resource types in §3.2 implemented
- [ ] Terraform provider: `protect_unmanaged_entries` flag works correctly
- [ ] Terraform provider: import workflow documented with example script
- [ ] Terraform provider: submitted for publication to Terraform Registry (publishing is a business track item; submission is the engineering AC)
- [ ] Kubernetes operator: all CRDs in §4.1 with admission webhook validation
- [ ] Kubernetes operator: reconciliation loop + immediate-on-change working
- [ ] DaemonSet `safe-to-evict: false` annotation in operator-managed spec
- [ ] ArgoCD custom health check targeting `/api/v1/health/deep`
- [ ] ServiceNow CMDB registration in Ansible post-deploy role
- [ ] NetBox inbound integration with fallback to static CIDRs
- [ ] All 3 emergency runbook playbooks tested end-to-end
- [ ] Emergency playbooks documented in `docs/runbooks/`

---

## 8. Business Track (Not Engineering Acceptance Criteria)

- **Terraform Registry publication approval** — Hashicorp reviews provider submissions via GitHub PR to the registry repository. Allow 1–2 weeks. Track separately from engineering completion.
- **Kubernetes operator publication** — if publishing to OperatorHub, submit after internal validation. Track separately.
