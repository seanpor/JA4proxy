# JA4proxy Microsoft Sentinel Integration

## Overview

This content pack connects JA4proxy telemetry to Microsoft Sentinel, providing:
- A custom data connector that creates the `JA4proxy_CL` Log Analytics table
- 5 analytics rules with MITRE ATT&CK tagging
- A 3-section SOC workbook
- 2 Logic App playbooks for automated response

## Architecture

```
JA4proxy proxy.py  →  Vector agent  →  Azure Monitor Logs API  →  JA4proxy_CL table
                       (vector-sentinel.yaml)                       in Log Analytics
                                                                        │
                                                              Sentinel Analytics Rules
                                                                        │
                                                              Incidents + Playbooks
```

## Prerequisites

- Microsoft Sentinel workspace
- JA4proxy with `logging.format: ecs` in `config/proxy.yml`
- Vector shipping agent running on the proxy host
- Azure CLI or Azure Portal access for deployment

## Deployment Steps

### Step 1: Deploy the Data Connector

```bash
az deployment group create \
  --resource-group rg-sentinel \
  --template-file integrations/sentinel/data-connector/JA4proxy_DataConnector.json \
  --parameters workspace=your-log-analytics-workspace
```

The deployment creates the `JA4proxy_CL` custom table with ECS-mapped columns.

### Step 2: Configure the Vector Shipping Agent

On the JA4proxy host:

```bash
# Set credentials
export SENTINEL_WORKSPACE_ID="your-workspace-id"
export SENTINEL_SHARED_KEY="your-primary-or-secondary-key"

# Run Vector alongside JA4proxy
python3 proxy.py 2>&1 | vector --config config/integrations/vector-sentinel.yaml
```

Verify data is flowing:

```kql
JA4proxy_CL
| take 10
| project TimeGenerated, source_ip_s, ja4proxy_action_s, ja4proxy_risk_score_d
```

### Step 3: Deploy Analytics Rules

Use the Sentinel REST API or portal to deploy each rule file:

```bash
# Using Azure CLI
WORKSPACE_ID="your-workspace-id"
RESOURCE_GROUP="rg-sentinel"
WORKSPACE_NAME="your-workspace-name"

for rule in integrations/sentinel/analytics-rules/*.json; do
  az sentinel alert-rule create \
    --resource-group "$RESOURCE_GROUP" \
    --workspace-name "$WORKSPACE_NAME" \
    --rule-id "$(uuidgen)" \
    --scheduled-rule "$(cat $rule)"
done
```

Or via the Sentinel portal: **Configuration → Analytics → Import**.

### Step 4: Deploy the Workbook

In the Sentinel portal: **Threat management → Workbooks → Add workbook → Import**.
Upload `integrations/sentinel/workbook/JA4proxy_Workbook.json`.

### Step 5: Deploy Playbooks

#### Block-IP-Playbook

1. Create an Azure Key Vault with the following secrets:
   - `JA4PROXY-MGMT-URL` — JA4proxy Management API base URL
   - `JA4PROXY-MGMT-TOKEN` — Bearer token for the Management API
   - `TEAMS-WEBHOOK-URL` — Teams incoming webhook URL

2. Deploy the Logic App:
   ```bash
   az logic workflow create \
     --resource-group rg-sentinel \
     --name ja4proxy-block-ip \
     --definition integrations/sentinel/playbooks/Block-IP-Playbook.json
   ```

3. Enable the Managed Identity on the Logic App and grant it `Key Vault Secrets User`
   on the Key Vault.

4. In Sentinel: **Configuration → Automation → Create → Automation rule** and attach
   the Logic App to run when an incident severity is High.

#### Enrich-IP-Playbook

1. Deploy similarly, using the same Key Vault.
2. Attach to Sentinel analytics rules as an alert trigger (not incident trigger).

## Analytics Rules Reference

| Rule | MITRE Technique | Severity | Query Frequency |
|---|---|---|---|
| Beaconing Detected | T1071 | High | Every 5 min |
| Multiple Blocked Fingerprints | T1190, T1036 | High | Every 15 min |
| Dial Change Outside Maintenance | T1562 | Medium | Every 5 min |
| Campaign from Known-Bad ASN | T1583, T1595 | High | Every 15 min |
| Spamhaus DROP Match | T1078 | High | Every 5 min |

## Custom Table Schema

The `JA4proxy_CL` table columns:

| Column | Type | Description |
|---|---|---|
| `TimeGenerated` | datetime | Event timestamp (UTC) |
| `ja4proxy_action_s` | string | allowed, blocked, banned, tarpitted, rate_limited, flagged |
| `ja4proxy_risk_score_d` | real | Composite risk score 0–100 |
| `ja4proxy_fingerprint_s` | string | JA4 TLS fingerprint |
| `ja4proxy_sni_s` | string | TLS SNI hostname |
| `ja4proxy_asn_org_s` | string | ASN organisation name |
| `ja4proxy_country_code_s` | string | ISO 3166-1 alpha-2 country |
| `ja4proxy_dial_d` | real | Proxy dial setting (0–100) |
| `source_ip_s` | string | Client IP address |
| `source_port_d` | real | Client source port |
| `tls_version_s` | string | TLS version |
| `tls_cipher_s` | string | Cipher suite |
| `RawData` | string | Full ECS JSON event |

## Troubleshooting

**No data in JA4proxy_CL:** Verify the workspace ID and shared key are correct. Check
Vector logs for HTTP 403 responses from the Azure Monitor API.

**Analytics rules not triggering:** Confirm the rule is enabled and has data in the
query time window. Run the query manually in Log Analytics to verify.

**Playbook failing:** Check the Logic App run history in the Azure portal. Verify
Managed Identity permissions on Key Vault.
