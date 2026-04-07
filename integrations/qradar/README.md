# JA4proxy DSM for IBM QRadar

## Overview

The JA4proxy Device Support Module (DSM) allows IBM QRadar to parse and correlate
LEEF 2.0 telemetry events from JA4proxy — a TLS-aware passthrough security proxy.

The DSM provides:
- LEEF 2.0 parser with field extraction
- QID event category mappings for all 6 JA4proxy actions
- 11 custom property definitions (JA4 fingerprints, risk score, dial, SNI, ASN, etc.)
- 3 offense contribution rules (high-risk connections, bans, repeated blocks)

## Requirements

- IBM QRadar SIEM 7.5 or later
- QRadar DSM Editor (included in QRadar 7.5+)
- JA4proxy with `logging.format: ecs` in `config/proxy.yml`
- Vector shipping agent running on the proxy host
  (`config/integrations/vector-qradar-leef.yaml`)

## Installation

### Step 1: Import the DSM

1. In QRadar, navigate to **Admin → Data Sources → DSM Editor**.
2. Click **Import DSM** and upload `JA4proxy-DSM.xml`.
3. Review the import summary — it should show:
   - 1 log source type: "JA4proxy TLS Security Proxy"
   - 7 QID mappings
   - 11 custom properties
   - 3 offense contribution rules
4. Click **Save and Deploy** to activate the DSM.

### Step 2: Create a Log Source

1. Navigate to **Admin → Data Sources → Log Sources → Add**.
2. Configure the log source:
   - **Log Source Name**: `ja4proxy-prod` (or your instance name)
   - **Log Source Type**: `JA4proxy TLS Security Proxy`
   - **Protocol Configuration**: `Syslog`
   - **Listen Port**: `514`
   - **Protocol**: `UDP`
3. Click **Save**.

### Step 3: Configure the Vector Agent

On the JA4proxy host, start the Vector agent to forward LEEF events:

```bash
export QRADAR_HOST=qradar.corp.example.com
export SERVICE_VERSION=1.2.3

python3 proxy.py 2>&1 | vector --config config/integrations/vector-qradar-leef.yaml
```

### Step 4: Verify Ingestion

In QRadar, navigate to **Log Activity** and filter by:
- **Log Source Type**: JA4proxy TLS Security Proxy

You should see events with the action field (allowed, blocked, banned, etc.) parsed
in the **Event Name** column.

To verify custom properties are mapped correctly:
1. Navigate to **Admin → Data Sources → Custom Properties**.
2. Search for "ja4_fingerprint" — it should show as mapped.
3. Right-click any JA4proxy event and select **Event Details** to see the custom
   property values populated.

## Custom Properties Reference

After import, these custom properties are available in QRadar AQL queries:

| Property Name | Type | Description |
|---|---|---|
| `ja4_fingerprint` | String | JA4 TLS client fingerprint |
| `ja4x_fingerprint` | String | JA4X certificate fingerprint |
| `ja4t_fingerprint` | String | JA4T TCP fingerprint |
| `risk_score` | Numeric | Composite risk score 0–100 |
| `dial_setting` | Numeric | Proxy dial 0–100 |
| `sni_hostname` | String | TLS SNI hostname |
| `asn_number` | Numeric | Source IP ASN number |
| `asn_org` | String | ASN organisation name |
| `tls_version` | String | TLS version (1.2, 1.3) |
| `tls_cipher` | String | IANA cipher suite name |
| `country_code` | String | ISO 3166-1 alpha-2 country |

## Sample AQL Queries

**All blocked connections in the last hour:**
```aql
SELECT sourceip, destinationip, "ja4_fingerprint", "risk_score", eventid
FROM events
WHERE logsourcetype = 'JA4proxy TLS Security Proxy'
AND eventid IN ('blocked', 'banned')
LAST 1 HOURS
```

**Top fingerprints by block count:**
```aql
SELECT "ja4_fingerprint", COUNT(*) AS block_count
FROM events
WHERE logsourcetype = 'JA4proxy TLS Security Proxy'
AND eventid = 'blocked'
GROUP BY "ja4_fingerprint"
ORDER BY block_count DESC
LIMIT 20
LAST 24 HOURS
```

**High-risk connections (score >= 70):**
```aql
SELECT sourceip, "risk_score", "sni_hostname", "asn_org", eventid
FROM events
WHERE logsourcetype = 'JA4proxy TLS Security Proxy'
AND "risk_score" >= 70
ORDER BY "risk_score" DESC
LAST 4 HOURS
```

## Offense Contribution Rules

The DSM automatically contributes to QRadar offenses for:

| Rule | Trigger | Magnitude |
|---|---|---|
| JA4proxy High Risk Connection | risk_score >= 70 | 3 |
| JA4proxy Banned IP | action = banned | 5 |
| JA4proxy Repeated Blocks | 10+ blocks from same IP in 5 min | 4 |

Offenses aggregate across all JA4proxy log sources automatically.

## Troubleshooting

**Events showing as "Unknown" log source type:** Ensure the DSM was deployed after
import (Admin → Deploy Changes).

**Custom properties empty:** Verify the Vector config is generating LEEF 2.0 format
with correct tab-separated attributes. Check QRadar System Notifications for parsing
errors.

**No events in Log Activity:** Check the QRadar firewall allows inbound UDP 514 from
the JA4proxy host. Verify with `tcpdump -i any udp port 514` on the QRadar console.
