# JA4proxy Technology Add-on for Splunk

## Overview

This Technology Add-on (TA) enables Splunk to ingest, parse, and correlate telemetry
events from JA4proxy — a TLS-aware passthrough security proxy.

Events arrive as newline-delimited ECS 8.x JSON objects. The TA provides:
- Sourcetype definition (`ja4proxy:telemetry`) with JSON KV extraction
- CIM field aliases for Network Traffic and Intrusion Detection data models
- Action severity lookup (`ja4proxy_actions.csv`)
- 5 pre-built correlation searches for Splunk Enterprise Security
- Macros for common search patterns

## Requirements

- Splunk Enterprise 9.x or Splunk Cloud 9.x
- Splunk Enterprise Security 7.x (for correlation searches and notable events)
- JA4proxy with `logging.format: ecs` set in `config/proxy.yml`
- Vector shipping agent (`config/integrations/vector-splunk-hec.yaml`) or direct HEC

## Installation

### Option A: Splunk Web

1. In Splunk Web, go to **Apps → Manage Apps → Install app from file**.
2. Upload the `ja4proxy-ta/` directory as a `.tar.gz` archive.
3. Restart Splunk if prompted.

### Option B: Manual

```bash
# Copy the TA to the Splunk apps directory
cp -r ja4proxy-ta/ $SPLUNK_HOME/etc/apps/
# Restart Splunk
$SPLUNK_HOME/bin/splunk restart
```

### Option C: Deployment Server

Deploy via the Splunk Deployment Server to all Heavy Forwarders or Indexers that
need to receive JA4proxy data.

## Data Ingestion Setup

### Using Vector (recommended)

Configure the Vector agent on the JA4proxy host:

```bash
# Set required environment variables
export SPLUNK_HEC_URL=https://splunk.corp.example.com:8088
export SPLUNK_HEC_TOKEN=your-hec-token-here

# Run Vector alongside JA4proxy (pipe proxy stdout to Vector)
python3 proxy.py 2>&1 | vector --config config/integrations/vector-splunk-hec.yaml
```

### Direct HEC (alternative)

If your JA4proxy instance writes logs to a file, configure a Splunk Universal
Forwarder with the following `inputs.conf` stanza:

```ini
[monitor:///var/log/ja4proxy/proxy.log]
index    = security
sourcetype = ja4proxy:telemetry
```

## Verifying Ingestion

After data starts flowing, verify with this SPL search:

```
index=security sourcetype=ja4proxy:telemetry | head 10 | table _time, "source.ip", "event.action", "event.risk_score"
```

You should see events with the `source.ip`, `event.action`, and `event.risk_score` fields
extracted correctly.

## Correlation Searches

The following correlation searches are included. Enable them in Splunk ES under
**Configure → Content → Content Management → Correlation Searches**:

| Search Name | Trigger Condition | Severity |
|---|---|---|
| JA4proxy - Beaconing Detected | IP connects at highly regular intervals | High |
| JA4proxy - New Fingerprint from Banned ASN | New TLS fingerprint from previously-banned ASN | Medium |
| JA4proxy - Dial Threshold Crossed | Dial changed outside maintenance window | Medium |
| JA4proxy - Burst of Blocks from Single /24 | 50+ blocks from same /24 in 5 minutes | High |
| JA4proxy - New Country Not Seen in 30 Days | First connection from an unexpected country | Low |

## Macros Reference

| Macro | Description |
|---|---|
| `` `ja4proxy_index` `` | Search scope: all JA4proxy events |
| `` `ja4proxy_blocks_last_hour` `` | Blocked/banned/tarpitted events, last 1 hour |
| `` `ja4proxy_blocks_last_24h` `` | Blocked/banned/tarpitted events, last 24 hours |
| `` `ja4proxy_high_risk_last_hour` `` | Events with risk_score >= 70, last 1 hour |
| `` `ja4proxy_fingerprint_stats` `` | Connection counts by JA4 fingerprint |
| `` `ja4proxy_top_blocked_ips` `` | Top 20 source IPs by block count |

## CIM Compliance

This TA maps JA4proxy events to:
- **CIM Network Traffic**: all connection events
- **CIM Intrusion Detection**: ban, campaign, and high-risk events

Run the **Splunk CIM Validator** app to confirm mapping completeness after installation.

## Troubleshooting

**Events not appearing:** Check that `KV_MODE = json` is active — run a search with
`| metadata type=sourcetypes` and confirm `ja4proxy:telemetry` is listed.

**Timestamps wrong:** Confirm JA4proxy is writing UTC timestamps and the `TZ = UTC`
setting in `props.conf` is effective for your deployment.

**Correlation searches not firing:** In Splunk ES, verify the searches are enabled and
the time range covers your data. Check `_internal` for scheduled search errors.
