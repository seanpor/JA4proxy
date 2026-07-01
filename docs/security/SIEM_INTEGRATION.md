<!--
title: "SIEM Integration Recipes for JA4proxy"
audience: security
last_reviewed: 2026-04-25
phase: 105
-->

# SIEM Integration

JA4proxy emits structured logs in **Elastic Common Schema (ECS) 8.x** so that
every connection decision, campaign alert, and configuration change lands in
your SIEM with correctly-typed, vendor-neutral fields — no normalisation
required.

This document provides ingestion recipes for the four most common enterprise
SIEM platforms. For the complete field-level schema, see
[`docs/api/ecs_extension.md`](../api/ecs_extension.md). This document does
**not** duplicate that reference; it shows how to **get the events into the
SIEM** and what to **alert on** once they arrive.

> **Token security note.** Every credential below is a placeholder
> (`<YOUR_HEC_TOKEN>`, `<YOUR_API_KEY>`, etc.). Replace at deploy time using
> your secret manager (Vault, AWS Secrets Manager, Azure Key Vault). Never
> commit real tokens to version control.

---

## Common preconditions

- JA4proxy `logging.format: ecs` in `config/proxy.yml` (default in Phase 80+)
- ECS schema validated against `config/integrations/ecs-schema.json`
- Time synchronisation: NTP on every JA4proxy node and every SIEM forwarder
- Log volume planning: ~1 KB per connection event; see
  [`docs/operations/SCALING_GUIDE.md`](../operations/SCALING_GUIDE.md) for retention sizing

---

## Recipe 1 — Splunk (HEC)

**Vendor doc:** <https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector>

JA4proxy ships events to Splunk via the **HTTP Event Collector (HEC)**. Use a
sidecar forwarder (Vector, Fluent Bit, or `splunk-otel-collector`) to read the
JSON log file and POST to HEC. Direct application HTTP egress is discouraged
in DMZ deployments.

### Forwarder configuration (Fluent Bit)

```ini
# /etc/fluent-bit/fluent-bit.conf
[INPUT]
    Name              tail
    Path              /var/log/ja4proxy/proxy.json
    Parser            json
    Tag               ja4proxy.events
    DB                /var/log/fluent-bit/ja4proxy.pos

[OUTPUT]
    Name              splunk
    Match             ja4proxy.events
    Host              splunk-hec.example.com
    Port              8088
    Splunk_Token      <YOUR_HEC_TOKEN>
    Splunk_Send_Raw   On
    TLS               On
    TLS.verify        On
    event_index       ja4proxy
    event_sourcetype  ja4proxy:ecs
```

### Splunk parser (props.conf)

```ini
# $SPLUNK_HOME/etc/apps/ja4proxy/local/props.conf
[ja4proxy:ecs]
INDEXED_EXTRACTIONS = json
KV_MODE = none
TIMESTAMP_FIELDS = @timestamp
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N%Z
SHOULD_LINEMERGE = false
TRUNCATE = 0
```

### Sample correlation rule (SPL)

Detect a coordinated bot wave: 50+ blocks from the same `/24` within 5 minutes,
all sharing one JA4 fingerprint.

```spl
index=ja4proxy sourcetype=ja4proxy:ecs "event.action"=blocked
| eval cidr24=mvindex(split("source.ip","."),0)+"."+mvindex(split("source.ip","."),1)+"."+mvindex(split("source.ip","."),2)+".0/24"
| stats count, dc(source.ip) AS unique_ips BY cidr24, ja4proxy.fingerprint.ja4, span=5m
| where count >= 50 AND unique_ips >= 10
```

---

## Recipe 2 — IBM QRadar (DSM with Syslog/LEEF)

**Vendor doc:** <https://www.ibm.com/docs/en/dsm?topic=overview-dsm-configuration-overview>

QRadar is most reliably fed via **syslog with LEEF or JSON payload**. Send JSON
ECS events directly; QRadar's universal DSM will auto-extract fields.

### Forwarder configuration (rsyslog forwarding ECS JSON)

```bash
# /etc/rsyslog.d/30-ja4proxy.conf
module(load="imfile" PollingInterval="1")

input(type="imfile"
      File="/var/log/ja4proxy/proxy.json"
      Tag="ja4proxy:"
      Severity="info"
      Facility="local6"
      ruleset="ja4proxy_to_qradar")

ruleset(name="ja4proxy_to_qradar") {
    action(type="omfwd"
           Target="qradar.example.com"
           Port="514"
           Protocol="tcp"
           Template="RSYSLOG_SyslogProtocol23Format"
           queue.type="LinkedList"
           queue.size="10000"
           action.resumeRetryCount="-1")
}
```

### QRadar custom property (extracts JA4 fingerprint)

In QRadar **Admin → Data Sources → Custom Event Properties**, create:

```
Name:               JA4 Fingerprint
Optimised:          Yes
Field Type:         AlphaNumeric
Capture Group:      1
RegEx:              "ja4proxy\.fingerprint\.ja4"\s*:\s*"([^"]+)"
Log Source Type:    Universal DSM
```

Repeat for `ja4proxy.score` (Numeric), `ja4proxy.country_code` (AlphaNumeric),
`event.action` (AlphaNumeric).

### Sample correlation rule (AQL)

Detect bot waves in the last 5 minutes from datacenter ASNs.

```sql
SELECT sourceip, "JA4 Fingerprint" AS ja4, COUNT(*) AS hits
FROM events
WHERE devicetype = 'Universal DSM'
  AND "ja4proxy.asn_org" ILIKE '%digitalocean%' OR "ja4proxy.asn_org" ILIKE '%hetzner%'
  AND "event.action" = 'blocked'
  AND LAST 5 MINUTES
GROUP BY sourceip, ja4
HAVING hits > 20
```

Promote to an offence when hits exceed 20 within 5 minutes from the same IP.

---

## Recipe 3 — Microsoft Sentinel (Azure Monitor / CEF)

**Vendor doc:** <https://learn.microsoft.com/en-us/azure/sentinel/connect-cef-syslog-ama>

Sentinel ingests via the **Azure Monitor Agent (AMA)** with a Common Event
Format (CEF) data collection rule. JA4proxy can emit CEF directly, or you can
forward ECS JSON through a CEF-translating syslog server (rsyslog with the
`mmjsonparse` module).

### Forwarder configuration (rsyslog → CEF on Linux relay host)

```bash
# /etc/rsyslog.d/40-ja4proxy-cef.conf
module(load="mmjsonparse")
module(load="omfwd")

template(name="JA4ProxyCEF" type="string"
  string="<%PRI%>%TIMESTAMP% %HOSTNAME% CEF:0|JA4proxy|JA4proxy|1.0|%$!event!action%|JA4proxy %$!event!action%|%$!event!severity%|src=%$!source!ip% spt=%$!source!port% dpt=%$!destination!port% act=%$!event!action% cs1Label=ja4 cs1=%$!ja4proxy!fingerprint!ja4% cs2Label=score cs2=%$!ja4proxy!score% cs3Label=country cs3=%$!ja4proxy!country_code%\n")

action(type="mmjsonparse" cookie="")
action(type="omfwd"
       Target="ama-relay.example.com"
       Port="514"
       Protocol="tcp"
       Template="JA4ProxyCEF")
```

### Sentinel parser (KQL function)

Save as a function `JA4Proxy_CL` so analysts can `call` it like a table.

```kusto
// Save as: JA4Proxy_CL
CommonSecurityLog
| where DeviceVendor == "JA4proxy"
| extend
    JA4 = tostring(DeviceCustomString1),
    RiskScore = toint(DeviceCustomString2),
    CountryCode = tostring(DeviceCustomString3),
    Action = tostring(Activity)
| project TimeGenerated, SourceIP, SourcePort, DestinationPort, Action,
          JA4, RiskScore, CountryCode, DeviceName
```

### Sample correlation rule (Analytics Rule)

Alert when a single JA4 fingerprint produces blocks from 50+ unique IPs within
30 minutes — a hallmark of distributed credential-stuffing.

```kusto
JA4Proxy_CL
| where Action == "blocked"
| where TimeGenerated > ago(30m)
| summarize UniqueIPs = dcount(SourceIP), Hits = count() by JA4
| where UniqueIPs >= 50 and Hits >= 200
```

Map this to MITRE ATT&CK technique **T1110.004 (Credential Stuffing)** in the
analytics rule properties.

---

## Recipe 4 — Wazuh (Syslog)

**Vendor doc:** <https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/how-it-works.html>

Wazuh ingests via **syslog** to the Wazuh manager, then a custom decoder
extracts ECS fields. The Wazuh agent's `localfile` collector can also read
the JSON file directly.

### Agent configuration (`ossec.conf` on each JA4proxy host)

```xml
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/ja4proxy/proxy.json</location>
    <label key="source">ja4proxy</label>
  </localfile>
</ossec_config>
```

### Wazuh decoder (`/var/ossec/etc/decoders/ja4proxy_decoders.xml`)

```xml
<decoder name="ja4proxy">
  <prematch>"service.name":"ja4proxy"</prematch>
</decoder>

<decoder name="ja4proxy-fields">
  <parent>ja4proxy</parent>
  <plugin_decoder offset="after_parent">JSON_Decoder</plugin_decoder>
</decoder>
```

### Wazuh rule (`/var/ossec/etc/rules/ja4proxy_rules.xml`)

```xml
<group name="ja4proxy,">
  <rule id="100501" level="0">
    <decoded_as>ja4proxy</decoded_as>
    <description>JA4proxy event</description>
  </rule>

  <rule id="100502" level="7">
    <if_sid>100501</if_sid>
    <field name="event.action">blocked|banned</field>
    <description>JA4proxy: $(event.action) connection from $(source.ip), score=$(event.risk_score), JA4=$(ja4proxy.fingerprint.ja4)</description>
    <mitre>
      <id>T1071.001</id>
    </mitre>
  </rule>

  <rule id="100510" level="12" frequency="50" timeframe="300">
    <if_matched_sid>100502</if_matched_sid>
    <same_field>ja4proxy.fingerprint.ja4</same_field>
    <description>JA4proxy: 50+ blocks in 5 minutes from same JA4 fingerprint — possible bot wave</description>
    <group>attack,bot_wave,</group>
  </rule>
</group>
```

### Sample correlation behaviour

Rule `100510` fires when the same JA4 fingerprint produces 50 blocks within
five minutes — a coordinated bot wave. Wazuh forwards the alert to email,
Slack, or any configured Active Response endpoint.

---

## Verifying ingestion

After deploying any of the four recipes, send a synthetic event and confirm it
appears in the SIEM with all expected fields populated:

```bash
# Tail the JA4proxy log file and force a known-bad request
curl -k --tls-max 1.0 https://your-proxy:443/  # forces TLS-version-old signal
sleep 2
tail -n 1 /var/log/ja4proxy/proxy.json | jq '.["event.action"], .["ja4proxy.score"]'
```

Expected JSON output: `"blocked"` (or `"flagged"` at low dial), `>= 30`. Then
search the SIEM for the same `@timestamp` to confirm round-trip ingestion.

---

## Related reading

- [`docs/api/ecs_extension.md`](../api/ecs_extension.md) — full ECS field
  reference (canonical schema)
- [`SCOPE_AND_LIMITATIONS.md`](../product/SCOPE_AND_LIMITATIONS.md)
  — non-goals; SIEM is one of the named complementary controls
- [`EVALUATION_CHECKLIST.md`](../product/EVALUATION_CHECKLIST.md)
  — what to monitor in your SIEM during a POC
- [`config/integrations/ecs-schema.json`](../../config/integrations/ecs-schema.json)
  — JSON Schema for CI validation of emitted events
