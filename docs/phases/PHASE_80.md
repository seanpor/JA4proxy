# Phase 80: ECS Structured Logging & SIEM Integration Pack

> **Prerequisite: Phase 79 (Management API + API tokens) must be complete.**

> **Note:** Phase 77 (Enterprise Security Stack — Vector sidecar pattern) must also be complete before the SIEM delivery mechanism is available. Confirm Phase 77 is merged before starting this phase.

---

## 1. Overview

Enterprise SOC teams live in their SIEM. If JA4proxy events do not appear there with
proper field normalisation, the product is operationally invisible — events go unacted
on and the tool gets decommissioned at renewal. This phase delivers:

1. A canonical **Elastic Common Schema (ECS) JSON log format** for all JA4proxy events
2. A **Splunk Technology Add-on (TA)** — the most common hard veto in enterprise
3. A **Microsoft Sentinel content pack** — mandatory for Azure-native enterprises
4. An **IBM QRadar DSM** — required for financial services and government
5. An **Elastic/Kibana integration pack**
6. A **webhook event stream** for SIEMs and custom integrations that prefer push over pull

Phase 77 (already on main) introduced the Vector sidecar pattern as a universal log
forwarder. This phase treats that as the delivery mechanism and defines the canonical
format and SIEM-specific content packs that ride on top of it.

---

## 2. Canonical Log Format — ECS 8.x

All JA4proxy components (Go proxy, Python analytics, management UI) must emit JSON
conforming to Elastic Common Schema 8.x. ECS is the most portable modern standard —
Splunk, Sentinel, QRadar, and Elastic all accept it, with lightweight field remapping
transforms in the Vector sidecar for platform-specific taxonomy.

### 2.1 Mandatory Fields — Every Event

```json
{
  "@timestamp": "2026-04-04T14:23:01.123Z",
  "event.kind": "event",
  "event.category": ["network", "intrusion_detection"],
  "event.type": ["connection", "allowed|denied|info"],
  "event.action": "allowed|blocked|tarpitted|banned|flagged",
  "event.outcome": "success|failure|unknown",
  "event.risk_score": 42,
  "event.severity": 1,
  "source.ip": "198.51.100.4",
  "source.port": 54321,
  "destination.ip": "203.0.113.1",
  "destination.port": 443,
  "network.transport": "tcp",
  "network.protocol": "tls",
  "tls.version": "1.3",
  "tls.cipher": "TLS_AES_256_GCM_SHA384",
  "host.name": "ja4proxy-prod-03",
  "host.ip": ["10.1.2.3"],
  "service.name": "ja4proxy",
  "service.version": "1.2.3"
}
```

### 2.2 JA4proxy Extension Fields

Non-ECS fields are namespaced under `ja4proxy.*`:

```json
{
  "ja4proxy.fingerprint.ja4": "t13d1516h2_aabbccddeeff_aabbccddeeff",
  "ja4proxy.fingerprint.ja4x": "aabbccddeeff_aabbccddeeff_aabbccddeeff",
  "ja4proxy.fingerprint.ja4t": "3232128_2-4-8-1-3_1460_8",
  "ja4proxy.dial_setting": 70,
  "ja4proxy.action": "blocked",
  "ja4proxy.score": 78,
  "ja4proxy.signals": [
    {"name": "spamhaus_drop", "score": 80, "detail": "listed in DROP feed"},
    {"name": "datacenter_asn", "score": 15, "detail": "AS14061 DigitalOcean"}
  ],
  "ja4proxy.sni": "api.example.com",
  "ja4proxy.alpn": "h2",
  "ja4proxy.tls_resumed": false,
  "ja4proxy.asn": 14061,
  "ja4proxy.asn_org": "DIGITALOCEAN-ASN",
  "ja4proxy.country_code": "US",
  "ja4proxy.node": "ja4proxy-prod-03",
  "ja4proxy.trace_id": "a3f2b1c4-..."
}
```

### 2.3 Event-Specific Fields

**Ban event** — additionally includes:
```json
{
  "threat.indicator.ip": "198.51.100.4",
  "threat.indicator.type": "ipv4-addr",
  "ja4proxy.ban.ttl_seconds": 3600,
  "ja4proxy.ban.reason": "score_threshold",
  "ja4proxy.ban.expires_at": "2026-04-04T15:23:01Z"
}
```

**Dial change event**:
```json
{
  "event.kind": "configuration",
  "event.action": "dial_changed",
  "ja4proxy.dial.old_value": 60,
  "ja4proxy.dial.new_value": 75,
  "ja4proxy.dial.changed_by": "j.smith@company.com",
  "ja4proxy.dial.itsm_ticket": "CHG0001234"
}
```

**Campaign detection event** (from analytics node):
```json
{
  "event.kind": "alert",
  "event.category": ["intrusion_detection"],
  "event.action": "campaign_detected",
  "ja4proxy.campaign.fingerprint": "t13d1516h2_...",
  "ja4proxy.campaign.ip_count": 47,
  "ja4proxy.campaign.asn_count": 3,
  "ja4proxy.campaign.window_minutes": 60,
  "ja4proxy.campaign.id": "camp-20260404-0042"
}
```

### 2.4 Log Format Migration

Migrating all JA4proxy components to ECS 8.x is a **breaking change** for existing log consumers. The following must be planned before deployment:

**What breaks:**
- Existing Grafana/Loki dashboards that parse the current `ALLOWED: ... | JA4: ...` log format will produce no results after migration.
- Any Prometheus alerting rules that rely on log-derived metrics via Loki will need updating.
- Downstream SIEM queries written against the old format need rewriting.

**Migration strategy:**
1. Add a `log_format` config key: `legacy` (default during transition) or `ecs`.
2. Run both formats in parallel for 2 sprints: the proxy emits both the legacy line and the ECS JSON object on separate log channels (e.g., stdout vs stderr, or two distinct Loki labels).
3. Update all Grafana dashboards and alert rules against the ECS format while legacy is still running.
4. Once dashboards are verified, flip `log_format: ecs` and remove legacy output.

```yaml
# config/proxy.yml
logging:
  format: legacy   # legacy | ecs — change to ecs after dashboard migration
  dual_output: true  # emit both during transition period
```

**CI gate:** Add a schema validation step to CI that runs `ecs-logging-validate` (or equivalent) against sample log output to catch ECS regressions before they ship.

---

## 3. Splunk Technology Add-on

The Splunk TA is the highest-priority deliverable in this phase. Any organisation
running Splunk Enterprise Security (ES) will hard-veto a product without one.

### 3.1 TA Contents

```
ja4proxy-ta/
  app.conf                    # TA metadata
  props.conf                  # sourcetype definition, field extractions
  transforms.conf             # lookup table references
  eventtypes.conf             # event type definitions (ja4proxy_block, ja4proxy_campaign)
  tags.conf                   # CIM tag mappings
  lookups/
    ja4proxy_actions.csv      # action → CIM-friendly label mapping
  macros.conf                 # search macros
  default/
    data/ui/nav/default.xml   # navigation
    data/ui/views/            # dashboards (5 pre-built)
  README/
```

### 3.2 CIM Compliance

Map JA4proxy fields to Splunk's **Common Information Model** Network Traffic and
Intrusion Detection data models. This is what makes JA4proxy work with Splunk ES
correlation searches out of the box.

| JA4proxy field | CIM field |
|----------------|-----------|
| `source.ip` | `src_ip` |
| `destination.ip` | `dest_ip` |
| `network.transport` | `transport` |
| `tls.version` | `ssl_version` |
| `tls.cipher` | `ssl_cipher` |
| `event.action` | `action` |
| `event.risk_score` | `risk_score` |
| `ja4proxy.fingerprint.ja4` | `app` (custom extension) |

### 3.3 Pre-built Correlation Searches (5)

1. **Beaconing detected** — `ja4proxy.action=flagged ja4proxy.signals{}.name=beaconing_detected` — threshold: 3 events in 15 minutes from same source IP
2. **New fingerprint from banned ASN** — join ban list with new `ja4proxy_block` events where ASN matches a previously banned fingerprint's ASN
3. **Dial threshold crossed** — alert when `ja4proxy.dial_setting` changes upward by > 20 points
4. **Burst of blocks from single /24** — > 50 blocked connections in 5 minutes from the same /24 CIDR
5. **New country not seen in 30 days** — `ja4proxy.country_code` in block events where that country has no entries in the last 30 days

### 3.4 Pre-built Dashboards (5)

1. **SOC Real-Time View** — live connection feed, block rate, top attacking fingerprints, dial gauge
2. **Campaign Tracker** — active campaigns, timeline, affected ASNs, fingerprint clusters
3. **Dial & Threshold History** — dial changes over time, blocks-per-day at each threshold
4. **Fingerprint Intelligence** — JA4 fingerprint cardinality, top fingerprints by volume/block rate
5. **Management Summary** — weekly/monthly aggregates for CISO reporting

### 3.5 Alert Action

An alert action that calls `POST /api/v1/bans` on the JA4proxy Management API directly
from a Splunk notable event. Requires an Operator-scoped API token stored in Splunk's
credential store (not in the TA config file).

### 3.6 Certification

Submit to Splunk Cloud Compatibility certification programme. Required for Splunk Cloud
customers (which is the majority of new deployments). Allow 4-6 weeks for the process.

---

## 4. Microsoft Sentinel Content Pack

Required for any enterprise running Azure. Sentinel is now the plurality SIEM in
enterprise new deployments.

### 4.1 Contents

- **Data connector**: ingests JA4proxy events from Log Analytics Workspace via the
  `Custom Logs (DCR-based)` connector, with a DCR (Data Collection Rule) that parses
  the ECS JSON and stores it in the `JA4proxy_CL` custom table.
- **Workbook**: 3 views — SOC analyst real-time, fingerprint intelligence, management
  summary. Mirrors the Splunk dashboards functionally.
- **Analytics rules** (5, scheduled, written in KQL with MITRE ATT&CK tags):
  1. Beaconing detected — T1071 (Application Layer Protocol)
  2. Multiple blocked fingerprints from single IP — T1190 (Exploit Public-Facing App)
  3. Dial change outside maintenance window — T1562 (Impair Defenses)
  4. Campaign from known-bad ASN — T1583 (Acquire Infrastructure)
  5. Spamhaus DROP match — T1078 (Valid Accounts, infrastructure reuse)
- **Playbooks** (Logic Apps, 2):
  1. **Block-IP playbook**: triggered on Sentinel incident → calls `POST /api/v1/bans`
     on JA4proxy API → posts confirmation to Teams/Slack channel
  2. **Enrich-IP playbook**: triggered on any Sentinel alert with a source IP →
     calls `GET /api/v1/connections?ip={ip}&since=30d` → appends fingerprint history
     to the incident as a comment

### 4.2 Publishing

Publish to the Microsoft Sentinel Content Hub (formerly Solutions). This requires a
`createUiDefinition.json` and ARM/Bicep templates wrapping the workbook and playbooks.
Microsoft's review process takes 4-6 weeks.

---

## 5. IBM QRadar DSM

Required for financial services and government accounts that standardised on QRadar.
QRadar is declining in new deployments but entrenched in regulated industries.

### 5.1 Contents

- **Log Source Type**: `JA4proxy TLS Security Proxy` — registered in QRadar's DSM
  Editor
- **LEEF format emitter**: Vector sidecar transform that converts ECS JSON to
  LEEF 2.0 format (`LEEF:2.0|JA4proxy|JA4proxy|1.2.3|blocked|...`)
- **Custom Properties**: `ja4_fingerprint`, `ja4x_fingerprint`, `risk_score`,
  `dial_setting`, `signal_list`
- **QRadar Network Hierarchy mapping**: `src_ip` and `dst_ip` map to QRadar's network
  objects for topology-aware correlation
- **Offense contribution**: configure the DSM to contribute to QRadar offenses on
  high-score block events (risk_score ≥ 70)

---

## 6. Elastic / Kibana Integration Pack

For organisations running the Elastic Stack (ELK). Lower priority than Splunk and
Sentinel but required to avoid losing Elastic-shop deals.

### 6.1 Contents

- **Index template** (`ja4proxy-*`): enforces ECS field mapping with JA4proxy extension
  fields as `keyword` type for efficient filtering
- **Ingest pipeline**: parses the raw JSON log, enriches with GeoIP (Elastic's built-in
  processor), normalises field names
- **ILM policy**: hot (7 days, 50GB max), warm (30 days), cold (90 days), delete
- **Kibana dashboards** (5): mirrors the Splunk dashboard set functionally
- **Detection rules** (5, written in EQL): mirrors the Sentinel analytics rule set

---

## 7. Webhook Event Stream

For SIEMs and custom integrations that prefer push over pull, and for SOAR platforms
(Phase 81) that need real-time event delivery.

### 7.1 Webhook Configuration

```yaml
# config/proxy.yml
webhooks:
  - id: splunk-hec
    url: "https://splunk.corp.internal:8088/services/collector/event"
    secret: "${WEBHOOK_SECRET_SPLUNK}"    # HMAC-SHA256 signing key
    events: ["block", "ban", "campaign", "dial_change", "health_degraded"]
    retry_attempts: 3
    retry_backoff_seconds: 5
    timeout_seconds: 10
```

### 7.2 Webhook Payload

```json
{
  "id": "evt-20260404-a3f2b1c4",
  "timestamp": "2026-04-04T14:23:01.123Z",
  "event_type": "ban",
  "signature": "sha256=abc123...",   // HMAC-SHA256 of body with secret
  "data": { /* full ECS event */ }
}
```

### 7.3 Delivery Guarantees

- At-least-once delivery via Redis Stream persistence
- Failed deliveries retried with exponential backoff
- Dead-letter queue after max retries: `webhooks:dlq` Redis Stream
- `GET /api/v1/webhooks/{id}/status` shows last delivery status and latency

---

## 8. Acceptance Criteria

- [ ] Log format migration plan documented; `log_format` config key implemented with `legacy` and `ecs` modes
- [ ] Dual-output transition mode working; Grafana dashboards updated to ECS format before legacy removed
- [ ] ECS schema validation CI step added to catch regressions
- [ ] All JA4proxy log output conforms to ECS 8.x schema, validated by CI schema check
- [ ] `ja4proxy.*` extension fields documented in `docs/api/ecs_extension.md`
- [ ] Splunk TA packaged, installable, and producing CIM-compliant events
- [ ] All 5 Splunk correlation searches fire correctly against synthetic test events
- [ ] All 5 Splunk dashboards render with live data
- [ ] Splunk alert action successfully calls Management API ban endpoint
- [ ] Sentinel data connector ingests events into `JA4proxy_CL` table
- [ ] All 5 Sentinel analytics rules fire on test events with correct MITRE tags
- [ ] Both Sentinel playbooks execute end-to-end in test tenant
- [ ] QRadar DSM packaged with LEEF emitter and custom properties
- [ ] Elastic index template, ingest pipeline, and ILM policy documented and tested
- [ ] Webhook delivery working with HMAC-SHA256 signature verification
- [ ] Webhook retry and dead-letter queue implemented
- [ ] Vector sidecar config templates provided for all four SIEM targets

---

## 9. Business Track (Not Engineering Acceptance Criteria)

The following are external publishing processes that cannot be completed by the engineering team alone and must not block the phase from being marked COMPLETE:

- **Splunk TA Cloud Compatibility Certification** — submit to Splunk's programme after the TA is packaged and tested. Allow 4–6 weeks for Splunk review. Track separately.
- **Microsoft Sentinel Content Hub publication** — submit ARM/Bicep templates after content pack is validated against a test Sentinel tenant. Allow 4–6 weeks for Microsoft review. Track separately.
