# Phase 81: SOAR, Webhooks & Enterprise Operations Platforms

> **Prerequisite: Phase 79 (Management API + scoped tokens) must be complete.**
> Phase 80 (webhooks) delivers the event stream this phase consumes.

---

## 1. Overview

Enterprise security operations teams do not respond to alerts manually — they run
automated playbooks and expect tools to close the response loop bidirectionally.
This phase delivers integration with the platforms that enterprise SOC and NOC teams
use for incident response, alert routing, and workflow automation:

- **Palo Alto XSOAR** — dominant enterprise SOAR
- **Splunk SOAR** (formerly Phantom) — common in Splunk-centric shops
- **ServiceNow SecOps** — ITSM-governed response; mandatory in enterprises where
  every security action requires a ticket
- **xMatters** — on-call routing with two-way mobile response; dominant in
  enterprises that run ServiceNow + xMatters as a pair
- **Interlink Software Service Watch** — UK enterprise NOC event management and
  auto-ticketing; common in UK financial services, telco, and utilities
- **PagerDuty / OpsGenie** — pure alerting with runbook links (lower complexity,
  higher coverage)

---

## 2. Required Management API Actions

All integrations in this phase depend on the following API endpoints (Phase 79):

```
POST   /api/v1/bans                    # Block an IP
DELETE /api/v1/bans/{ip}               # Release a ban
POST   /api/v1/watchlist               # Add to elevated monitoring
POST   /api/v1/allowlist               # Temporary allowlist entry
DELETE /api/v1/allowlist/{id}          # Remove allowlist entry
GET    /api/v1/connections?ip={ip}     # Connection history for enrichment
GET    /api/v1/fingerprints/{ja4}      # Fingerprint detail and history
PATCH  /api/v1/dial                    # Change dial (Operator token required)
GET    /api/v1/health/deep             # Health check for SOAR monitoring
```

Each integration uses an **Operator-scoped API token** stored in the platform's
credential store — never hardcoded in playbook config. Dial changes require explicit
confirmation steps in playbooks due to their fleet-wide impact.

---

## 3. Palo Alto XSOAR Integration

XSOAR is the market-leading enterprise SOAR and the first integration any serious
enterprise buyer will ask for.

### 3.1 Integration Package

A custom XSOAR integration (`JA4proxy`) with the following commands:

| Command | Description |
|---------|-------------|
| `ja4proxy-ban-ip` | Ban an IP with optional TTL and justification |
| `ja4proxy-release-ban` | Release an active ban |
| `ja4proxy-get-connection-history` | Return connection timeline for an IP |
| `ja4proxy-get-fingerprint-detail` | Full fingerprint intel including associated IPs |
| `ja4proxy-add-to-watchlist` | Add IP to elevated monitoring |
| `ja4proxy-get-health` | Deep health check of all nodes |
| `ja4proxy-add-to-allowlist` | Temporary allowlist (with mandatory expiry) |
| `ja4proxy-get-dial` | Return current dial setting |

**Test strategy:** XSOAR playbooks cannot be tested without an XSOAR tenant. Two acceptable approaches:
1. **Developer tenant** — Palo Alto provides free XSOAR developer instances; provision one for integration testing. Document setup in `docs/developer/MOCK_SERVERS.md`.
2. **Mock HTTP server** — implement a mock XSOAR webhook receiver in `tests/mocks/soar_mock.py` that validates the correct API calls are made. Both approaches must be documented; at least the mock must be implemented for CI.

### 3.2 Incident Playbooks (2)

**Playbook 1 — JA4proxy Ban Event Response:**
```
Trigger: JA4proxy ban webhook → XSOAR incident
1. Enrich: call ja4proxy-get-connection-history for the banned IP (last 7 days)
2. Enrich: call ja4proxy-get-fingerprint-detail for the associated JA4 fingerprint
3. Enrich: VirusTotal, AbuseIPDB lookups on the IP
4. Decision gate: if risk_score ≥ 85 AND VirusTotal detections > 3:
   → Auto-escalate: create ServiceNow P2 incident
   → Notify: post enrichment summary to #security-incidents Slack channel
5. If risk_score < 50: flag for analyst review, do not auto-escalate
6. Close-loop: when ServiceNow incident resolved → call ja4proxy-release-ban if FP confirmed
```

**Playbook 2 — IOC Push (Threat Intel → JA4proxy):**
```
Trigger: new high-confidence IP indicator from threat intel feed
1. Check: call ja4proxy-get-connection-history — has this IP been seen?
2. If seen in last 30 days: call ja4proxy-ban-ip with TTL=72h
3. If not seen: call ja4proxy-add-to-watchlist
4. Log: create XSOAR indicator with JA4proxy context
5. Notify: post to #threat-intel channel
```

---

## 4. Splunk SOAR Integration

For Splunk-centric security teams that run Splunk SOAR alongside Splunk ES.

### 4.1 App Contents

A Splunk SOAR app (`ja4proxy`) with actions:

| Action | Parameters |
|--------|-----------|
| `block_ip` | `ip`, `ttl_seconds`, `reason` |
| `unblock_ip` | `ip` |
| `get_connection_history` | `ip`, `days` |
| `get_fingerprint_history` | `ja4_fingerprint`, `days` |
| `add_to_watchlist` | `ip`, `reason` |
| `add_to_allowlist` | `ip`, `ttl_seconds`, `reason` |
| `remove_from_allowlist` | `ip` |
| `get_health` | — |

**Test strategy:** Use the existing `tests/mocks/` pattern. A Splunk SOAR mock server or developer sandbox must be documented for integration testing.

### 4.2 Connector Configuration

The app stores the Management API base URL and Operator-scoped API token in Splunk
SOAR's asset configuration (encrypted credential store). Token rotation is handled
by calling `POST /api/v1/tokens/{id}/rotate` and updating the SOAR asset — a process
that should be scripted and run on a 90-day schedule.

**Token rotation script:** A script `scripts/rotate_soar_token.sh` must be delivered with this phase. It calls `POST /api/v1/tokens/{id}/rotate`, updates the SOAR platform asset/credential via its API, and logs the rotation event. Validated for Splunk SOAR and XSOAR. Run on a 90-day schedule via cron or CI.

---

## 5. ServiceNow SecOps Integration

In enterprises where ServiceNow is the system of record for all security actions,
every JA4proxy block must have a corresponding ticket. This is not optional — without
it, SecOps teams cannot demonstrate compliance (every action must be traceable to a
change record).

### 5.1 Automatic Incident Creation

Configure JA4proxy webhooks to call ServiceNow's **Security Incident Response (SIR)**
table API on ban events:

```json
// POST https://company.service-now.com/api/now/table/sn_si_incident
{
  "short_description": "JA4proxy ban: {{ source.ip }} (score={{ event.risk_score }})",
  "description": "{{ ja4proxy.signals | format }}",
  "category": "network_intrusion",
  "severity": "{{ risk_score >= 85 ? '1' : '2' }}",
  "u_source_ip": "{{ source.ip }}",
  "u_ja4_fingerprint": "{{ ja4proxy.fingerprint.ja4 }}",
  "u_ja4proxy_ban_id": "{{ ja4proxy.ban_id }}"
}
```

### 5.2 Enrichment Action

When a ServiceNow security analyst opens a JA4proxy-created incident, a flow action
calls `GET /api/v1/connections?ip={source_ip}&since=30d` and appends the connection
history as a work note. The analyst sees full context without leaving ServiceNow.

### 5.3 Resolution Close-Loop

When a ServiceNow SIR incident is resolved as a false positive:
- Resolution workflow triggers a ServiceNow flow
- Flow calls `DELETE /api/v1/bans/{ip}` via the JA4proxy Spoke (Integration Hub)
- Flow calls `POST /api/v1/allowlist` with `ttl_seconds=86400` to prevent immediate
  re-ban
- JA4proxy audit log records the release, attributed to the ServiceNow ticket number

### 5.4 ServiceNow Spoke (Integration Hub)

Publish a ServiceNow Spoke in the ServiceNow Store. The Spoke exposes JA4proxy actions
as Flow Designer steps, allowing ServiceNow administrators to build custom workflows
without writing script. Required for enterprises that restrict custom scripting in
ServiceNow.

---

## 6. xMatters Integration

xMatters is not just an alerting tool — it provides two-way workflow automation with
mobile response capability. The integration is significantly richer than PagerDuty.

### 6.1 Inbound Event Plan

Configure an xMatters inbound integration (HTTP trigger) that receives JA4proxy
webhook events and routes them through an xMatters Event Plan:

**JA4proxy Event Plan — routing logic:**

| Condition | Route to | Notification |
|-----------|----------|-------------|
| `risk_score >= 85` AND `campaign_detected=true` | SecOps manager + on-call analyst | Phone call + push + SMS |
| `risk_score >= 85` | On-call SecOps analyst | Push + SMS |
| `health_degraded=true` | On-call SRE | Push + SMS |
| `dial_changed=true` AND outside maintenance window | SecOps manager | Push |
| `risk_score >= 70` | On-call analyst | Push only |

### 6.2 Response Options (Two-Way)

When an on-call engineer receives an xMatters notification, they can respond with
one of these options directly from their mobile device — no need to open a browser:

| Response | Action xMatters takes |
|----------|----------------------|
| `Acknowledge` | Posts acknowledgement to #security-ops Slack, creates ServiceNow work note |
| `Escalate` | Notifies SecOps manager, promotes to P1 in ServiceNow |
| `False Positive — Release` | Calls `DELETE /api/v1/bans/{ip}` + `POST /api/v1/allowlist` (24h TTL) |
| `Extend Ban` | Calls `PATCH /api/v1/bans/{ip}` extending TTL by 24h |
| `View Context` | Opens deep link to JA4proxy Management UI fingerprint detail page |

### 6.3 Flow Designer Integration

Use xMatters Flow Designer (no-code workflow builder) to define the full flow.
Publish it as an xMatters shared library so other xMatters customers can install it.

**Conditional example:**
```
IF event_type == "campaign_detected"
  AND ip_count > 20
  AND asn_country_code != "GB"   // configurable per deployment
THEN:
  Create ServiceNow P2 incident
  Notify SecOps manager AND on-call analyst simultaneously
  Post campaign summary to #threat-intel Slack channel
```

### 6.5 Deployment Architecture Requirement for Mobile Response

The two-way mobile response options in §6.2 (e.g., "False Positive — Release") require xMatters to call the JA4proxy Management API outbound. This means the Management API must be reachable from xMatters Cloud or the xMatters On-Premise Agent. This is a deployment constraint that must be resolved before implementing the integration.

**Option A — Internet-accessible Management API (recommended for cloud deployments):**
Place the Management API behind a reverse proxy with TLS client certificate authentication (mTLS). Only requests presenting a valid xMatters-issued client certificate are accepted. The xMatters Endpoint is configured with the client certificate and the Management API URL.

**Option B — xMatters On-Premise Agent (for air-gapped or internal-only deployments):**
Deploy the xMatters On-Premise Agent inside the corporate network alongside JA4proxy. The agent proxies outbound xMatters Cloud requests to the internal Management API. No internet exposure required. This is the correct choice for most enterprise deployments where the Management API is on an internal network.

Document the chosen option in `docs/enterprise/security-architecture.md` and in the xMatters integration runbook. Default recommendation: Option B for all regulated-industry deployments.

### 6.4 xMatters API Token Storage

Store the JA4proxy Operator-scoped API token in xMatters' Endpoint configuration
(encrypted). xMatters outbound calls to JA4proxy are authenticated via this token.

---

## 7. Interlink Software Service Watch Integration

Interlink Service Watch is the UK enterprise NOC event management platform. Common
in UK financial services, utilities, and telco. Provides event correlation,
topology-aware alerting, and ITSM auto-ticketing.

### 7.1 JA4proxy as a Managed Entity

Register each JA4proxy node in Service Watch as a custom device class
`"Network Security Appliance / TLS Proxy"` via the Ansible post-deploy role:

```yaml
# Ansible task: register node in Interlink Service Watch
- name: Register JA4proxy node in Interlink Service Watch
  uri:
    url: "{{ interlink_api_url }}/api/v2/devices"
    method: POST
    headers:
      Authorization: "Bearer {{ interlink_api_token }}"
    body_format: json
    body:
      name: "{{ inventory_hostname }}"
      class: "network_security_appliance"
      ip_address: "{{ ansible_host }}"
      attributes:
        version: "{{ ja4proxy_image_tag }}"
        upstream_lb: "{{ upstream_lb_host }}"
        downstream_backend: "{{ backend_host }}"
        environment: "{{ deploy_environment }}"
```

### 7.2 Event Ingestion

Service Watch accepts events via CEF over syslog (TLS). Configure the Vector sidecar
on each proxy host to forward JA4proxy events to the Interlink Service Watch syslog
receiver:

```yaml
# config/integrations/vector-interlink.yaml (Vector sidecar config)
sources:
  ja4proxy_logs:
    type: journald
    units: ["ja4proxy-proxy.service", "ja4proxy-analytics.service"]

transforms:
  to_cef:
    type: remap
    inputs: ["ja4proxy_logs"]
    source: |
      .cef = "CEF:0|JA4proxy|JA4proxy Proxy|" + .service.version +
             "|" + .event.action +
             "|JA4proxy " + .event.action +
             "|" + string!(.event.risk_score / 10) +
             "|src=" + .source.ip +
             " dst=" + .destination.ip +
             " act=" + .event.action +
             " cs1=" + .ja4proxy.fingerprint.ja4 +
             " cs1Label=JA4Fingerprint"

sinks:
  interlink_syslog:
    type: socket
    inputs: ["to_cef"]
    address: "{{ interlink_syslog_host }}:6514"
    mode: tcp
    tls:
      enabled: true
      ca_file: "/etc/ja4proxy/tls/interlink-ca.crt"
```

### 7.3 Event Correlation Rules

Service Watch administrators configure correlation rules to reduce alert noise.
Provide example rules in `docs/integration/interlink_correlation_rules.md`:

**Campaign rule**: if N ban events from the same ASN occur within T minutes, emit
a single `"Campaign Detected"` event rather than N individual ban alerts. This is
the key value Interlink provides — correlation before the NOC sees it.

**Health degradation rule**: if the JA4proxy device health check transitions from
`OK` to `DEGRADED`, emit a P2 alert and create a Remedy/ServiceNow incident
automatically via Interlink's ITSM connector.

### 7.4 Auto-Ticketing

Interlink Service Watch integrates natively with Remedy, ServiceNow, and Jira Service
Management. Configure the JA4proxy campaign event class to auto-create an ITSM ticket
with the event correlation summary. This is configuration in Service Watch, not code
in JA4proxy — document the required configuration in the integration guide.

---

## 8. PagerDuty and OpsGenie

Both are pure alerting platforms. The integration is simpler — one-way event push,
no bidirectional action. The critical addition over the existing Phase 14e Prometheus
alerting is **runbook links in every alert**.

Every Alertmanager rule must include:
```yaml
annotations:
  runbook_url: "https://docs.example.com/runbooks/ja4proxy/{{ .Labels.alertname }}"
  summary: "{{ .Annotations.description }}"
```

PagerDuty integration key and OpsGenie API key are configured in Alertmanager.
No custom code required — Alertmanager's built-in PagerDuty and OpsGenie receivers
handle delivery. This is a configuration task, not a development task.

---

## 9. Acceptance Criteria

- [ ] XSOAR integration package installable and both playbooks execute end-to-end in test tenant
- [ ] Splunk SOAR app installable with all 7 actions functional
- [ ] ServiceNow SIR incident auto-created on ban webhook event
- [ ] ServiceNow resolution close-loop releases ban and adds allowlist entry
- [ ] xMatters Event Plan routes correctly based on risk_score thresholds
- [ ] All 5 xMatters mobile response options call the correct API endpoints
- [ ] xMatters Flow Designer integration exported as shared library
- [ ] Interlink Service Watch device registration via Ansible post-deploy role
- [ ] Vector-to-Interlink CEF syslog forwarding working with TLS
- [ ] Interlink correlation rule examples documented in `docs/integration/`
- [ ] PagerDuty and OpsGenie runbook URLs on all Alertmanager rules
- [ ] All SOAR integrations use Operator-scoped API tokens (never Admin)
- [ ] Token rotation script documented and validated for all platforms
- [ ] Mock SOAR server or developer tenant documented in `tests/mocks/` or `docs/developer/MOCK_SERVERS.md`
- [ ] Token rotation script `scripts/rotate_soar_token.sh` implemented and tested for XSOAR and Splunk SOAR
- [ ] xMatters deployment architecture (Option A or B) documented in `docs/enterprise/security-architecture.md`

---

## 10. Business Track (Not Engineering Acceptance Criteria)

The following are external publishing processes that cannot be completed by the engineering team alone and must not block the phase from being marked COMPLETE:

- **ServiceNow Spoke — ServiceNow Store submission** — submit after the Spoke is validated end-to-end in a test ServiceNow tenant. Store review takes several weeks. Track separately.
- **xMatters shared library publication** — export the Flow Designer integration as a shared library and publish to the xMatters marketplace after internal validation. Track separately.
