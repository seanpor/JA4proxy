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
PATCH  /api/v1/bans/{ip}               # Extend ban TTL  ← verify Phase 79 delivers this; see P100-J
POST   /api/v1/watchlist               # Add to elevated monitoring
POST   /api/v1/allowlist               # Temporary allowlist entry
DELETE /api/v1/allowlist/{id}          # Remove allowlist entry
GET    /api/v1/connections?ip={ip}     # Connection history for enrichment
GET    /api/v1/fingerprints/{ja4}      # Fingerprint detail and history
PATCH  /api/v1/dial                    # Change dial (Operator token required)
GET    /api/v1/health/deep             # Health check for SOAR monitoring
POST   /api/v1/tokens/{id}/rotate      # Rotate API token  ← verify Phase 79 delivers this; see P100-K
```

Each integration uses an **Operator-scoped API token** stored in the platform's
credential store — never hardcoded in playbook config. Dial changes require explicit
confirmation steps in playbooks due to their fleet-wide impact.

> **Phase 79 dependency check:** Before starting implementation, verify that
> `PATCH /api/v1/bans/{ip}` and `POST /api/v1/tokens/{id}/rotate` are present in the
> merged Phase 79 branch. If either is absent, raise it in Phase 100 (items 100-J and
> 100-K) and build the dependent features against a stub endpoint — do not block the
> rest of Phase 81.

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

**Test strategy:** XSOAR playbooks cannot be executed without an XSOAR tenant, but the
**Python connector code** (`integrations/xsoar/JA4proxy/`) makes HTTP calls to the
Management API — those are fully testable offline. Required:

1. **Unit tests in `tests/integration/test_soar_connectors.py`** — for every command
   (`ja4proxy-ban-ip`, `ja4proxy-release-ban`, etc.), test that the correct HTTP method,
   path, headers, and body are sent. Use a mock HTTP server (`tests/mocks/soar_mock.py`).
   Assert that non-2xx responses are raised as errors with the original status code logged.
2. **Developer tenant (optional)** — Palo Alto provides free XSOAR developer instances.
   If one is available, document setup in `docs/developer/MOCK_SERVERS.md`. Live testing
   moves to Phase 100 (item 100-E) when access is available.

The mock must be implemented for CI to pass. The developer tenant is bonus coverage.

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

**Test strategy:** The Splunk SOAR app (`integrations/splunk_soar/ja4proxy/`) makes
HTTP calls to the Management API. Test all 8 actions against the mock HTTP server in
`tests/mocks/soar_mock.py` (same mock as XSOAR — both call the same Management API
endpoints). Splunk SOAR platform installation is tracked in Phase 100 (item 100-E).

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
table API on ban events. The webhook handler receives an ECS event dict and builds the
ServiceNow payload programmatically — ServiceNow's REST API takes literal JSON values,
not a template language.

Deliver as `integrations/servicenow/ja4proxy_snow_handler.py`:

```python
import json, os, requests

def ecs_to_sir(event: dict) -> dict:
    """Build a ServiceNow SIR payload from a JA4proxy ECS event dict."""
    risk_score = event.get("event.risk_score", 0)
    signals    = event.get("ja4proxy.signals", [])
    signal_txt = "; ".join(
        f"{s['name']}(+{s['score']}): {s['reason']}" for s in signals
    ) if signals else "No signals recorded."
    # SIR severity: 1=Critical, 2=High, 3=Moderate, 4=Low, 5=Planning
    severity = "1" if risk_score >= 85 else "2"
    return {
        "short_description": (
            f"JA4proxy ban: {event.get('source.ip', 'unknown')} "
            f"(score={risk_score})"
        ),
        "description": signal_txt,
        "category": "network_intrusion",
        "severity": severity,
        "u_source_ip":         event.get("source.ip", ""),
        "u_ja4_fingerprint":   event.get("ja4proxy.fingerprint.ja4", ""),
        "u_ja4proxy_ban_id":   event.get("ja4proxy.ban_id", ""),
    }

def create_sir_incident(event: dict) -> str:
    """POST to ServiceNow SIR table. Returns the created incident sys_id."""
    # Credentials read at call time so tests can patch os.environ without
    # reloading the module. No module-level constants.
    snow_instance = os.environ.get("SNOW_INSTANCE", "")
    snow_user     = os.environ.get("SNOW_USER", "")
    snow_pass     = os.environ.get("SNOW_PASS", "")
    sir_url = f"https://{snow_instance}/api/now/table/sn_si_incident"
    payload = ecs_to_sir(event)
    resp = requests.post(
        sir_url,
        auth=(snow_user, snow_pass),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        data=json.dumps(payload),
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["result"]["sys_id"]
```

> **Design note:** credentials are read inside `create_sir_incident()` at call time,
> not at module import. Module-level constants would be evaluated with empty env vars
> during test collection, making env-var patching ineffective without a module reload.

**Unit tests in `tests/unit/test_servicenow_handler.py` (12 tests):**
- `TestEcsToSirSeverity` — boundary tests at 84, 85, 90, 70 (all four boundary/midpoint cases)
- `TestEcsToSirSignals` — signals list → concatenated description; empty list → "No signals recorded."
- `TestEcsToSirFieldMapping` — `source.ip`, `ja4proxy.fingerprint.ja4`, `short_description` content
- `TestCreateSirIncident` — mock `requests.post` returns 201 → returns `sys_id`; verifies
  `u_source_ip`, `severity`, and `category` in the POST body; 403 and 500 error propagation

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

### 6.4 Deployment Architecture Requirement for Mobile Response

The two-way mobile response options in §6.2 (e.g., "False Positive — Release") require xMatters to call the JA4proxy Management API outbound. This means the Management API must be reachable from xMatters Cloud or the xMatters On-Premise Agent. This is a deployment constraint that must be resolved before implementing the integration.

**Option A — Internet-accessible Management API (recommended for cloud deployments):**
Place the Management API behind a reverse proxy with TLS client certificate authentication (mTLS). Only requests presenting a valid xMatters-issued client certificate are accepted. The xMatters Endpoint is configured with the client certificate and the Management API URL.

**Option B — xMatters On-Premise Agent (for air-gapped or internal-only deployments):**
Deploy the xMatters On-Premise Agent inside the corporate network alongside JA4proxy. The agent proxies outbound xMatters Cloud requests to the internal Management API. No internet exposure required. This is the correct choice for most enterprise deployments where the Management API is on an internal network.

Document the chosen option in `docs/enterprise/security-architecture.md` and in the xMatters integration runbook. Default recommendation: Option B for all regulated-industry deployments.

### 6.5 xMatters API Token Storage

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
#
# Source: "stdin" is the correct choice for Docker/container deployments — the
# Go proxy writes to stdout and Docker captures it. "journald" is ONLY correct
# for bare-metal RHEL deployments where the proxy runs as a systemd service.
# This config matches the pattern in vector-sentinel.yaml (Phase 80).
#
# For bare-metal systemd deployments, replace the source with:
#   type: journald
#   units: ["ja4proxy-proxy.service", "ja4proxy-analytics.service"]

sources:
  ja4proxy_logs:
    type: stdin
    # Reads newline-delimited ECS JSON from the Go proxy's stdout.

transforms:
  parse_ecs:
    type: remap
    inputs: ["ja4proxy_logs"]
    source: |
      . = parse_json!(string!(.message))

  to_cef:
    type: remap
    inputs: ["parse_ecs"]
    source: |
      # CEF severity must be an integer 0–10.
      # risk_score is 0-100; divide by 10 and round to nearest integer.
      cef_severity = to_string(to_int(round(float!(.["event.risk_score"]) / 10.0)))

      .cef = "CEF:0|JA4proxy|JA4proxy Proxy|" + string(.["service.version"] ?? "unknown") +
             "|" + string!(.["event.action"]) +
             "|JA4proxy " + string!(.["event.action"]) +
             "|" + cef_severity +
             "|src=" + string!(.["source.ip"]) +
             " dst=" + string(.["destination.ip"] ?? "") +
             " act=" + string!(.["event.action"]) +
             " cs1=" + string(.["ja4proxy.fingerprint.ja4"] ?? "") +
             " cs1Label=JA4Fingerprint"

sinks:
  interlink_syslog:
    type: socket
    inputs: ["to_cef"]
    # Set INTERLINK_SYSLOG_HOST env var to your Service Watch syslog receiver hostname.
    # Vector uses ${ENV_VAR} syntax — not {{ Jinja2 }}.
    address: "${INTERLINK_SYSLOG_HOST}:6514"
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

Phase 81 is **COMPLETE** when all criteria in §9.1 pass. Criteria in §9.2 require
platform access; they are tracked in Phase 100 and do not block phase completion.

### 9.1 Testable offline — Phase 81 completion gate

- [x] XSOAR connector Python package exists at `integrations/xsoar/JA4proxy/`; all 8 commands implemented
- [x] Splunk SOAR app exists at `integrations/splunk_soar/ja4proxy/`; all 8 actions implemented
- [x] ServiceNow handler `integrations/servicenow/ja4proxy_snow_handler.py` exists; `ecs_to_sir()` and `create_sir_incident()` unit-tested (12 tests in `tests/unit/test_servicenow_handler.py`)
- [x] Token rotation script `scripts/rotate_soar_token.sh` exists, documented, calls `POST /api/v1/tokens/{id}/rotate`
- [x] `tests/mocks/soar_mock.py` mock HTTP server implemented; used by XSOAR and Splunk SOAR unit tests
- [x] `tests/integration/test_soar_connectors.py` passes: all 8 XSOAR commands + all 8 Splunk SOAR actions tested against mock server, asserting correct HTTP method, path, headers, and body
- [x] Vector Interlink config `config/integrations/vector-interlink.yaml` exists; CEF severity is integer 0–10; `stdin` source (Docker) documented and bare-metal `journald` variant noted; `${ENV_VAR}` syntax used (not Jinja2)
- [x] Interlink Ansible registration task documented in `docs/integration/interlink_setup.md`
- [x] Interlink correlation rule examples documented in `docs/integration/interlink_correlation_rules.md`
- [x] PagerDuty and OpsGenie `runbook_url` annotations added to all Alertmanager rules in `monitoring/alertmanager/rules/`
- [x] All SOAR integrations use Operator-scoped API tokens; no Admin tokens in any config
- [x] xMatters deployment architecture (Option A and B) documented in `docs/enterprise/security-architecture.md`
- [x] `PATCH /api/v1/bans/{ip}` and `POST /api/v1/tokens/{id}/rotate` verified present in Phase 79 or raised in P100 (items 100-J, 100-K)

### 9.2 Requires platform access — tracked in Phase 100 (item 100-E)

These cannot be completed without platform tenants. When access becomes available, work
these as a sub-task of Phase 100 item 100-E:

- [ ] XSOAR integration package installable; both playbooks execute end-to-end in test tenant
- [ ] Splunk SOAR app installable with all 8 actions functional in a SOAR sandbox
- [ ] ServiceNow SIR incident auto-created on ban webhook; resolution close-loop releases ban
- [ ] xMatters Event Plan routes correctly based on risk_score thresholds; all 5 response options call correct endpoints
- [ ] xMatters Flow Designer integration exported as shared library
- [ ] Interlink Service Watch device registration confirmed in a test Service Watch instance
- [ ] Vector-to-Interlink CEF syslog forwarding confirmed working end-to-end

---

## 10. Implementation Notes

Key decisions and non-obvious fixes made during implementation. Read before
modifying any Phase 81 artifact.

### XSOAR: two Python implementations of the same contract

`integrations/xsoar/JA4proxy/commands.py` — async (`aiohttp`), used by the CI test
suite against the SOARMock server. No `demisto` dependency.

`integrations/xsoar/JA4proxy/JA4proxy.yml` (embedded `script:` field) — synchronous
(`requests`), uses `demisto.params()` / `demisto.args()` / `return_results()`. This is
the code that actually executes inside the XSOAR runtime. XSOAR requires synchronous
Python; aiohttp cannot run in its sandbox.

Do not merge these into one file. They serve different runtimes.

### ServiceNow: credentials at call time, not module level

Early drafts placed `SNOW_INSTANCE`, `SNOW_USER`, `SNOW_PASS`, and `SIR_TABLE_URL` as
module-level constants. These were removed. Module-level `os.environ` reads happen at
import time with empty env vars, making `patch.dict(os.environ, ...)` ineffective
without a full module reload. Read credentials inside the function.

### Token rotation script: `--fail` removed intentionally

`curl --fail` exits non-zero on HTTP 4xx/5xx before the script can inspect the response
body or status code. The HTTP status check (`HTTP_STATUS != "200"`) and specific error
messages were dead code while `--fail` was present. Removed `--fail`; the status check
block now actually runs.

The new token is **intentionally not printed to stdout** to prevent exposure in cron
logs and CI pipelines. Operators must retrieve it from their secrets manager or directly
via the API response. This is a deliberate security trade-off.

### SOARMock: 204 must have no body

`web.json_response({}, status=204)` violates RFC 9110 §15.3.5 (204 No Content MUST NOT
include a message body). The mock now returns `web.Response(status=204)` for all DELETE
requests. This matters for any future test that inspects response headers.

### `ttl_seconds` guard: `<= 0`, not `== 0`

Both the XSOAR `add_to_allowlist` and Splunk SOAR `add_to_allowlist` guard against
`ttl_seconds <= 0`. The original `== 0` check silently accepted negative values (e.g.,
a caller passing `-3600` from a miscalculated expiry). Both unit tests and integration
tests cover zero and negative cases.

### Vector config: `${ENV_VAR}` not `{{ Jinja2 }}`

Vector's VRL/config interpolation uses `${ENV_VAR}` syntax. `{{ variable }}` is Jinja2
(Ansible/Helm) and will not be substituted by Vector — it will be sent as a literal
string to the socket sink, causing a DNS failure at runtime.

### Both connectors include `Accept: application/json`

`_make_headers()` in both `commands.py` and `connector.py` includes
`"Accept": "application/json"`. This matches the embedded XSOAR YAML script. Omitting
it is safe today (the Management API returns JSON regardless) but creates silent
divergence if the API ever gains content negotiation.

---

## 11. Business Track (Not Engineering Acceptance Criteria)

The following are external publishing processes that cannot be completed by the engineering team alone and must not block the phase from being marked COMPLETE:

- **ServiceNow Spoke — ServiceNow Store submission** — submit after the Spoke is validated end-to-end in a test ServiceNow tenant. Store review takes several weeks. Track separately.
- **xMatters shared library publication** — export the Flow Designer integration as a shared library and publish to the xMatters marketplace after internal validation. Track separately.
