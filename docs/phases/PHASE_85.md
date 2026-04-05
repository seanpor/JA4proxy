# Phase 85: Threat Intelligence Ingestion

> **Prerequisite: Phase 79 (Management API) must be complete.**
> Phase 80 (ECS logging) delivers the outbound event format. This phase delivers
> the inbound side — consuming threat intelligence and converting it to JA4proxy rules.

---

## 1. Overview

Phase 20 delivers TAP mode TAXII export — JA4proxy as a threat intel *publisher*.
This phase delivers the inbound side: JA4proxy as a threat intel *consumer*.

The strategic opportunity here is larger than it appears. JA4proxy sees the TLS
fingerprint of every threat actor — something no IP-reputation feed captures. A
curated, community-sourced JA4 fingerprint feed becomes a **strategic moat**: the
longer the product is deployed, the more fingerprints it accumulates, the harder it
is for attackers to evade. This is the same flywheel Spamhaus built with IP reputation,
but applied to TLS behaviour.

This phase delivers:

1. **TAXII 2.1 client** — pull JA4 fingerprint indicators from any TAXII server
2. **JA4 STIX 2.1 extension** — first published standard for JA4 fingerprint indicators
3. **Recorded Future connector** — named commercial feed (common in enterprise)
4. **CrowdStrike Threat Intelligence connector** — named commercial feed
5. **Curated JA4 fingerprint feed architecture** — infrastructure for the strategic moat
6. **Feed management UI** — enable/disable/monitor feeds from the Management UI

---

## 2. TAXII 2.1 Client

### 2.1 Architecture

The threat intel client runs as a background task in the analytics node. It polls
configured TAXII servers on a schedule, converts indicators to JA4proxy rules via
the Management API, and logs all ingestion activity to the audit trail.

```
TAXII Server                   Analytics Node                JA4proxy API
    │                               │                              │
    │◀── GET /taxii2/collections ───│                              │
    │──── collection list ─────────▶│                              │
    │◀── GET /collections/{id}/     │                              │
    │         objects?added_after=  │                              │
    │──── STIX bundle ─────────────▶│                              │
    │                               │── parse indicators ──────────│
    │                               │── POST /api/v1/blocklist ───▶│
    │                               │── POST /api/v1/bans ─────────│
    │                               │◀── 201 Created ─────────────│
    │                               │── write audit log ───────────│
```

### 2.2 Configuration

```yaml
# config/proxy.yml
threat_intel:
  feeds:
    - id: taxii-isac
      type: taxii2
      url: "https://taxii.example-isac.org/taxii2/"
      collection_id: "enterprise-attack"
      username: "${TAXII_ISAC_USERNAME}"
      password: "${TAXII_ISAC_PASSWORD}"
      poll_interval_minutes: 60
      enabled: true
      # Object types to consume (ignore others)
      consume:
        - indicator          # STIX Indicator objects
      # Only ingest indicators with these pattern types
      pattern_types:
        - ipv4-addr          # IP bans
        - ipv6-addr
        - x-ja4-fingerprint  # JA4 blocklist (Phase 85 extension)
      # Only ingest above this confidence threshold (0-100)
      min_confidence: 70
      # TTL for auto-created bans (0 = no expiry)
      ban_ttl_hours: 168     # 7 days
      # Tag applied to all managed_by values for this feed
      managed_by_tag: "taxii-isac"
```

### 2.3 Feed Circuit-Breaker

Feed polling must not retry endlessly on failure. Implement a per-feed circuit-breaker:

```python
# src/analytics/ti_feed_client.py — circuit-breaker behaviour
# State: CLOSED (normal) → OPEN (failed) → HALF-OPEN (testing recovery)

CIRCUIT_BREAKER_THRESHOLD = 3        # failures before opening
CIRCUIT_BREAKER_TIMEOUT_S  = 600     # 10 minutes before testing recovery
CIRCUIT_BREAKER_BACKOFF_MAX_S = 3600 # max backoff: 1 hour

# On failure:
# 1. Increment failure counter for feed_id
# 2. If counter >= threshold: open circuit, log WARNING, increment Prometheus counter
#    ja4proxy_ti_feed_circuit_open{feed_id="taxii-isac"}
# 3. While open: skip poll, log DEBUG "circuit open, skipping"
# 4. After timeout: attempt one poll (HALF-OPEN)
#    - Success: close circuit, reset counter, log INFO "circuit closed"
#    - Failure: reset timeout, stay open, log WARNING
```

Add Prometheus metrics:
- `ja4proxy_ti_feed_poll_total{feed_id, result="success|failure|skipped"}` — counter
- `ja4proxy_ti_feed_circuit_open{feed_id}` — gauge (1 = open, 0 = closed)
- `ja4proxy_ti_feed_indicators_managed{feed_id}` — gauge

Add Alertmanager rule: alert when `ja4proxy_ti_feed_circuit_open == 1` for > 30 minutes.

### 2.4 Indicator Processing

For each STIX Indicator received:
1. Check if it's an IP pattern — if so, call `POST /api/v1/bans` with `managed_by=taxii-isac`
2. Check if it's a `x-ja4-fingerprint` pattern — if so, call `POST /api/v1/blocklist`
3. Check if indicator has TTL (`valid_until`) — pass through as `expires_at`
4. Deduplicate: if indicator already exists with matching content, skip (idempotent)
5. Log to audit trail: `actor=feed:taxii-isac, action=blocklist_entry_added, source=taxii`

### 2.5 Automatic Feed Cleanup

When an indicator expires in the TAXII feed (revoked or past `valid_until`), the
client calls `DELETE /api/v1/blocklist/{id}` or `DELETE /api/v1/bans/{ip}` to remove
it. Rules added by a feed are only removed by that feed — human-added rules are never
affected.

---

## 3. JA4 STIX 2.1 Extension

The standard STIX 2.1 Indicator object does not have a pattern type for JA4
fingerprints. This extension defines one.

### 3.1 Extension Definition

```json
{
  "type": "extension-definition",
  "spec_version": "2.1",
  "id": "extension-definition--3b37e1e8-5a20-4c3d-aa0c-9a581b6f9d4e",
  "name": "JA4 Fingerprint Extension",
  "description": "Extends STIX 2.1 Indicator objects to support JA4 TLS fingerprint patterns.",
  "created": "2026-04-04T00:00:00Z",
  "modified": "2026-04-04T00:00:00Z",
  "created_by_ref": "identity--ja4proxy-project",
  "schema": "https://ja4proxy.io/stix/extensions/ja4-fingerprint/schema.json",
  "version": "1.0",
  "extension_types": ["property-extension"],
  "extension_properties": ["pattern_type"]
}
```

### 3.2 JA4 Indicator Pattern

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--a1b2c3d4-...",
  "name": "Cobalt Strike default TLS profile",
  "pattern_type": "x-ja4-fingerprint",
  "pattern": "[x-ja4-fingerprint:value = 't10d170900_9dc949161b6c_b64c0ad42cb7']",
  "indicator_types": ["malicious-activity"],
  "confidence": 95,
  "valid_from": "2026-04-04T00:00:00Z",
  "kill_chain_phases": [
    {"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}
  ],
  "extensions": {
    "extension-definition--3b37e1e8-...": {
      "extension_type": "property-extension",
      "ja4": "t10d170900_9dc949161b6c_b64c0ad42cb7",
      "ja4x": null,
      "source": "ja4proxy-community-feed",
      "likely_category": "c2_framework",
      "likely_tool": "cobalt_strike"
    }
  }
}
```

### 3.3 Publishing the Extension

The extension definition is:
- Published to `https://ja4proxy.io/stix/extensions/ja4-fingerprint/`
- Registered in the OASIS STIX community by posting to the `cti-stix2-json-schemas` GitHub repository (the community convention for custom extension definitions — OASIS does not operate a formal approval registry). Open a PR adding the extension schema to `extensions/` in that repo and note the PR URL in `docs/stix/ja4-fingerprint-extension.md`.
- Documented in `docs/stix/ja4-fingerprint-extension.md` with full schema and examples

This establishes JA4proxy as the reference implementation for JA4 threat indicators.
Any other tool that wants to share JA4 fingerprint threat intel uses this extension.

### 3.4 UUID Reservation

The extension definition UUID (`extension-definition--3b37e1e8-5a20-4c3d-aa0c-9a581b6f9d4e`) becomes the permanent canonical identifier once published. It cannot be changed without breaking every downstream consumer.

**Before any implementation:**
1. Verify this UUID does not clash with any existing STIX extension definition by searching the OASIS CTI TC schema repository and the MITRE ATT&CK extension registry.
2. If a clash is found, generate a new UUID with `python3 -c "import uuid; print('extension-definition--' + str(uuid.uuid4()))"` and update the spec.
3. Record the confirmed UUID in `docs/stix/ja4-fingerprint-extension.md` with a note: "This UUID is permanent. Do not change post-publication."

This is a pre-implementation gate: no STIX code is written until the UUID is confirmed and recorded.

---

## 4. Commercial Feed Connectors

### 4.1 Recorded Future

Recorded Future offers a TAXII 2.0/2.1 feed for customers with an API subscription.
The standard TAXII client (§2) handles most of the work; the connector adds:

- **Automatic credential exchange**: reads `RF_API_TOKEN` from environment, exchanges
  for TAXII credentials via Recorded Future's token endpoint
- **Feed selection**: configures the correct collection IDs for IP intelligence and
  (when RF adds support) fingerprint indicators
- **Fusion score mapping**: RF confidence score → min_confidence threshold translation

```yaml
threat_intel:
  feeds:
    - id: recorded-future
      type: recorded_future
      api_token: "${RF_API_TOKEN}"
      feeds:
        - ip_threat_intel       # IP bans
        - c2_server_tracking    # IP bans with C2 context
      min_rf_risk_score: 75     # RF uses 0-100 risk score
      ban_ttl_hours: 72
      enabled: false            # opt-in
```

### 4.2 CrowdStrike Threat Intelligence

CrowdStrike Falcon Intelligence exposes an indicator API (not TAXII). The connector
calls the Falcon Intel API directly:

```yaml
threat_intel:
  feeds:
    - id: crowdstrike-falcon
      type: crowdstrike
      client_id: "${CS_CLIENT_ID}"
      client_secret: "${CS_CLIENT_SECRET}"
      indicator_types:
        - ip_address
        - domain              # Used for SNI blocklist (future)
      min_malicious_confidence: high   # low|medium|high
      poll_interval_minutes: 30
      ban_ttl_hours: 48
      enabled: false
```

The connector:
1. Authenticates via `POST /oauth2/token` with `scope=indicators:read`
2. Polls `GET /intel/combined/indicators/v1?type=ip_address&malicious_confidence=high`
3. Converts to Management API bans via the same path as TAXII indicators
4. Handles CrowdStrike pagination (cursor-based, not offset)

### 4.3 Generic REST Feed Connector

For threat intel platforms with non-standard APIs, a configurable REST connector:

```yaml
threat_intel:
  feeds:
    - id: internal-threat-intel
      type: rest
      url: "https://threatintel.corp.internal/api/v1/indicators"
      auth:
        type: bearer
        token: "${INTERNAL_TI_TOKEN}"
      # JSONPath to extract IPs from response
      ip_jsonpath: "$.indicators[*].value"
      # JSONPath to extract TTL (in seconds, optional)
      ttl_jsonpath: "$.indicators[*].expires_in"
      # Static TTL if not in response
      ban_ttl_hours: 24
      poll_interval_minutes: 15
```

---

## 5. Curated JA4 Fingerprint Feed

> **Scope boundary:** §5.1–§5.3 (hosted feed infrastructure) are a **business track item**, not an engineering deliverable for this phase. The engineering team delivers §5.4 (the bundled seed file) and §5.2 (the contribution client config). The hosted TAXII server at `https://feed.ja4proxy.io/` requires cloud infrastructure, a domain, a curation process, and ongoing operations — this is a product investment decision separate from Phase 85.

### 5.1 Architecture (Future Hosted Feed — Business Track)

```
Customer Deployment A  ──▶ ┐
Customer Deployment B  ──▶ │──▶ JA4proxy Cloud Feed ──▶ TAXII Server ──▶ All Customers
Customer Deployment C  ──▶ ┘         (opt-in, hosted service — future)
```

When the hosted feed is launched (business track), each contributing customer submits:
- JA4 fingerprints blocked with high confidence (risk score ≥ 85)
- Triggering signals (no PII — no raw IP addresses)
- Confirmed false-positive rate

### 5.2 Contribution Client (Engineering Deliverable)

The contribution client config is an engineering deliverable — the code to send data to a future hosted feed. Disabled by default. When the hosted feed is available, customers opt in:

```yaml
threat_intel:
  feed_contribution:
    enabled: false   # opt-in, never default
    submit_threshold: 90
    submit_min_occurrences: 100
    anonymise: true
    endpoint: "https://feed.ja4proxy.io/api/v1/contribute"   # future hosted service
    api_key: "${JA4PROXY_FEED_API_KEY}"
```

The contribution endpoint is stubbed in the code but not functional until the hosted service exists. Emit a log WARNING if `enabled: true` but the endpoint is unreachable.

### 5.3 Feed Format (Future)

When the hosted feed launches:
- TAXII 2.1 server at `https://feed.ja4proxy.io/taxii2/`
- JSON download at `https://feed.ja4proxy.io/ja4-blocklist.json`
- Compatible with the standard TAXII client from §2 — no special integration needed

### 5.4 Initial Seed File (Engineering Deliverable)

Ship a `config/known_bad_fingerprints.yml` bundled with the product. This is an engineering deliverable — a static YAML file of vetted public-research fingerprints, loadable by the blocklist module on startup.

```yaml
# config/known_bad_fingerprints.yml — phase-85
# Source: public security research, verified against production traffic
# This file is loaded at startup if threat_intel.seed_file.enabled: true
fingerprints:
  - ja4: "t10d170900_9dc949161b6c_b64c0ad42cb7"
    name: "Cobalt Strike default TLS profile"
    category: c2_framework
    source: "https://github.com/FoxIO-LLC/ja4/tree/main/technical_details"
    confidence: 98

  - ja4: "t13d190900_9dc949161b6c_e7d705d9851f"
    name: "Masscan with TLS (scanner)"
    category: scanner
    source: public_research
    confidence: 95

  - ja4: "t10d010600_0000000000_e7d705d9851f"
    name: "TLS 1.0 scanner (legacy protocol)"
    category: scanner
    source: public_research
    confidence: 85
```

---

## 6. Feed Management UI

The Management UI (Phase 79+ management API) exposes feed status at
`GET /api/v1/threat-intel/feeds`:

```json
[
  {
    "id": "taxii-isac",
    "type": "taxii2",
    "status": "healthy",
    "last_poll": "2026-04-04T14:00:00Z",
    "next_poll": "2026-04-04T15:00:00Z",
    "indicators_managed": 1247,
    "last_24h_additions": 14,
    "last_24h_removals": 3,
    "error_count_24h": 0
  }
]
```

The feed management page in the UI shows:
- Feed status cards (green/yellow/red)
- Indicators managed per feed
- Recent additions and removals
- Error log for failed polls
- Enable/disable toggle per feed (requires Operator role)

---

## 7. Acceptance Criteria

- [ ] UUID confirmed non-clashing and recorded in `docs/stix/ja4-fingerprint-extension.md` before any STIX code is written
- [ ] Circuit-breaker implemented with Prometheus metrics and Alertmanager rule
- [ ] `config/known_bad_fingerprints.yml` ships with ≥ 10 vetted fingerprints (seed file — engineering deliverable)
- [ ] Contribution client code present but endpoint stubbed; WARNING logged if enabled without live hosted service
- [ ] TAXII 2.1 client polls configured servers and creates blocklist/ban entries
- [ ] Deduplication: re-ingesting the same indicator is a no-op
- [ ] Expired/revoked TAXII indicators are removed from blocklist/bans
- [ ] All feed-ingested rules have `managed_by=feed:{id}` tag
- [ ] JA4 STIX 2.1 extension definition published at `docs/stix/`
- [ ] `x-ja4-fingerprint` pattern type accepted by TAXII client
- [ ] Recorded Future connector authenticates and polls IP intel feed
- [ ] CrowdStrike connector authenticates (OAuth2) and polls indicators
- [ ] Generic REST connector works with configurable JSONPath extraction
- [ ] `known_bad_fingerprints.yml` ships with ≥10 vetted fingerprints
- [ ] Feed contribution config documented and opt-in only (opt-in, endpoint stubbed until hosted service available)
- [ ] Feed management API endpoint returns per-feed status
- [ ] Feed status visible in Management UI
- [ ] All feed operations logged to audit trail with `source=feed:{id}`
- [ ] Feed polling failures circuit-break and alert (do not retry endlessly)
- [ ] Min confidence threshold respected — below-threshold indicators are logged but not applied

---

## 8. Business Track (Not Engineering Acceptance Criteria)

- **Hosted JA4proxy community feed** (`https://feed.ja4proxy.io/`) — requires cloud infrastructure, domain, TLS certificates, a curation team, and ongoing operations. This is a product investment decision, not an engineering task for Phase 85.
- **OASIS CTI TC community registration** — post the extension schema to `cti-stix2-json-schemas` as a community PR. Not a blocking gate; track separately.
