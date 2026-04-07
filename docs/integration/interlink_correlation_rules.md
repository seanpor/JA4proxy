<!--
title: Interlink Service Watch Correlation Rules
audience: NOC Engineers, Service Watch Administrators
last_reviewed: 2026-04-07
phase: 81
-->

# Interlink Service Watch Correlation Rules

This document provides example correlation rules for Interlink Software Service Watch
to reduce alert noise from JA4proxy events and surface actionable incidents.

All rules are configured in Service Watch, not in JA4proxy. The proxy delivers raw
CEF events to Service Watch via the Vector sidecar (see `interlink_setup.md`). Service
Watch applies these rules to correlate and enrich those events before the NOC sees them.

Configurable parameters (N, T, R) are shown in uppercase. Set these to values that
match your environment's normal traffic volume during the Service Watch rule editor
session.

---

## Campaign Detection Rule

When multiple ban events arrive from the same ASN within a short window, they indicate
a coordinated campaign rather than isolated incidents. This rule collapses N individual
ban events into a single `Campaign Detected` event, reducing NOC queue noise
significantly.

```
# Rule: JA4proxy Campaign Detection
# Class: ja4proxy_campaign
#
# Purpose: Correlate individual ban events from the same ASN into a single
# campaign alert. Prevents the NOC console from filling with hundreds of
# individual ban entries during a single attack wave.
#
# Configurable parameters:
#   N = minimum number of ban events to trigger campaign (recommended: 5)
#   T = time window in minutes (recommended: 10)

RULE ja4proxy_campaign_detection
  MATCH:
    device_class  = "network_security_appliance"
    cef_event_id  = "blocked"
    cef_cs1Label  = "JA4Fingerprint"
    # Service Watch extracts the ASN from the source IP via its topology database.
    # If your Service Watch instance does not have ASN enrichment, use
    # cef_device_vendor = "JA4proxy" with a grouping key on source /24 subnet instead.

  CORRELATE BY:
    field:       source_asn
    # Groups ban events by the originating ASN. All bans from the same ASN
    # within the time window are treated as a single campaign.

  THRESHOLD:
    count:       >= N     # e.g. 5 — tune down in low-traffic environments
    time_window: T min    # e.g. 10 — shorter windows catch faster campaigns

  EMIT:
    event_class:  "ja4proxy_campaign"
    severity:     HIGH
    summary:      "JA4proxy: Campaign detected from ASN {source_asn} — {count} bans in {time_window} minutes"
    description:  "Coordinated attack activity detected. Source ASN: {source_asn}. Affected JA4 fingerprints: {unique_cef_cs1}. First seen: {first_event_time}. Last seen: {last_event_time}. Ban count: {count}."
    # {unique_cef_cs1} lists the distinct JA4 fingerprints observed in the window —
    # useful for identifying whether the campaign uses a single tool or multiple.

  AUTO_TICKET:
    enabled:      true
    priority:     P2
    template:     "ja4proxy_campaign_incident"
    # Requires the ITSM connector to be configured in Service Watch.
    # See §ITSM Connector Configuration below.

  SUPPRESS_CHILDREN:
    true
    # Suppresses the individual ban event notifications while the campaign
    # event is active. The campaign event remains open until no new bans
    # arrive from that ASN for T minutes.
```

**Tuning guidance:**

- Start with N=5 and T=10 minutes. If you see too many single-source events promoted
  to campaigns, increase N. If campaigns are missed, decrease T.
- In high-volume environments (> 10,000 connections/min), consider grouping by source
  /24 subnet instead of ASN to avoid one large ASN generating false campaign events
  from unrelated traffic.
- Review the campaign event's `unique_cef_cs1` field. If a campaign uses more than
  three distinct JA4 fingerprints, it may indicate a sophisticated actor rotating
  tools — escalate to the threat intelligence team.

---

## Health Degradation Rule

When JA4proxy transitions from healthy to degraded, the proxy may be dropping
connections silently or making incorrect allow/block decisions. This requires
immediate NOC attention and automatic ITSM ticket creation.

```
# Rule: JA4proxy Health Degradation
# Class: ja4proxy_health
#
# Purpose: Alert immediately when any JA4proxy node transitions from OK to
# DEGRADED health state. Trigger auto-ITSM ticket for SLA tracking.
#
# JA4proxy health states emitted in CEF events:
#   event.action = "health_ok"       — all checks passing
#   event.action = "health_degraded" — one or more subsystems degraded
#   event.action = "health_failed"   — node not responding to health checks

RULE ja4proxy_health_degradation
  MATCH:
    device_class  = "network_security_appliance"
    cef_event_id  IN ["health_degraded", "health_failed"]
    # Matches both degraded and failed states. The NOC handles both
    # via the same workflow with different priority.

  TRANSITION:
    from_state:  "health_ok"
    to_state:    "health_degraded"
    # Only alerts on state change, not on repeated health_degraded events
    # from the same node. Prevents alert storms during extended degradation.

  STATE_TIMEOUT:
    clear_after: 5 min
    # If no health_ok event arrives within 5 minutes of the last health_degraded,
    # escalate from P2 to P1.

  EMIT:
    event_class:  "ja4proxy_health"
    severity:     HIGH        # P2 on initial transition
    summary:      "JA4proxy health degraded: {source_hostname}"
    description:  "Node {source_hostname} ({source_ip}) has transitioned to DEGRADED state. Check Redis connectivity, GeoIP database load, and downstream backend health. Management API: https://{source_hostname}:8090/api/v1/health/deep"

  AUTO_TICKET:
    enabled:      true
    priority:     P2
    template:     "ja4proxy_health_incident"
    assignment:   "network-security-oncall"
    # Assigns to the on-call network security group in your ITSM system.
    # Adjust the assignment group to match your ITSM configuration.

  ESCALATE:
    condition:    "open_duration > 5 min"
    new_severity: CRITICAL
    new_priority: P1
    notify:       "network-security-manager"
    # After 5 minutes without recovery, escalate. The Management API's
    # /health/deep endpoint provides subsystem-level detail to aid diagnosis.
```

**ITSM ticket template fields for `ja4proxy_health_incident`:**

| Field | Value |
|---|---|
| Category | Network Security Infrastructure |
| Subcategory | TLS Proxy |
| Impact | 2 - Significant (proxy may be passing unscored traffic) |
| Urgency | 2 - High |
| Short description | JA4proxy health degraded: {source_hostname} |
| Description | Include the full event description from the rule above |
| Resolution notes | Attach output of `GET /api/v1/health/deep` at resolution time |

---

## Rate Rule

When a single source IP generates more than R events per minute, it has moved beyond
normal connection rates and warrants immediate severity escalation. This catches
connection-flooding attacks that may not individually score high enough for a ban.

```
# Rule: JA4proxy High Rate Source
# Class: ja4proxy_rate
#
# Purpose: Escalate severity when a single source IP exceeds R events/minute.
# Distinct from the campaign rule — this targets single-IP volume, not
# ASN-level coordination.
#
# Configurable parameters:
#   R = events per minute threshold (recommended: 60 for most environments;
#       100+ for high-traffic API gateways)

RULE ja4proxy_high_rate_source
  MATCH:
    device_class  = "network_security_appliance"
    cef_event_id  IN ["blocked", "flagged", "rate_limited", "tarpitted"]
    # Matches any enforcement action — a high-rate source may be rate-limited
    # before it accumulates enough score to be banned.

  CORRELATE BY:
    field:        source_ip
    # Groups all enforcement events by exact source IP.

  THRESHOLD:
    rate:         >= R events/minute    # e.g. 60
    time_window:  1 min
    # A sliding 1-minute window. Events older than 1 minute do not count.

  EMIT:
    event_class:  "ja4proxy_rate"
    severity:     HIGH
    summary:      "JA4proxy: High event rate from {source_ip} — {rate}/min (threshold: R/min)"
    description:  "Source IP {source_ip} is generating {rate} enforcement events per minute. Actions observed: {unique_cef_event_ids}. JA4 fingerprint: {cef_cs1}. Consider adding to watchlist or banning via Management API if behaviour continues."

  CORRELATE_WITH:
    rule:         "ja4proxy_campaign_detection"
    field:        source_asn
    note:         "If this source IP shares an ASN with an active campaign event, annotate both events."
    # Cross-references the campaign rule so NOC engineers can see whether a
    # high-rate single IP is part of a broader campaign.

  AUTO_TICKET:
    enabled:      false
    # High rate from a single IP is common during scans and load tests.
    # Auto-ticketing is intentionally disabled here; let the analyst decide.
    # Enable this if your SLA requires every high-rate source to be tracked.

  NOTIFY:
    channel:      "security-ops"
    message:      "High connection rate from {source_ip} ({rate}/min). Review in JA4proxy Management UI: https://ja4proxy.internal/connections?ip={source_ip}"
```

**Tuning guidance:**

- Set R to at least 3 times your legitimate peak rate for a single IP. Check the
  `ja4proxy_active_connections` Prometheus gauge to establish a baseline.
- If your environment receives legitimate high-rate API traffic from a known IP range,
  add those CIDRs to the JA4proxy static allowlist (`config/proxy.yml` under
  `static_ip_allowlist`) rather than raising the threshold globally.
- The rate rule fires before the ban threshold — the intent is to give the NOC early
  warning to investigate manually before automatic enforcement escalates.

---

## ITSM Connector Configuration

Service Watch can auto-create tickets in Remedy, ServiceNow, and Jira Service
Management when correlation rules fire with `AUTO_TICKET: enabled: true`.

Configure the connector under **Service Watch Admin > Integrations > ITSM**:

| Setting | Value |
|---|---|
| ITSM Platform | ServiceNow (or Remedy / Jira SM — depends on your estate) |
| Instance URL | Your ITSM instance URL |
| Authentication | Service account with incident create/update permission |
| Default assignment group | `network-security-oncall` (adjust to your group) |
| Ticket on close | Resolve or close the ITSM ticket when the Service Watch event clears |

The `AUTO_TICKET` blocks in the rules above reference named templates
(`ja4proxy_campaign_incident`, `ja4proxy_health_incident`). Define these templates in
**Service Watch Admin > Event Templates** with the field mappings described in each
rule section.

---

## Event Class Hierarchy

Register the following event classes in Service Watch before deploying the rules:

```
network_security_appliance         (device class — created by Ansible registration)
  └── ja4proxy_campaign            (event class — campaign detection rule)
  └── ja4proxy_health              (event class — health degradation rule)
  └── ja4proxy_rate                (event class — high rate rule)
```

Parent-child relationships allow NOC dashboards to show all JA4proxy events under a
single `network_security_appliance` node in the topology view.
