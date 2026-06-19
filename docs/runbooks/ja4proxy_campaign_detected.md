<!--
title: "ja4proxy campaign detected Runbook"
audience: oncall, sre
last_reviewed: 2026-04-10
phase: 86
-->

# Runbook: ja4proxy_campaign_detected

## Severity
INFO (campaign detected, block rate normal) → WARNING (block rate rising)

## What is happening
The analytics node has detected a coordinated attack campaign — multiple
IPs/JA4 fingerprints exhibiting similar attack patterns within a short
time window. This is detected via cross-instance statistical analysis
of Redis Streams.

## Impact
- **Low (INFO):** Campaign detected, block rate within normal bounds.
  JA4proxy is handling it automatically.
- **Medium (WARNING):** Campaign is driving block rate up. Monitor for
  potential FP impact on legitimate traffic.

## Diagnosis
1. Check Management UI Campaign Tracker:
   - Navigate to Campaigns page.
   - Review active campaigns, their fingerprint clusters, and source IPs.
2. Check analytics node for campaign details:
   ```bash
   curl -sf http://<analytics-node>:<port>/api/v1/campaigns | python3 -m json.tool
   ```
3. Check if campaign IPs are from a known ASN/datacenter. ASN is classified
   in-process (MaxMind GeoLite2-ASN) — there is no ASN Redis key; the ASN is
   recorded on each connection event and in the RDAP cache. Inspect a sample
   campaign IP:
   ```bash
   redis-cli -h <redis-host> GET 'rdap:ip:<campaign-ip>'   # JSON includes "asn"
   ```

## Resolution
**Standard campaign (no FP impact):**
- No action required. JA4proxy automatically blocks campaign traffic.
- Document the campaign for post-incident review.

**High-volume campaign:**
1. Consider a temporary dial increase to reduce collateral damage:
   ```bash
   curl -sf -X PUT http://localhost:8090/api/v1/dial \
     -H "Content-Type: application/json" \
     -d '{"value": <current-dial + 10>}'
   ```
2. Monitor block rate and FP rate for 15 minutes.
3. If block rate stabilises, return dial to previous value.

## Escalation
No page required for INFO-level campaigns.
Page SecOps if campaign involves known APT infrastructure or state-level
actors (check ASN and RDAP enrichment data).
