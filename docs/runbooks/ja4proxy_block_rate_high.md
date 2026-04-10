<!--
title: "ja4proxy block rate high Runbook"
audience: oncall, sre
last_reviewed: 2026-04-10
phase: 86
-->

# Runbook: ja4proxy_block_rate_high

## Severity
WARNING (>2% sustained for 15 min) → CRITICAL (>10% sustained for 5 min)

## What is happening
JA4proxy is blocking an unusually high percentage of inbound connections.
This could indicate an active attack campaign (expected behaviour) or
a false positive wave from a recent dial increase or fingerprint update.

## Impact
- **High (CRITICAL):** >10% of all connections blocked. If this is a
  false positive wave, legitimate users are being denied service.
- **Low (WARNING):** >2% block rate. Likely an attack campaign; expected
  behaviour if the traffic is genuinely malicious.

## Diagnosis
1. Check Management UI Campaign Tracker for active campaigns:
   ```bash
   curl -sf http://localhost:8090/api/v1/events | head -20
   ```
2. Check top blocked JA4 fingerprints:
   ```bash
   # From Prometheus metrics
   curl -s http://<node>:9090/metrics | grep 'ja4proxy_connections_total{action="block"}'
   ```
3. Check if dial was recently changed:
   ```bash
   curl -sf http://<node>:9090/health/deep | python3 -c "import sys,json; print('dial:', json.load(sys.stdin)['dial'])"
   ```
4. Check if block rate correlates with a specific JA4 pattern:
   - Look at the Management UI → Fingerprint Analysis page.
   - Identify if a single JA4 fingerprint accounts for >50% of blocks.

## Resolution
**If confirmed attack campaign:**
- No action required. JA4proxy is doing its job.
- Monitor for FP reports in Management UI.
- If specific fingerprint is a legitimate tool (e.g., internal scanner),
  add to whitelist:
  ```bash
  curl -sf -X POST http://localhost:8090/api/v1/lists/ja4/whitelist \
    -H "Content-Type: application/json" \
    -d '{"fingerprint": "<ja4_hash>"}'
  ```

**If false positive wave:**
1. Immediately lower dial to reduce block aggressiveness:
   ```bash
   curl -sf -X PUT http://localhost:8090/api/v1/dial \
     -H "Content-Type: application/json" \
     -d '{"value": <previous-dial-value>}'
   ```
2. Review recent signal score changes or config reloads.
3. File a ticket and document the FP for the analytics team.

## Escalation
Page SecOps lead if block rate >10% AND FP rate >0.1%.
Escalate to security architect if a legitimate business tool is blocked.
