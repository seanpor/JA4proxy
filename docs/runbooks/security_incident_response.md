<!--
title: Security_Incident_Response
audience: Operators, Security Teams
last_reviewed: 2026-03-27
phase: 21
-->

# Security Incident Response Runbook

## Overview

This runbook covers incident response for JA4proxy internal errors and exception rate
anomalies. These are operational incidents (proxy misbehaving), not security incidents
(attacker activity). For attacker response, see `security_policy.md`.

---

## Detecting Anomalies

### Monitor These Metrics

| Metric | Normal | Investigate |
|--------|--------|-------------|
| `ja4proxy_connection_errors_total` | 0 (must be zero) | Any non-zero value |
| `ja4proxy_handler_panics_total` | < 1/s | > 5/s sustained |
| `ja4proxy_signal_error_total` | 0 in normal operation | Any sustained rate |
| `ja4proxy_signal_skipped_total` | Low; spikes if Redis/DNS degrades | > 10/s sustained |
| `ja4proxy_dns_ptr_errors_total` | < 0.5/s | > 5/s sustained |
| `ja4proxy_rdap_enrichment_queue_depth` | 0–1/min | > 10/min sustained |

### Alerting Rules

- **`PipelineInternalError`** (severity: critical, fires immediately) — `ja4proxy_connection_errors_total` is non-zero
- **`ExceptionRateSpike`** (severity: warning, fires after 5m) — exception rate 2× above 1-hour baseline in any module

---

## Pipeline Internal Error (Critical) {#pipeline-internal-error}

This alert fires when an unexpected exception propagates to the top-level pipeline
handler. This **should never happen**. A non-zero rate indicates a bug in signal
module logic (not an external failure, which is caught and handled lower down).

### Immediate Actions

1. **Check logs** — look for the phase and collector where the error occurred:
   ```bash
   grep '"event":"unexpected_error"' /var/log/ja4proxy/proxy.log | tail -20 | jq .
   ```
   Or in JSON mode:
   ```bash
   docker logs ja4proxy 2>&1 | grep unexpected_error | tail -20 | jq .
   ```

2. **Identify the phase and collector** — the `phase` and `collector` log fields tell
   you exactly where the error occurred.

3. **If blocking decisions are being affected**: set dial to 0 (monitor mode) to stop
   blocking while you investigate. The proxy continues operating fail-open.
   ```bash
   # Via Redis
    redis-cli SET config:dial 0
   ```

4. **Collect the stack trace** from the log `stack_trace` field and file a bug.

5. **Do not restart the proxy** unless the error rate is so high it is impacting
   performance — the proxy operates fail-open and continues serving traffic.

### Log Entry Format

```json
{
  "type": "system",
  "level": "ERROR",
  "subsystem": "pipeline",
  "event": "unexpected_error",
  "client_ip": "1.2.3.4",
  "phase": "signal_collection",
  "collector": "asn_classifier",
  "exc_type": "AttributeError",
  "exc_message": "'NoneType' object has no attribute 'category'",
  "stack_trace": "...",
  "timestamp": "2026-03-10T14:23:00Z"
}
```

---

## Exception Rate Spike {#exception-rate-spike}

This alert fires when the exception rate in any module is 2× the 1-hour baseline for
5 minutes. This is a warning — the proxy is still operating correctly (fail-open), but
there is a new failure pattern that warrants investigation.

### Investigation Steps

1. **Identify the spiking module** using the Grafana panel:
   ```
   Grafana → Dashboard 03 (System) → Row 3b (Exception Health) → Exception Rate by Module
   ```

2. **Identify the exception type**:
   ```bash
   grep '"exc_type"' /var/log/ja4proxy/proxy.log | \
       jq -r '.exc_type' | sort | uniq -c | sort -rn | head -10
   ```

3. **Common causes by module**:

   | Module | Common exception type | Probable cause |
   |--------|----------------------|----------------|
   | `dns_enrichment` | `asyncio.TimeoutError` | Upstream DNS server slow or unreachable |
   | `dns_enrichment` | `socket.herror` | DNS NXDOMAIN or SERVFAIL responses |
   | `asn_classifier` | `AttributeError` | MaxMind GeoLite2-ASN file corrupted or deleted |
   | `rdap_enrichment` | `aiohttp.ClientError` | RDAP registry unreachable |
   | `rdap_enrichment` | `asyncio.TimeoutError` | RDAP registry slow |
   | `blocklists` | `aiohttp.ClientError` | Spamhaus/feed download failure |
   | `abuseipdb` | `aiohttp.ClientError` | AbuseIPDB unreachable or rate-limited |

4. **DNS failures** — check upstream DNS servers:
   ```bash
   dig @8.8.8.8 +short reverse.example.com
   ```

5. **MaxMind file issues** — verify file integrity:
   ```bash
   ls -la config/GeoLite2-ASN.mmdb
   python3 -c "import maxminddb; r=maxminddb.open_database('config/GeoLite2-ASN.mmdb'); print('OK')"
   ```

6. **Redis connectivity** — if `signal_skipped_total` is also spiking:
   ```bash
   redis-cli ping
   ```

---

## Signal Skips vs Signal Errors

These two metrics have different meanings:

| Metric | Meaning | Normal? |
|--------|---------|---------|
| `ja4proxy_signal_skipped_total` | Expected infrastructure failure (Redis/DNS/timeout) — fail-open by design | Yes, during degraded infra |
| `ja4proxy_signal_error_total` | Unexpected internal logic error | No — investigate |

Signal skips are expected during Redis downtime or DNS outages. The proxy continues
operating and skips that signal for affected connections (fail-open). Signal errors
indicate a code defect — file a bug.

---

## Fail-Open Guarantees

When any of the following fail, the proxy **always allows the connection** and continues:

- Redis unavailable (read or write)
- DNS resolution timeout or NXDOMAIN
- MaxMind GeoLite2 database unreadable
- AbuseIPDB unreachable or returns error
- RDAP registry unreachable
- Spamhaus/blocklist feed download failure

The only exceptions are **hard block bypasses** (JA4 blacklist, country blacklist,
Spamhaus match) which use in-memory state loaded at startup. If that state is empty
(e.g. fresh startup before first download), those connections are NOT blocked.

**The proxy never blocks due to its own internal errors.**

---

## Escalation

| Condition | Action |
|-----------|--------|
| `PipelineInternalError` firing continuously | Page on-call; consider dial=0 |
| Exception rate spike + unusual block rate | Check for attacker activity causing load on external services |
| MaxMind database missing after deploy | Roll back deploy; check build artifact |
| Redis down > 5 min | See `redis_operations.md` |
