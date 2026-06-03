<!--
title: "external api failures Runbook"
audience: oncall, sre
last_reviewed: 2026-04-10
phase: 86
-->

# Runbook: External API Failures

## Overview

JA4proxy integrates with three external services: AbuseIPDB (Phase 10), RDAP (Phase 11),
and DNS resolvers (Phase 7). All three are optional enrichment sources. When any of them
fails, the proxy continues to operate normally — the contribution of that signal to the
risk score drops to zero and the connection is handled by the remaining signals. This is
the explicit fail-open design mandated by the core asymmetry principle.

---

## AbuseIPDB (Phase 10)

### Daily quota exhaustion

**Alert:** `ja4proxy_abuseipdb_quota_remaining < 100`

AbuseIPDB free-tier accounts have a daily lookup quota. When the quota is exhausted,
all new IP lookups return HTTP 429. The proxy falls back to cached scores for known IPs;
unknown IPs receive a score of 0 (fail open — they are not penalised for the cache miss).

**Check current quota:**
```bash
redis-cli GET abuseipdb:quota:remaining
# Returns integer: remaining lookups today
# Key has TTL aligned to UTC midnight reset
```

**Check recent error rate:**
```bash
# Prometheus metric
ja4proxy_abuseipdb_lookups_total{result="error"}

# Redis key for last error timestamp
redis-cli GET abuseipdb:last_error
```

**Immediate mitigation — disable AbuseIPDB temporarily:**

1. Edit `config/proxy.yml`:
   ```yaml
   abuseipdb:
     enabled: false
   ```
2. Send SIGHUP to the proxy process:
   ```bash
   docker compose kill -s SIGHUP proxy
   ```
3. Verify: `ja4proxy_abuseipdb_lookups_total` counter stops incrementing.

The proxy will log:
```
INFO | abuseipdb | event=disabled | reason=hot_reload
```

**Re-enable procedure:**

Wait until UTC midnight (quota resets). Then:
1. Edit `config/proxy.yml`: set `abuseipdb.enabled: true`.
2. Send SIGHUP: `docker compose kill -s SIGHUP proxy`.
3. Monitor `ja4proxy_abuseipdb_quota_remaining` for the first few minutes.

> Note: `worker_count` and `queue_size` changes under `abuseipdb:` require a full
> proxy restart — hot reload only applies to `enabled` and `api_key`. A WARN is logged
> if these are changed via SIGHUP without restart.

### API key invalid or rotated

**Symptom:** `ja4proxy_abuseipdb_lookups_total{result="error"}` spikes; proxy logs show
HTTP 401.

**Fix:**
1. Obtain the new API key from the AbuseIPDB dashboard.
2. Update `config/proxy.yml` under `abuseipdb.api_key`.
3. Send SIGHUP.

### AbuseIPDB service unavailable

**Symptom:** HTTP 5xx or connection timeout errors in proxy logs.

The proxy already handles this transparently. The bloom filter dedup mechanism ensures
failed lookups are not retried for the current bloom window (24h TTL), preventing
quota waste on repeated failures for the same IP.

No operator action is required unless the outage persists > 24 hours (bloom filter will
expire and lookups resume automatically).

---

## RDAP (Phase 11)

### Token bucket depletion per RIR

Each Regional Internet Registry (ARIN, RIPE, APNIC, LACNIC, AFRINIC) has its own token
bucket to rate-limit RDAP lookups. When a bucket is depleted, RDAP lookups for IPs in
that RIR's range are skipped until tokens replenish. The score contribution from RDAP
drops to zero for affected lookups.

**Check token bucket state:**
```bash
redis-cli HGETALL rdap:tokens:arin
redis-cli HGETALL rdap:tokens:ripe
redis-cli HGETALL rdap:tokens:apnic
redis-cli HGETALL rdap:tokens:lacnic
redis-cli HGETALL rdap:tokens:afrinic
# Fields: tokens (current count), last_refill (Unix timestamp)
```

**Manual token bucket reset** (use if a RIR was unreachable and bucket drained):
```bash
redis-cli DEL rdap:tokens:ripe
# The bucket is recreated with full tokens on the next RDAP lookup attempt.
```

**Check RDAP error rate:**
```bash
# Prometheus
ja4proxy_rdap_lookups_total{result="error"}
ja4proxy_rdap_lookups_total{result="timeout"}
```

### Block expansion emergency disable

RDAP block expansion is off by default. If it has been enabled and is producing
unexpected CIDR bans, disable it immediately:

1. Edit `config/proxy.yml`:
   ```yaml
   rdap_enrichment:
     block_expansion:
       enabled: false
   ```
2. Send SIGHUP: `docker compose kill -s SIGHUP proxy`.
3. Review existing CIDR bans: `redis-cli SCAN 0 MATCH 'ban_cidr:*' COUNT 100`.
4. Manually lift false-positive CIDR bans:
   ```bash
   redis-cli DEL ban_cidr:203.0.113.0/24
   ```

**Check hourly expansion cap:**
```bash
redis-cli GET rdap:expansion:hourly_count
# Should be well below rdap_enrichment.block_expansion.max_per_hour
```

### RDAP service unreachable

RDAP endpoints are contacted via HTTPS. If an RIR's RDAP service is unreachable:
- The lookup times out (configurable `rdap_enrichment.timeout_seconds`).
- The score contribution is zero.
- The Prometheus counter increments.
- No retry storm occurs — the bloom filter prevents re-queuing the same IP.

No operator action required for transient outages. For extended RIR outages (> 1 hour):
```bash
# Disable RDAP entirely
# config/proxy.yml: rdap_enrichment.enabled: false
docker compose kill -s SIGHUP proxy
```

---

## DNS Enrichment (Phase 7)

### DNS resolver unreachable

**Alert indicator:** `ja4proxy_dns_enrichment_errors_total` counter rising rapidly.

The DNS enrichment worker performs async PTR lookups (FCrDNS). If the configured resolver
is unreachable, all lookups fail with NXDOMAIN or timeout.

**Check error counter:**
```bash
# Prometheus
ja4proxy_dns_enrichment_errors_total{error_type="timeout"}
ja4proxy_dns_enrichment_errors_total{error_type="nxdomain"}
ja4proxy_dns_enrichment_errors_total{error_type="servfail"}
```

**Check queue depth:**
```bash
redis-cli LLEN dns:enrichment:queue
# Growing queue means workers are not consuming.
# Steady queue with high error counter means workers are running but resolvers failing.
```

**Check which resolver is configured:**
```bash
grep -A5 'dns_enrichment' config/proxy.yml
# Look for nameservers: list
```

**Switch to a backup resolver:**
1. Edit `config/proxy.yml`:
   ```yaml
   dns_enrichment:
     nameservers:
       - "8.8.8.8"
       - "1.1.1.1"
   ```
2. Send SIGHUP: `docker compose kill -s SIGHUP proxy`.

### Worker stall (queue growing, no consumption)

The DNS enrichment module uses an async worker loop with automatic restart on
unhandled exception. The restart loop is documented in `src/security/dns_enrichment.py`.

If the queue is growing but errors are not incrementing (workers are not consuming
at all):

```bash
# Restart the proxy to reinitialise workers
docker compose restart proxy
```

The queue is a Redis LIST — pending jobs are not lost during restart.

### Fallback behaviour during DNS outage

Connections proceed without DNS enrichment. The residential classification signal
(−10 score for residential PTR) is absent. Connections that would have received a
residential bonus may score slightly higher, but this is a conservative (safe) direction.

No operator action required for the proxy to continue serving traffic. DNS enrichment
will resume automatically when the resolver becomes reachable.

---

## General Checklist for Any External API Failure

1. Confirm the proxy is still forwarding traffic: check `ja4proxy_connections_total`.
2. Identify the failing service from Prometheus: look for `{result="error"}` spikes.
3. Confirm fail-open is active: check that `ja4proxy_connections_total{action="allow"}`
   rate is unchanged or higher (not lower — lower could indicate the service failure
   is causing unexpected blocks).
4. Apply the service-specific mitigation above.
5. Note the time window of degraded enrichment for the incident report.
6. Re-enable the service once it recovers and verify error rate drops to baseline.

---

## Related

- `docs/runbooks/redis_operations.md` — Redis health (external API caches live in Redis)
- `docs/phases/complete/PHASE_07.md` — DNS enrichment architecture
- `docs/phases/complete/PHASE_10.md` — AbuseIPDB integration details
- `docs/phases/complete/PHASE_11.md` — RDAP enrichment and block expansion
