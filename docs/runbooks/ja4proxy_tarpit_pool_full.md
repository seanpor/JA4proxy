<!--
title: "ja4proxy tarpit pool full Runbook"
audience: oncall, sre
last_reviewed: 2026-04-10
phase: 86
-->

# Runbook: ja4proxy_tarpit_pool_full

## Severity
WARNING (tarpit pool >80% capacity) → CRITICAL (tarpit pool at 100%)

## What is happening
The JA4proxy tarpit connection pool is at or near capacity. Tarpits
hold suspicious connections open to waste attacker resources. When the
pool is full, new connections that would be tarpitted are instead
allowed or blocked (depending on configuration).

## Impact
- **High (CRITICAL):** Pool exhausted. New suspicious connections bypass
  the tarpit and are either allowed (attacker wins) or blocked (possible FP).
  Security posture is degraded.
- **Medium (WARNING):** Pool approaching capacity. Tarpit effectiveness
  is reducing as connections are released early.

## Diagnosis
1. Check current tarpit pool utilisation:
   ```bash
   curl -s http://<node>:9090/metrics | grep ja4proxy_tarpit
   ```
2. Check pool size configuration:
   ```bash
   grep -A5 'tarpit' config/proxy.yml
   ```
3. Check tarpit connection lifespan (are connections being released?):
   ```bash
   curl -s http://<node>:9090/metrics | grep ja4proxy_tarpit_overflow
   ```
4. Check if there's an active tarpit attack (many connections from same ASN):
   ```bash
   # From Management UI or direct Redis query
   redis-cli -h <redis-host> KEYS 'ja4proxy:asn:*' | head -5
   ```

## Resolution
**If under active tarpit attack:**
1. Increase tarpit pool size (requires config reload):
   ```yaml
   # In config/proxy.yml
   tarpit:
     max_connections: <current * 2>
   ```
   Then reload: `kill -HUP $(pgrep -f ja4proxy)`
2. Consider reducing tarpit duration to free connections faster:
   ```yaml
   tarpit:
     timeout_seconds: 30  # from 60
   ```
3. If attack is from a specific ASN, consider hard-blocking it:
   ```bash
   # Block the ASN at the network layer (iptables/nftables)
   # or add to JA4proxy's ISP block list.
   ```

**If pool exhaustion from normal traffic:**
1. Review tarpit configuration — the pool may be undersized for your
   traffic volume.
2. Consider moving tarpit to a dedicated backend (separate server)
   to avoid resource contention with the proxy hot path.

## Escalation
Page Platform Engineering if tarpit pool needs infrastructure scaling.
Page SecOps lead if tarpit exhaustion is caused by a targeted attack.
