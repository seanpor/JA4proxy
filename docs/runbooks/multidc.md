<!--
title: "mulTIdc Runbook"
audience: oncall, sre
last_reviewed: 2026-04-10
phase: 86
-->

# Multi-DC Survivability & Failover Runbook

This runbook covers cross-datacenter state replication, consistency protocols, and disaster recovery procedures for JA4proxy multi-DC deployments.

---

## 1. Architecture Overview

JA4proxy uses an **asynchronous state replication** model to ensure that WAN latency never impacts the connection hot path.

- **Hot Path:** Local Redis only. No cross-DC calls during TLS analysis.
- **Async Sync:** IP bans and whitelists propagate via Redis Streams and the `syncagent` binary.
- **Consistency:** The "Dial" (blocking threshold) uses a **Synchronous Consistency Protocol** with an 8-second timeout.
- **Integrity:** All cross-DC traffic is protected by mTLS with Peer-CN identity mapping and Ed25519 event signing.

---

## 2. Critical Alerts

### SyncAgentWANDisconnected
**Severity:** Critical
**What is firing:** The local sync agent cannot reach a peer DC.
**Impact:** Security state (bans/whitelists) is diverging between DCs.
**Resolution:**
1. Check WAN connectivity between DC regions.
2. Verify `syncagent` service is running in both DCs: `systemctl status ja4proxy-syncagent`.
3. Check mTLS certificate expiry: `openssl x509 -in /etc/ja4proxy/sync.crt -text -noout`.

### DialDivergence
**Severity:** Critical
**What is firing:** The `config:dial` value in this DC differs from the global average by > 5 points.
**Impact:** Inconsistent security posture. One DC may be under-blocking while another is over-blocking.
**Resolution:**
1. Verify the last dial change in the audit log.
2. If a DC is stuck, manually force the dial value:
   ```bash
   curl -X POST -d '{"dial": 50, "immediate": true}' https://admin-api/v1/config/dial
   ```
3. Check `syncagent` logs for "Dial propagation timeout" errors.

### SyncClockDriftHigh
**Severity:** Warning
**What is firing:** NTP drift between DCs exceeds 50ms.
**Impact:** "Last-writer-wins" conflict resolution may become unreliable.
**Resolution:**
1. Check `chronyc tracking` or `ntpstat` on the host.
2. Force NTP sync: `sudo chronyc -a makestep`.
3. If drift persists, investigate hardware clock issues or network jitter.

---

## 3. Failure Scenarios

### 3.1 WAN Partition (Split-Brain)
**Scenario:** DCs are healthy but cannot communicate.
**Behavior:**
- Each DC operates independently using its local state.
- IP bans issued in DC-A will NOT appear in DC-B until the link heals.
- **Partition Heal:** When the link restores, `syncagent` will replay buffered stream events.
- **Tombstones:** Whitelist removals are synced as "Removals" to ensure they persist even if the base set is unioned during heal.

### 3.2 Datacenter Dark (Total Loss)
**Scenario:** DC-A is completely offline.
**Behavior:**
- GSLB (Global Server Load Balancing) should steer all traffic to DC-B.
- DC-B continues to operate normally. No manual intervention required for state.

### 3.3 Redis Sentinel Failover
**Scenario:** The local Redis master in DC-A fails.
**Behavior:**
- Redis Sentinel elects a new master within ~10s.
- JA4proxy Go client (Failover mode) automatically reconnects to the new master.
- **Hot Path Impact:** Proxy fails open (monitor mode) during the ~10s election window.

---

## 4. Operational Procedures

### 4.1 Emergency "Panic" Dial Change
If the WAN is saturated and you need to immediately change the blocking level globally without waiting for peer ACKs:
```bash
# This bypasses the 8s consistency wait
curl -X POST -H "Content-Type: application/json" \
     -d '{"dial": 80, "immediate": true}' \
     https://ja4-admin-api/v1/config/dial
```

### 4.2 Manually Clearing Tombstones
If a whitelist entry is "stuck" due to a stale tombstone:
1. Identify the key: `ja4:whitelist:removals`.
2. Clear the specific member: `redis-cli SREM ja4:whitelist:removals <fingerprint>`.

---

## 5. Chaos Testing (GameDay)

To verify multi-DC resilience, execute the following quarterly:

1. **Simulate WAN Loss:** Block port 7379/7380 between DCs for 10 minutes. Verify `SyncAgentWANDisconnected` fires.
2. **State Convergence:** Ban an IP in DC-A during partition. Restore link. Verify IP is banned in DC-B within 60s of heal.
3. **Dial Timeout:** Trigger a dial change while WAN is blocked. Verify the 8s timeout fires and the change is applied locally.
4. **MTTR Measurement:** Measure time from "Link Restored" to "State Identical" across all DCs.
