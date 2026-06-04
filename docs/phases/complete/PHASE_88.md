# Phase 88: Multi-Datacenter Survivability & Failover (Hardened)

> **Prerequisites: Phase 64 (DR baseline), Phase 86/87 (Observability), 
> High-precision NTP/Chrony (sub-10ms drift monitoring), 
> Phase 35 (Ed25519 Signing Infrastructure).**

---

## 1. Overview

Phase 88 adds multi-datacenter (multi-DC) survivability to JA4proxy. The core constraint remains: **No WAN call may appear on the per-connection hot path.** All security state propagates asynchronously via Redis Streams, except for the high-stakes Dial Protocol which uses a dedicated synchronous RPC with a strict timeout and fail-local fallback.

This hardened design introduces **Tombstones** to solve the "Zombie Whitelist" problem, **Peer-CN mapping** to prevent cross-DC impersonation, **Strict Inbound Filtering** to prevent arbitrary key overrides, and **Reliable Outbound Sync** to ensure state convergence after WAN partitions.

---

## 2. Implementation Roadmap (Small Chunks)

### Phase 88.1: Sentinel Transition & WAN Foundation (Small)
*Goal: Prepare the proxy for multi-node Redis and establish the WAN baseline.*
- [x] Implement NTP/Chrony drift monitoring; alert if drift > 50ms between DC pairs.
- [x] Update `internal/redis/client.go` to support `goredis.NewFailoverClient` (Sentinel mode).
- [x] Create `cmd/syncagent` skeleton with mTLS-protected WAN listener (port 7379).
- [x] Implement "Heartbeat" (RTT) metrics and `ja4proxy_sync_wan_connected` gauge.
- [x] **Validation:** Verify proxy fail-open during a simulated Sentinel master election.

### Phase 88.2: Async State Propagation & Tombstones (Hardened)
*Goal: Sync bans and whitelists across DCs without blocking the hot path.*
- [ ] **Reliable Delivery:** Update `runOutboundLoop` to only ACK stream messages AFTER all configured peers have acknowledged receipt. Implement a retry queue for unreachable peers.
- [ ] **Inbound Security:** Implement strict key whitelisting in `processInbound`. Reject any key not matching `ban:*`, `ja4:whitelist*`, or `ja4:blacklist*`.
- [ ] **Tombstone Logic:** Implement `ja4:whitelist:removals` (24h TTL) to prevent "union-on-heal" from re-adding deleted items.
- [ ] **Semantic Validation:** Inbound reader must reject events with `origin_ts` > 60s in the future or older than the stream buffer.
- [ ] **Validation:** `test-multidc-partition.sh` (Verify state converges correctly AFTER a 5-minute simulated WAN outage).

### Phase 88.3: The Secure Dial Consistency Protocol (Hardened)
*Goal: Secure the most dangerous configuration value.*
- [ ] **Dial RPC Bounds:** Update `handleDialRPC` to reject values < 0 or > 100.
- [ ] **8-Second Rule:** No dial change takes effect locally until all peers ACK OR 8s elapses (firing a CRITICAL alert).
- [ ] **Panic Mode:** Add `immediate: true` to the Management API to bypass the 8s wait during active saturation.
- [ ] **Peer-CN Mapping:** Validate that the `origin_dc` field in the payload matches the Peer's mTLS Client Certificate CN.
- [ ] **Validation:** `test-dial-bounds.sh` (Verify rejection of out-of-bounds dial values).

### Phase 88.4: Observability & Security Hardening (Hardened)
*Goal: Ensure visibility and isolate the new sync binary.*
- [ ] **Metrics Integration:** Instrument `syncagent` to actually populate the 11 multi-DC metrics (Lag, Events, Connection Status).
- [ ] **Integrity Signing:** Implement Ed25519 signing for all sync events using Phase 35 keys. Verify signatures in `processInbound`.
- [ ] **Fail-Closed TLS:** Remove `InsecureSkipVerify` fallbacks. Agent must fail to start/connect if mTLS certificates are missing or invalid.
- [ ] **Validation:** `scripts/check-audit-integrity.sh` (Verify audit log entries have valid cryptographic signatures).

### Phase 88.5: Disaster Recovery & GameDay (Small)
*Goal: Prove survivability under stress.*
- [x] Finalize `docs/runbooks/multidc.md` with the 7 failure scenarios.
- [ ] **Chaos Testing:** Execute a "GameDay" event: simulate a simultaneous WAN partition and a volumetric attack.
- [ ] Measure and document MTTR for cross-DC state convergence.
- [ ] **Acceptance:** Sign off on the Multi-DC Readiness Report.

---

## 3. Core Architecture & Security Controls

### 3.1 Inbound Security Envelope
The sync agent **MUST** enforce the following for every inbound event:
1. **Identity:** `event.OriginDC == mTLS.PeerCN`.
2. **Integrity:** `Ed25519.Verify(event.Signature, event.Payload)`.
3. **Authorization:** `key` must match allowed security patterns.
4. **Semantics:** `dial` value between 0-100; `timestamp` within drift threshold.

### 3.2 Reliable Outbound Sync
To prevent state divergence during WAN partitions:
- Messages are only `XACK`ed from the outbound stream if **all** configured peers receive them.
- If a peer is down, the agent must keep the message un-ACKed and retry until the link heals.

---

## 6. Acceptance Criteria (Hardened)

- [ ] All 11 Multi-DC metrics are correctly populated and visible in Grafana.
- [ ] Cross-DC events are cryptographically signed and verified.
- [ ] Inbound key validation prevents arbitrary Redis overrides.
- [ ] WAN partition test proves 100% state convergence after link restoration.
- [ ] Out-of-bounds dial values are rejected by the RPC layer.
