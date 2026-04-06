# Phase 88: Multi-Datacenter Survivability & Failover

> **Prerequisites: Phase 64 (DR runbook baseline), Phase 86 (observability),
> Phase 87 (infrastructure observability) must be complete.**

---

## 1. Overview

Phase 88 adds multi-datacenter survivability to JA4proxy. The proxy is stateless at
the connection layer; all security state lives in Redis. This makes multi-DC operation
feasible but requires careful design: each DC must operate independently during WAN
failures (consistent with the fail-open design), while critical security state (bans,
dial setting, whitelist/blacklist) propagates between DCs within defined bounds.

This phase does NOT:
- Require Redis Enterprise or Redis Cluster geo-distribution. It uses open-source
  Redis Sentinel per DC plus a new sync agent.
- Change the proxy hot path. No WAN round-trips occur during connection handling.
- Replace the Phase 64 single-DC DR runbook. It extends it with multi-DC scenarios.

The central non-negotiable constraint is that no WAN call may appear on the per-
connection hot path. Every design decision in this phase flows from that constraint.

---

## 2. Topology Decision Matrix

### 2.1 Active-Active vs Active-Passive

| Dimension | Active-Active | Active-Passive |
|---|---|---|
| Complexity | High — cross-DC sync, conflict resolution, dial divergence protocol | Low — one authoritative DC; standby receives async sync |
| RTO | Near-zero (GeoDNS TTL 30–60s) | 60–180s (DNS TTL + health check convergence) |
| RPO | ~30s for ban state, ~10s for dial. On partition heal, worst-case 30s window where a ban was not enforced | Same RPO characteristics |
| Operational cost | High — two live DCs under attack simultaneously | Low — clear authority; planned failover |
| When to use | Geo-latency matters, or capacity requires load distribution | Single DC handles peak load; second DC exists purely for resilience |
| State on WAN failure | Both DCs continue independently; sync resumes on reconnect | Standby becomes authoritative; on heal, primary reconciles from standby state |

### 2.2 Recommended Progression

Start with active-passive. Deploy DC-A as primary and DC-B as a warm standby receiving
async sync. Operate for 30 days to validate the sync agent, measure real-world RPO, and
train operators on the dial propagation protocol. Promote to active-active only after
the sync agent has survived at least one simulated WAN partition from the Phase 64
GameDay chaos event.

The operational cost difference between the two topologies is real. The RTO difference
(30s vs near-zero) is only worth paying when the SLA requires it.

---

## 3. Redis Cross-DC Architecture

### 3.1 Per-DC Redis Sentinel Topology

Each datacenter runs a three-node Redis Sentinel cluster. Three Sentinel nodes is the
minimum for automatic leader election without split-brain (quorum = 2 of 3). The Sentinel
master name across all DCs is `ja4proxy-primary`.

```
DC-A
┌─────────────────────────────────────────────────────────┐
│                                                         │
│  redis-a-primary:6379  ◄──── Sentinel-a-1:26379        │
│         │              ◄──── Sentinel-a-2:26379        │
│         │              ◄──── Sentinel-a-3:26379        │
│         │ replication (async, local LAN)                │
│  redis-a-replica-1:6379                                 │
│  redis-a-replica-2:6379                                 │
│                                                         │
│  JA4proxy × N ──────────────────► redis-a-primary      │
│  (connect via Sentinel discovery)                       │
└─────────────────────────────────────────────────────────┘

DC-B  [mirror of DC-A structure]

Cross-DC sync channel (WAN — mTLS, port 7379):

DC-A                                      DC-B
┌─────────────┐                          ┌─────────────┐
│ sync-agent-a│◄────── mTLS stream ─────►│ sync-agent-b│
│             │                          │             │
│ reads from  │                          │ reads from  │
│ ja4proxy:   │                          │ ja4proxy:   │
│ events      │                          │ events      │
│ (local)     │                          │ (local)     │
└─────────────┘                          └─────────────┘
     │                                         │
     ▼                                         ▼
redis-a-primary                          redis-b-primary
(writes synced state                     (writes synced state
 from DC-B)                               from DC-A)
```

Each proxy instance connects to its local Sentinel using the Sentinel mode of go-redis
(`goredis.NewFailoverClient`), replacing the current `goredis.NewClient` in
`internal/redis/client.go`. On Sentinel failover, go-redis transparently reconnects;
the proxy continues to fail-open during the reconnect window.

### 3.2 Sync Agent Design — Two-Stream Protocol

The sync agent is a new Go binary at `cmd/syncagent/main.go`. It is not a proxy; it
does not sit on the hot path. It runs as one instance per DC.

**Two-stream protocol:**

1. **Outbound stream:** Reads `ja4proxy:dc:{dc_id}:sync:out` (a Redis Stream) that is
   populated by a stream writer watching for syncable key changes.
2. **Inbound:** Writes incoming events from the remote DC into local Redis.

Example outbound XADD:

```
XADD ja4proxy:dc:dc-a:sync:out MAXLEN ~ 50000 * \
  key_type ban \
  key ban:1.2.3.4 \
  op set \
  value "crawler:rate-limit" \
  ttl_remaining_ms 3540000 \
  origin_dc dc-a \
  origin_ts 1744041600123
```

The remote agent reads via XREADGROUP with consumer group `sync-dc-b`. XACK happens
only after the write to remote Redis succeeds. On WAN failure, the reader blocks at
the last acknowledged ID. On reconnect it replays from that ID. No events are lost as
long as the stream has not been trimmed past the last acknowledged ID.

**Stream trimming:** `MAXLEN ~ 50000` means approximately 50,000 events. At peak load
(8,100 conn/s, 5% syncable writes = 405 events/s), this represents approximately 123
seconds of buffering. If WAN is down longer than 123 seconds, the oldest events are
trimmed. This is acceptable because ban TTLs are measured in hours and the system
fails open.

**Retry policy:** WAN reconnect uses exponential backoff: 1s, 2s, 4s, 8s, 16s, 30s
cap. The sync agent never panics on WAN failure — it logs WARN and enters
buffer-accumulation mode.

**Backpressure:** If a local Redis write fails, the agent does NOT XACK. It retries
with a 500ms pause up to 5 times, then drops the event and increments
`ja4proxy_sync_apply_drops_total`.

**mTLS:** The WAN channel uses mTLS with a dedicated CA separate from the proxy-to-
backend CA. Each DC sync agent presents a client certificate with CN
`syncagent-{dc_id}`.

### 3.3 Sync Agent Configuration

```yaml
# config/syncagent.yml
sync_agent:
  dc_id: "dc-a"
  listen_addr: "0.0.0.0:7379"
  remote_addr: "dc-b-sync.example.com:7379"
  tls:
    cert_file: "/etc/syncagent/tls/syncagent.crt"
    key_file:  "/etc/syncagent/tls/syncagent.key"
    ca_file:   "/etc/syncagent/tls/sync-ca.crt"
  outbound_stream: "ja4proxy:dc:dc-a:sync:out"
  inbound_consumer_group: "sync-dc-a"
  buffer_maxlen: 50000
  wan_reconnect_backoff_max_seconds: 30
  local_redis_sentinel:
    master_name: "ja4proxy-primary"
    sentinels:
      - "redis-a-sentinel-1:26379"
      - "redis-a-sentinel-2:26379"
      - "redis-a-sentinel-3:26379"
```

---

## 4. State Classification

Every Redis key type is classified by sync strategy. The strategies are:

- **SYNC-IMMEDIATE** — enqueued within one connection cycle; target propagation ≤30s.
- **SYNC-ASYNC** — best-effort; eventual consistency acceptable.
- **LOCAL-ONLY** — never crosses WAN.
- **DIAL-PROTOCOL** — special handling; see Section 5.

| Key Pattern | Type | Sync Strategy | Rationale | Conflict Resolution |
|---|---|---|---|---|
| `ban:{ip}` | String | SYNC-IMMEDIATE | Active bans are primary cross-DC security state | Max-TTL wins on partition heal. Compare remaining TTL; keep entry with longer TTL: `SET ban:{ip} {reason} PX {max(ttl_a, ttl_b)}` |
| `config:dial` | String | DIAL-PROTOCOL | Most dangerous divergence — see §5 | Last-writer-wins by `origin_ts`. Never use max. |
| `ja4:whitelist` | SET | SYNC-IMMEDIATE | Missing whitelist entry causes false positives | Set union on heal. Removal requires explicit operator action. |
| `ja4:blacklist` | SET | SYNC-IMMEDIATE | Blacklist misses are low-cost; should still propagate quickly | Set union on heal. |
| `ip:blacklist` | SET | SYNC-IMMEDIATE | XDP kernel-drop map source. REMOVE must propagate immediately | Explicit delta sync. REMOVE operations applied immediately, not unioned. |
| `static:allowlist` | SET | SYNC-IMMEDIATE | Missed allowlist entry blocks a legitimate user (high cost) | Set union on heal. REMOVE is explicit. |
| `session:ip:{ip}:ja4:{ja4}` | Hash | LOCAL-ONLY | Cross-DC session state would require WAN on hot path — violates core constraint | N/A |
| `lifespan:{ip}` | Sorted Set | LOCAL-ONLY | Statistical input; per-DC samples are independently correct | N/A |
| `concurrent:{ip}` | Integer | LOCAL-ONLY | Atomic cross-DC increments on hot path would add WAN latency | N/A |
| `visitor:{ip}` | Hash | SYNC-ASYNC | Return-visitor tracking benefits from cross-DC data; 7-day TTL tolerates latency | Last-write-wins on individual hash fields by `last_seen` timestamp |
| `attribution:profile:{fp}` | String (JSON) | SYNC-ASYNC | Enrichment data; 90-day TTL | Last-writer-wins by `origin_ts` |
| `attribution:ips:{fp}` | SET | SYNC-ASYNC | Monotonically growing | Set union on heal |
| `behavioral:probing:{fp}` | SET | SYNC-ASYNC | Coordinated probing detection benefits from cross-DC data; 1h TTL | Set union on heal |
| `behavioral:burst:{sni}` | Sorted Set | LOCAL-ONLY | 10-second TTL; sync latency exceeds TTL window | N/A |
| `behavioral:known_ja4` | SET | SYNC-IMMEDIATE | New-fingerprint alerting requires consistent registry | Set union. No REMOVE path. |
| `ban_cidr:{cidr}` | String | SYNC-IMMEDIATE | CIDR bans protect entire netblocks | Max-TTL wins |
| `tor:exit:ips` | SET | LOCAL-ONLY | Each DC independently refreshes from the same upstream source | N/A |
| `analytics:campaign:{subnet}` | String (JSON) | SYNC-ASYNC | Campaign detected in DC-A is likely hitting DC-B too | Last-writer-wins by `origin_ts` |
| All enrichment caches (`rdap:*`, `abuseipdb:*`, `greynoise:*`, etc.) | String (JSON) | LOCAL-ONLY | External API quota is per-DC; sharing adds WAN coupling | N/A |
| All bloom filters | Bloom | LOCAL-ONLY | Merging probabilistic structures across WAN adds complexity for no security gain | N/A |
| `management:audit_log` / `management:policy_audit` | List | SYNC-IMMEDIATE | Compliance requires a consistent audit trail across DCs | Append-only. Duplicate suppression by entry UUID. |
| `ja4proxy:events` (stream) | Stream | LOCAL-ONLY | Consumed by local analytics node | N/A |
| `backup:*` | Various | LOCAL-ONLY | Per-DC operational state | N/A |

---

## 5. The Dial Consistency Protocol

### 5.1 Why Dial Divergence Is the Most Dangerous Inconsistency

The dial is not just a config value — it is the threshold function that determines
whether a connection is blocked. At dial=100 the block threshold is approximately 50;
at dial=0 every connection passes regardless of score. A 10-point dial difference
between DCs means the DC with the lower dial has an effective block threshold 35 points
higher.

During a WAN partition where an operator raises the dial in response to an attack, the
other DC continues in a degraded defensive posture. Critically: dial changes happen in
response to active attacks — the moment you need consistency most is the moment WAN
partition is most likely, because a volumetric attack may be degrading the WAN link
simultaneously.

### 5.2 Propagation Protocol Rules

**Rule 1:** No dial change takes effect locally until it has been acknowledged by all
reachable DCs OR the propagation timeout (8 seconds) has elapsed.

**Propagation flow:**

```
Operator
  │
  ▼
Management UI
  │
  ▼
POST /api/v1/config/dial
  │
  ▼
writes ja4proxy:dc:dial:pending
  │
  ▼
Sync agent sends DIAL_PROP event via mTLS direct RPC (port 7380)
to all reachable peers
  │
  ├── Full ack received from all peers within 8s ──►
  │                                                  │
  └── Timeout (8s elapsed) ──────────────────────►  │
                                                     ▼
                               SET config:dial
                               PUBLISH config:dial:change
                               DEL ja4proxy:dc:dial:pending
```

**Rule 2:** The propagation timeout is 8 seconds. If any DC does not acknowledge within
8s, the change proceeds locally AND the `DialPropagationFailed` alert fires at critical
severity.

**Rule 3:** Dial propagation uses a synchronous RPC call over mTLS at port 7380
(distinct from the async stream port 7379). It does not use the async stream.

**Rule 4:** On partition heal, the most-recently-written dial wins by `origin_ts`. Not
highest, not lowest. An operator lowering the dial during an incident must not have a
stale high-dial event overwrite their change.

### 5.3 Failure Handling

When propagation fails:
- The `DialPropagationFailed` alert fires immediately (no `for:` period).
- The local DC applies the change.
- The incident is logged to `management:policy_audit` with
  `propagation_status: partial`.
- On WAN reconnect, the sync agent applies the most-recent dial by `origin_ts`.
- If both DCs changed the dial independently during the partition, the
  `DialDivergence` alert fires on heal and the operator must manually confirm the
  authoritative value.

---

## 6. HAProxy and Global Routing

### 6.1 Active-Active: GeoDNS and Per-DC HAProxy

```
                  GeoDNS / Anycast / Global LB
                           │
         ┌─────────────────┴─────────────────┐
         ▼                                   ▼
    HAProxy-DC-A                        HAProxy-DC-B
    JA4proxy × N                        JA4proxy × N
    Redis-DC-A                          Redis-DC-B
         │                                   │
         └────────── Sync Agent ─────────────┘
              (async, mTLS, port 7379)
```

**Route 53 latency-based routing (AWS CLI example):**

```bash
# Create health check
aws route53 create-health-check \
  --caller-reference dc-a-$(date +%s) \
  --health-check-config '{
    "Type": "HTTPS",
    "FullyQualifiedDomainName": "dc-a.ja4proxy.example.com",
    "Port": 443,
    "ResourcePath": "/health",
    "RequestInterval": 10,
    "FailureThreshold": 2
  }'

# Create latency record for DC-A
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890ABC \
  --change-batch '{
    "Changes": [{
      "Action": "CREATE",
      "ResourceRecordSet": {
        "Name": "proxy.example.com",
        "Type": "A",
        "SetIdentifier": "dc-a",
        "Region": "us-east-1",
        "TTL": 30,
        "HealthCheckId": "HEALTH_CHECK_ID_A",
        "ResourceRecords": [{"Value": "203.0.113.10"}]
      }
    }]
  }'
```

**HAProxy backend configuration:**

```haproxy
defaults
    option  redispatch
    timeout queue 10s

backend ja4proxy_backend
    balance leastconn
    option  httpchk GET /health HTTP/1.0\r\nHost:\ health-check
    http-check expect status 200
    timeout check 3s
    server proxy1 proxy1:8080 send-proxy-v2 check inter 5s fall 2 rise 1 weight 100
    server proxy2 proxy2:8080 send-proxy-v2 check inter 5s fall 2 rise 1 weight 100
    server proxy3 proxy3:8080 send-proxy-v2 check inter 5s fall 2 rise 1 weight 100
    server proxy4 proxy4:8080 send-proxy-v2 check inter 5s fall 2 rise 1 weight 100
```

`fall 2 rise 1` marks a backend DOWN after 2 consecutive failed health checks (10s)
and UP after 1 success. This is asymmetric by design: fast to mark DOWN, conservative
about marking UP to avoid oscillation during instability.

For deployments without Route 53, Cloudflare Load Balancing provides a simpler
alternative. With Cloudflare proxied mode, DNS TTL is effectively zero — failover
propagates in under 5 seconds without waiting for resolver cache expiry.

### 6.2 Active-Passive: Global LB Failover

**Azure Traffic Manager example:**

```json
{
  "properties": {
    "profileStatus": "Enabled",
    "trafficRoutingMethod": "Priority",
    "dnsConfig": {
      "relativeName": "ja4proxy",
      "ttl": 30
    },
    "monitorConfig": {
      "protocol": "HTTPS",
      "port": 443,
      "path": "/health",
      "intervalInSeconds": 10,
      "timeoutInSeconds": 5,
      "toleratedNumberOfFailures": 2
    },
    "endpoints": [
      {
        "name": "dc-a-primary",
        "type": "Microsoft.Network/trafficManagerProfiles/externalEndpoints",
        "properties": {
          "target": "dc-a.ja4proxy.example.com",
          "endpointStatus": "Enabled",
          "priority": 1
        }
      },
      {
        "name": "dc-b-standby",
        "type": "Microsoft.Network/trafficManagerProfiles/externalEndpoints",
        "properties": {
          "target": "dc-b.ja4proxy.example.com",
          "endpointStatus": "Enabled",
          "priority": 2
        }
      }
    ]
  }
}
```

DNS TTL of 30s is a propagation cap, not a guarantee. Resolvers may cache longer. For
faster failover use Cloudflare proxied mode or AWS Route 53 alias records.

---

## 7. Failure Scenario Runbooks

### Scenario 1: WAN Link Failure (DC Partition)

**Trigger / Symptoms:** `SyncAgentWANDisconnected` alert fires;
`ja4proxy_sync_wan_connected` drops to 0.

**Immediate Impact:** Ban propagation halted. Both DCs continue independently. All
existing bans enforce locally. New bans issued on one DC do not reach the other.

**Recovery:**

```bash
# Verify WAN path from sync agent host
curl --cert /etc/syncagent/tls/syncagent.crt \
     --key  /etc/syncagent/tls/syncagent.key \
     --cacert /etc/syncagent/tls/sync-ca.crt \
     https://dc-b-sync.example.com:7379/health

# Check sync agent buffer depth (should be rising during partition)
redis-cli XLEN ja4proxy:dc:dc-a:sync:out

# On WAN restore: sync agent auto-replays from last ack'd ID — no manual action
# Verify reconnection:
redis-cli HGET ja4proxy:sync:agent:status wan_connected

# After heal: verify dial consistency across DCs
redis-cli GET config:dial  # run on both DC-A and DC-B Redis
```

**RTO:** Zero — both DCs continue serving. Full sync resume: within 5 minutes of WAN
restoration.

---

### Scenario 2: Complete DC Failure (DC Goes Dark)

**Trigger / Symptoms:** `SyncAgentWANDisconnected` AND `HAProxyBackendDown` for all
DC-A backends. Global LB routes all traffic to DC-B.

**Immediate Impact:** Traffic shifts to DC-B within DNS TTL plus health check
convergence (≤60s). DC-B has at most 30s-stale ban state. DC-B sync buffer
accumulates.

**Recovery:**

```bash
# Step 1: Restore Redis Sentinel cluster
# Start Sentinel nodes first; wait for master election
redis-cli -h redis-a-sentinel-1 -p 26379 SENTINEL masters

# Step 2: Reseed DC-A Redis from DC-B snapshot
redis-cli -h redis-b-primary BGSAVE
# Transfer dump.rdb to DC-A and restore

# Step 3: Start DC-A sync agent; verify WAN channel connected
# Monitor sync lag before returning DC-A to rotation:
redis-cli XLEN ja4proxy:dc:dc-a:sync:out  # should trend to 0

# Step 4: Return DC-A to global LB gradually (10% weight first)
aws route53 change-resource-record-sets ...  # update weight
```

**RTO:** 60s for traffic shift to DC-B. DC-A restoration: 15 minutes (operator-driven).

---

### Scenario 3: DC Redis Failure Only (Proxy Nodes Up, Redis Down)

**Trigger / Symptoms:** `RedisDown` alert fires. Health endpoint shows
`"redis": "degraded"`. Proxy logs emit WARN for every connection.

**Immediate Impact:** All connections pass through unchecked. `GetDial()` returns 0
(monitor mode). Local LRU cache enforces recently-seen bans for up to 30 minutes.

**Recovery:**

```bash
# Verify Sentinel master election status
redis-cli -h redis-a-sentinel-1 -p 26379 SENTINEL get-master-addr-by-name ja4proxy-primary

# If no master elected, trigger manual failover
redis-cli -h redis-a-sentinel-1 -p 26379 SENTINEL failover ja4proxy-primary

# Verify proxy auto-reconnects (no restart required)
# Watch proxy logs for: "redis reconnected"

# Reload Lua scripts after Redis restarts
redis-cli SCRIPT LOAD "$(cat scripts/lua/sliding_window.lua)"
redis-cli PUBLISH config:reload '{"type":"lua_reload"}'
```

**RTO:** Automatic. Redis Sentinel failover completes in ≤30s. Proxy reconnects without
restart.

---

### Scenario 4: Dial Setting Divergence

**Trigger / Symptoms:** `DialDivergence` alert fires. Grafana shows inconsistent block
rates between DCs on the multi-DC dashboard.

**Immediate Impact:** The DC with the lower dial is blocking fewer connections during
an active attack.

**Recovery:**

```bash
# Read dial on both DCs
redis-cli -h redis-a-primary GET config:dial
redis-cli -h redis-b-primary GET config:dial

# Identify operator's intent from policy audit log
redis-cli -h redis-a-primary LRANGE management:policy_audit 0 9

# Apply authoritative value via Management API (triggers propagation protocol)
curl -X POST https://mgmt.dc-a.example.com/api/v1/config/dial \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"dial": 75, "reason": "attack-in-progress"}'
```

**RTO:** ≤8s for propagation protocol completion. Alert resolution: ≤2 minutes.

---

### Scenario 5: Redis Data Loss in One DC

**Trigger / Symptoms:** Redis restarts clean. `ja4proxy_active_bans` drops to 0 on
one DC. Sync agent inbound shows high XACK activity as it replays.

**Immediate Impact:** The affected DC operates fail-open. Active bans are missing. The
sync agent will re-propagate forward-in-time events but NOT historical state older than
the stream buffer.

**Recovery — Option A (faster, recommended):**

```bash
# Restore from DC-B snapshot
redis-cli -h redis-b-primary BGSAVE
scp redis-b-primary:/var/lib/redis/dump.rdb redis-a-primary:/var/lib/redis/
redis-cli -h redis-a-primary DEBUG RELOAD
```

**Recovery — Option B (stream replay only):**

Allow the sync agent to replay pending stream events. Current active bans propagate
within 30 minutes. Historical bans (TTL expired during partition) are not recovered,
but this is safe because expired bans should not be enforced.

**RTO:** With snapshot restore: ≤10 minutes. With stream replay only: ≤30 minutes for
current-state bans.

---

### Scenario 6: Asymmetric Performance Degradation (One DC Slow, Not Failed)

**Trigger / Symptoms:** `ProxyHighLatency` fires on DC-A. HAProxy queue elevated.
Health checks still passing — global LB does not auto-failover.

**Immediate Impact:** Global LB keeps routing to DC-A. DC-A clients see high latency.
Sync still operates but may be slower.

**Recovery:**

```bash
# Reduce DC-A weight in Route 53 immediately
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890ABC \
  --change-batch '{"Changes":[{"Action":"UPSERT","ResourceRecordSet":{
    "Name":"proxy.example.com","Type":"A","SetIdentifier":"dc-a",
    "Region":"us-east-1","TTL":30,
    "ResourceRecords":[{"Value":"203.0.113.10"}]}}]}'
# (reduce weight field to 10 or 0)

# Diagnose root cause
docker stats --no-stream           # CPU throttle?
redis-cli --latency-history        # Redis latency?
ss -s                              # socket queue buildup?

# Restore weights when DC-A metrics return to baseline
```

**RTO:** Operator-driven within 5 minutes. Note: a future enhancement is HAProxy
`agent-check` on port 9999 that returns a weight based on latency percentile,
automating this step without DNS changes.

---

### Scenario 7: Split-Brain During Extended Partition

**Trigger / Symptoms:** WAN down for more than 10 minutes. Sync buffers approaching
capacity (`ja4proxy_sync_outbound_stream_len` approaching 50,000). Both DCs have
independent bans and potentially divergent dial values.

**Immediate Impact:** Both DCs function correctly and independently. State has diverged.
The `SyncBufferNearCapacity` and `DialDivergence` alerts are firing.

**Recovery:**

```bash
# On WAN restoration, sync agent auto-reconciles:
# - Bans: max-TTL wins (both sides XADD their state; agent picks longer TTL)
# - SETs (whitelist, blacklist): union applied
# No manual action required for traffic.

# Verify dial consistency after heal (highest-priority manual check):
redis-cli -h redis-a-primary GET config:dial
redis-cli -h redis-b-primary GET config:dial

# Check for intentional whitelist removals during partition
# (union on heal means removals made during partition must be re-applied manually)
redis-cli -h redis-a-primary SMEMBERS ja4:whitelist > /tmp/wl-a.txt
redis-cli -h redis-b-primary SMEMBERS ja4:whitelist > /tmp/wl-b.txt
diff /tmp/wl-a.txt /tmp/wl-b.txt

# Monitor stream replay completion
watch -n5 'redis-cli XLEN ja4proxy:dc:dc-a:sync:out'
```

**RTO:** State convergence within 5 minutes of WAN restoration for current state. No
operator action is required for traffic continuity.

---

## 8. Multi-DC Observability

### 8.1 New Prometheus Metrics

The sync agent exposes a Prometheus endpoint on port 9382. Add it to
`monitoring/prometheus/prometheus.yml`:

```yaml
  - job_name: 'syncagent'
    scrape_interval: 15s
    static_configs:
      - targets: ['syncagent:9382']
        labels:
          service: syncagent
          role: cross-dc-sync
```

**Metrics emitted by the sync agent:**

```
ja4proxy_sync_wan_connected{dc, peer}
  Gauge. 1 = WAN channel up, 0 = disconnected.

ja4proxy_sync_rtt_ms{dc, peer}
  Gauge. WAN round-trip latency in milliseconds, measured every 15s via dial heartbeat.

ja4proxy_sync_outbound_stream_len{dc}
  Gauge. Number of events in the outbound stream awaiting delivery. Rising during
  WAN partition; should trend toward 0 during normal operation.

ja4proxy_sync_events_sent_total{dc, peer, key_type}
  Counter. Total sync events successfully delivered to the remote DC, by key type.

ja4proxy_sync_events_received_total{dc, source, key_type}
  Counter. Total sync events received and applied from remote DCs, by key type.

ja4proxy_sync_apply_drops_total{dc, source, key_type}
  Counter. Events dropped after exhausting local Redis write retries. Any non-zero
  value warrants investigation.

ja4proxy_sync_last_event_age_seconds{dc, peer}
  Gauge. Seconds since the last event was received from a given peer. Used to detect
  a "silent link" where the WAN channel is up but no events are flowing.

ja4proxy_dial_current{dc}
  Gauge. Current dial value on this DC. Add dc label to the existing metric. Used
  by the DialDivergence alert to compare values across DCs.

ja4proxy_sync_dial_propagation_total{dc, result}
  Counter. Dial propagation attempts by result. result = acked | timeout.

ja4proxy_sync_replay_lag_seconds{dc, consumer}
  Gauge. How far behind the stream head the consumer group is, in seconds.
  Key SLA metric: should be < 30s during normal operation.

ja4proxy_sync_reconcile_total{dc, key_type, resolution}
  Counter. Conflict resolutions applied during partition heal, by key type and
  resolution strategy (max_ttl, union, last_writer).
```

### 8.2 Alertmanager Rules

Append a new group `ja4proxy_multidc` to `monitoring/prometheus/alerts.yml`.

```yaml
  - name: ja4proxy_multidc
    interval: 30s
    rules:

      - alert: SyncAgentWANDisconnected
        expr: ja4proxy_sync_wan_connected == 0
        for: 30s
        labels:
          severity: critical
          component: syncagent
          alert_type: multidc
        annotations:
          summary: "DC {{ $labels.dc }} lost WAN sync channel to {{ $labels.peer }}"
          description: >
            The cross-DC sync channel has been down for 30 seconds. Ban propagation
            is halted. Both DCs continue independently. If the partition lasts longer
            than the stream buffer capacity (~123s at peak load), events will be
            trimmed and state will diverge further.
          runbook_url: "docs/runbooks/multidc.md#wan-link-failure"

      - alert: SyncAgentReplayLagHigh
        expr: ja4proxy_sync_replay_lag_seconds > 30
        for: 60s
        labels:
          severity: warning
          component: syncagent
          alert_type: multidc
        annotations:
          summary: "DC {{ $labels.dc }} sync replay lag {{ $value | humanize }}s"
          description: >
            The sync agent is more than 30 seconds behind the stream head. This may
            indicate a slow WAN link, Redis write latency, or a recent partition heal
            with a large backlog to replay.
          runbook_url: "docs/runbooks/multidc.md#replay-lag"

      - alert: SyncBufferNearCapacity
        expr: ja4proxy_sync_outbound_stream_len > 40000
        for: 60s
        labels:
          severity: warning
          component: syncagent
          alert_type: multidc
        annotations:
          summary: "DC {{ $labels.dc }} sync buffer at {{ $value }} events (limit ~50000)"
          description: >
            The outbound sync stream is at {{ $value }} events. At peak load the
            buffer capacity is approximately 123 seconds. Events will be trimmed if
            the WAN remains down. Oldest events will be lost.
          runbook_url: "docs/runbooks/multidc.md#buffer-capacity"

      - alert: DialDivergence
        expr: >
          max(ja4proxy_dial_current) by () - min(ja4proxy_dial_current) by () > 5
        for: 30s
        labels:
          severity: critical
          component: syncagent
          alert_type: multidc
        annotations:
          summary: "Dial divergence {{ $value }} points across DCs"
          description: >
            The dial setting differs by more than 5 points between DCs. This is the
            most dangerous multi-DC inconsistency: the DC with the lower dial has a
            materially higher block threshold. Resolve immediately by applying the
            authoritative dial via the Management API propagation protocol.
          runbook_url: "docs/runbooks/multidc.md#dial-divergence"

      - alert: DialPropagationFailed
        expr: >
          increase(ja4proxy_sync_dial_propagation_total{result="timeout"}[5m]) > 0
        for: 0m
        labels:
          severity: critical
          component: syncagent
          alert_type: multidc
        annotations:
          summary: "Dial propagation timed out — dial may be diverging"
          description: >
            A dial change did not receive acknowledgement from all DCs within the
            8-second timeout. The change has been applied locally. The remote DC
            retains its previous dial value until the next sync or operator
            intervention.
          runbook_url: "docs/runbooks/multidc.md#dial-propagation-failed"

      - alert: SyncAgentSilentLink
        expr: ja4proxy_sync_last_event_age_seconds > 120
        for: 0m
        labels:
          severity: warning
          component: syncagent
          alert_type: multidc
        annotations:
          summary: "No sync events from {{ $labels.peer }} for {{ $value | humanize }}s"
          description: >
            The WAN channel reports as connected but no events have been received
            from the peer DC for more than 120 seconds. This may indicate the remote
            sync agent has stopped writing, the remote Redis is degraded, or the
            connection is alive but idle (check if the remote DC has zero activity).
          runbook_url: "docs/runbooks/multidc.md#silent-link"
```

**Alertmanager routing addition** — add to `alertmanager.yml` routes:

```yaml
    - match:
        component: syncagent
        severity: critical
      receiver: oncall-pager
```

**Inhibition rule** — downstream noise suppression:

```yaml
inhibit_rules:
  - source_match:
      alertname: SyncAgentWANDisconnected
    target_match_re:
      alertname: "SyncAgentReplayLagHigh|SyncBufferNearCapacity"
    equal: ["dc"]
```

`SyncAgentWANDisconnected` inhibits `SyncAgentReplayLagHigh` and
`SyncBufferNearCapacity` because both are direct downstream symptoms of the WAN
disconnection. They would fire within seconds of a partition; suppressing them keeps
the oncall alert focused on the root cause.

### 8.3 Grafana Dashboard

Add `monitoring/grafana/dashboards/ja4proxy-multidc.json` as a new dashboard. Do NOT
add multi-DC panels to `ja4proxy-overview.json` or `ja4proxy-infrastructure.json`.

**Template variable:**

```json
{
  "name": "dc_pair",
  "type": "query",
  "query": "label_values(ja4proxy_sync_wan_connected, dc)",
  "label": "DC",
  "current": {}
}
```

**Dashboard layout:**

```
╔══ DC Link Status (Row 1) ════════════════════════════════════════════╗
║  [WAN Connected: dc-a→dc-b] [WAN Connected: dc-b→dc-a]             ║
║  [RTT ms: dc-a→dc-b]        [RTT ms: dc-b→dc-a]      (stat, h=4)  ║
╚══════════════════════════════════════════════════════════════════════╝

╔══ Dial Parity (Row 2) ══════════════════════════════════════════════╗
║  [Dial: DC-A] [Dial: DC-B]   [Dial Gap: max-min] (stat, h=4)      ║
║  [Dial setting per DC — time series, all DCs overlaid]   (h=8)     ║
╚══════════════════════════════════════════════════════════════════════╝

╔══ Sync Performance (Row 3) ═════════════════════════════════════════╗
║  [Outbound stream len with 40k/50k reference lines]      (h=8)     ║
║  [Replay lag seconds per DC] [Events/s sent + received]  (h=8)     ║
╚══════════════════════════════════════════════════════════════════════╝

╔══ Block Rate Per DC (Row 4) ════════════════════════════════════════╗
║  [Block rate per DC — diverging rates = early dial divergence]      ║
║  (time series, one series per dc label)                  (h=8)     ║
╚══════════════════════════════════════════════════════════════════════╝

╔══ Ban State Parity (Row 5) ═════════════════════════════════════════╗
║  [redis_db_keys per DC — large differences = state divergence]      ║
║  [Active bans per DC]                                    (h=8)     ║
╚══════════════════════════════════════════════════════════════════════╝
```

The Dial Parity row is the most operationally important. The "Dial Gap" stat panel uses
a red threshold at > 5 to immediately surface divergence. Operators should check this
dashboard first during any active attack.

---

## 9. Operational Procedures

### 9.1 Planned DC Maintenance Drain

This procedure achieves zero client impact throughout the maintenance window.

**T-15 min:** Notify ops channel. Confirm DC-B is healthy and sync lag < 5s.

**T-5 min:** Set DC-A weight to 0 in global LB:

```bash
# Route 53: set weight to 0 (removes DC-A from rotation without deleting the record)
aws route53 change-resource-record-sets --hosted-zone-id Z1234567890ABC \
  --change-batch '{"Changes":[{"Action":"UPSERT","ResourceRecordSet":{
    "Name":"proxy.example.com","Type":"A","SetIdentifier":"dc-a",
    "Region":"us-east-1","TTL":30,"Weight":0,
    "ResourceRecords":[{"Value":"203.0.113.10"}]}}]}'
```

**T-0:** Disable all proxy backends in DC-A HAProxy:

```bash
for i in 1 2 3 4; do
  echo "disable server ja4proxy_backend/proxy${i}" | \
    socat stdio /var/run/haproxy/admin.sock
done
```

**T+0 to T+30s:** Wait for active connections to drain:

```bash
# Watch current connections; proceed when CurrConns reaches 0
watch -n2 'echo "show stat" | socat stdio /var/run/haproxy/admin.sock | \
  cut -d, -f1,2,18 | grep ja4proxy'
```

**T+30s:** Stop proxy processes gracefully (SIGTERM for graceful drain):

```bash
docker compose -f docker/docker-compose.poc.yml stop proxy
```

**After proxy stops:** Stop the sync agent:

```bash
docker compose -f docker/docker-compose.poc.yml stop syncagent
```

**Perform maintenance.**

**Restoration sequence:**

1. Start Redis Sentinel nodes; wait for master election.
2. Reseed from DC-B snapshot if state drift is suspected.
3. Start sync agent; wait for `ja4proxy_sync_wan_connected = 1`.
4. Start proxy processes.
5. Restore DC-A weight in global LB (start at 10%; promote to full after 5 minutes).

### 9.2 DC Expansion — Adding a Third DC

**Sync agent configuration for DC-C (multi-peer):**

```yaml
sync_agent:
  dc_id: "dc-c"
  remote_peers:
    - addr: "dc-a-sync.example.com:7379"
      dc_id: "dc-a"
    - addr: "dc-b-sync.example.com:7379"
      dc_id: "dc-b"
  tls:
    cert_file: "/etc/syncagent/tls/syncagent.crt"
    key_file:  "/etc/syncagent/tls/syncagent.key"
    ca_file:   "/etc/syncagent/tls/sync-ca.crt"
  outbound_stream: "ja4proxy:dc:dc-c:sync:out"
  inbound_consumer_group: "sync-dc-c"
  buffer_maxlen: 50000
  wan_reconnect_backoff_max_seconds: 30
  local_redis_sentinel:
    master_name: "ja4proxy-primary"
    sentinels:
      - "redis-c-sentinel-1:26379"
      - "redis-c-sentinel-2:26379"
      - "redis-c-sentinel-3:26379"
```

**Expansion steps:**

1. Update DC-A and DC-B `syncagent.yml` to add DC-C as a peer. Send SIGHUP for hot
   reload (no restart required).
2. Seed DC-C Redis from a DC-A snapshot.
3. Start DC-C sync agent; wait for `ja4proxy_sync_wan_connected = 1` for both peers.
4. Start DC-C proxy processes with dial=0 (monitor mode).
5. Wait for sync replay lag < 5s on all DC-C consumers.
6. Add DC-C to global LB at 10% weight.
7. Monitor DC-C for 15 minutes; verify block rate and dial match DC-A and DC-B.
8. Promote DC-C to equal weight.

### 9.3 Cross-DC Upgrade Sequence

All DCs must run the same version by the end of the upgrade window. Mixed-version
operation is permitted only within a defined window; never across a maintenance
boundary.

**Constraint:** The sync protocol uses `schema_version` tags on XADD events. Sync
agents ignore unknown event types. This provides one-version forward compatibility,
sufficient for a rolling upgrade.

**Sequence:**

1. Upgrade DC-C first (least traffic). Verify 30 minutes.
2. Upgrade DC-B while DC-A serves majority traffic. Verify 30 minutes.
3. Upgrade DC-A.

**Rollback within a DC:** Use the existing blue/green procedure from Phase 43. Completes
within 30 seconds. Roll back at the DC level, not the sync agent level.

**Redis schema migrations:** New key types must be forward-compatible. Old sync agents
receiving events with unknown `key_type` values log a WARN and skip them; they do not
crash or disconnect.

---

## 10. Makefile Targets

Add at the bottom of `Makefile`. Do NOT edit existing targets.

```makefile
## Phase 88 targets

# Start the sync agent in the local DC (for dev/staging)
syncagent:
	go run ./cmd/syncagent/ --config config/syncagent.yml

# Build the sync agent binary
build-syncagent:
	go build -o bin/ja4proxy-syncagent ./cmd/syncagent/

# Run sync agent unit tests
test-phase-88:
	python3 -m pytest tests/phase-88/ -v --timeout=60
	go test ./cmd/syncagent/... -v

# Run multi-DC scenario smoke test (requires two Redis instances on localhost)
test-multidc-smoke:
	bash scripts/smoke/test_multidc_sync.sh

# Simulate WAN failure and verify both DCs continue serving
test-multidc-wan-failure:
	bash scripts/smoke/test_multidc_wan_failure.sh

# Verify dial propagation completes within 8 seconds
test-dial-propagation:
	bash scripts/smoke/test_dial_propagation.sh

# Run MTTR measurement for multi-DC scenarios
measure-mttr-multidc:
	bash scripts/measure_mttr_multidc.sh
```

---

## 11. Files Introduced or Modified

| File | Change |
|---|---|
| `cmd/syncagent/main.go` | New binary — sync agent entry point |
| `cmd/syncagent/agent.go` | Sync agent logic: outbound writer, inbound reader, WAN reconnect |
| `cmd/syncagent/dial_rpc.go` | Dial propagation RPC server/client (port 7380) |
| `cmd/syncagent/metrics.go` | Prometheus metric registration for sync agent |
| `internal/redis/client.go` | Replace `goredis.NewClient` with `goredis.NewFailoverClient` for Sentinel |
| `config/syncagent.yml` | New sync agent config file |
| `monitoring/prometheus/prometheus.yml` | Add syncagent scrape job |
| `monitoring/prometheus/alerts.yml` | Append `ja4proxy_multidc` alert group |
| `monitoring/alertmanager/alertmanager.yml` | Add syncagent routing rule and inhibition rule |
| `monitoring/grafana/dashboards/ja4proxy-multidc.json` | New dashboard |
| `monitoring/grafana/provisioning/dashboards/default.yml` | Add new dashboard path |
| `docs/runbooks/multidc.md` | New runbook |
| `tests/phase-88/` | New test directory |
| `scripts/smoke/test_multidc_sync.sh` | Multi-DC smoke test |
| `scripts/smoke/test_multidc_wan_failure.sh` | WAN failure simulation test |
| `scripts/smoke/test_dial_propagation.sh` | Dial propagation timing test |
| `scripts/measure_mttr_multidc.sh` | MTTR measurement harness |
| `Makefile` | Append Phase 88 targets at bottom only |
| `CHANGELOG.md` | Prepend Phase 88 entry |
| `docs/phases/manifest.yaml` | Set Phase 88 status to COMPLETE |

**Shared file rules:**
- `monitoring/prometheus/alerts.yml` — append only. Lines above the new group must be
  byte-for-byte identical before and after.
- `monitoring/alertmanager/alertmanager.yml` — add one routing rule and one inhibition
  rule only.
- `Makefile` — add at the bottom only. Do not edit existing targets.
- `internal/redis/client.go` — replace the client constructor only. Do not alter any
  other function signatures.

---

## 12. Acceptance Criteria

### Sync Agent

- [ ] `cmd/syncagent/main.go` exists and `go build ./cmd/syncagent/` succeeds with zero warnings
- [ ] Sync agent connects to local Redis via Sentinel (`goredis.NewFailoverClient`); proxy also updated
- [ ] Outbound stream populated with correct XADD fields (`key_type`, `key`, `op`, `value`, `ttl_remaining_ms`, `origin_dc`, `origin_ts`) for all SYNC-IMMEDIATE key types
- [ ] XACK is issued only after successful remote Redis write; confirmed by test that kills remote Redis mid-stream and verifies no data loss on reconnect
- [ ] WAN reconnect uses exponential backoff (1s, 2s, 4s, 8s, 16s, 30s cap); verified in unit test
- [ ] `ja4proxy_sync_apply_drops_total` increments when local Redis write fails after 5 retries
- [ ] mTLS enforced on WAN channel; connections without a valid sync CA certificate are rejected
- [ ] `config/syncagent.yml` present with all fields documented; hot reload via SIGHUP verified

### Dial Protocol

- [ ] Dial change does not take effect until all reachable DCs ack OR 8-second timeout elapses
- [ ] `DialPropagationFailed` alert fires (immediately, `for: 0m`) when propagation times out; verified in `test-dial-propagation` script
- [ ] `test-dial-propagation` script completes within 10 seconds and asserts dial value is consistent across both DC Redis instances
- [ ] Partition-heal conflict: most-recent `origin_ts` wins; test with two independent dial changes during simulated partition

### HAProxy and Routing

- [ ] Active-passive example configuration (Azure Traffic Manager JSON) validated against the Azure schema; active-active Route 53 example contains correct CLI syntax
- [ ] HAProxy backend configuration uses `fall 2 rise 1` and `send-proxy-v2`; tested against existing `config/haproxy.cfg`
- [ ] `test-multidc-wan-failure` script verifies that proxy instances continue accepting connections when the sync agent's WAN channel is severed (iptables DROP or network namespace isolation)

### Observability

- [ ] All 11 sync agent Prometheus metrics present in `/metrics` output of a running sync agent instance
- [ ] `ja4proxy_multidc` alert group present in `alerts.yml`; all 6 alerts validate as correct PromQL via `promtool check rules`
- [ ] `SyncAgentWANDisconnected` inhibits `SyncAgentReplayLagHigh` and `SyncBufferNearCapacity`; verified in `promtool test rules`
- [ ] `ja4proxy-multidc.json` exists and is valid JSON; contains Dial Parity row with gap stat panel
- [ ] `DialDivergence` alert expression uses `max(...) - min(...) > 5`; unit-tested with fixture series showing 6-point gap

### Operational Procedures

- [ ] Planned maintenance drain procedure executed in staging: DC-A drained, connections confirmed zero, processes stopped, DC-B served all traffic, DC-A restored, weights returned — zero client errors throughout
- [ ] DC expansion procedure documented and tested with a third local Redis instance; sync lag < 5s after seeding
- [ ] `docs/runbooks/multidc.md` present with sections for all 7 failure scenarios; each section contains Trigger, Impact, Recovery Commands, and RTO

### Failure Scenario Testing

- [ ] Scenario 1 (WAN failure): `test-multidc-wan-failure` passes; both DCs serve traffic; sync resumes automatically on reconnect
- [ ] Scenario 2 (complete DC failure): HAProxy health check fails for all DC-A backends within 10s; traffic shifts to DC-B; verified in smoke test
- [ ] Scenario 3 (Redis down): proxy emits WARN per connection; `GetDial()` returns 0; local LRU cache enforces recent bans; auto-reconnect verified
- [ ] Scenario 4 (dial divergence): injecting different dial values into two Redis instances triggers `DialDivergence` alert within 30s + `for` period
- [ ] Scenario 5 (Redis data loss): after `DEBUG FLUSHALL` on DC-A Redis, sync agent re-propagates current bans; active ban count recovers to DC-B level within stream replay window
- [ ] Scenario 6 (asymmetric degradation): weight-reduction procedure reduces DC-A traffic within 30s of Route 53 change; verified via access log analysis
- [ ] Scenario 7 (split-brain): after 2-minute simulated partition, on reconnect ban state converges (max-TTL wins), set state converges (union), and dial uses most-recent `origin_ts`; verified in `test-multidc-smoke`

### Documentation

- [ ] `CHANGELOG.md` updated with Phase 88 entry in standard format
- [ ] `docs/phases/manifest.yaml` Phase 88 status set to `COMPLETE` with `completed:` date
- [ ] `python3 scripts/sync-roadmap.py` run; `docs/phases/TODO.md` and `docs/PROJECT_STATUS.md` regenerated
- [ ] `make test-phase-88` passes with zero failures and zero skipped tests
