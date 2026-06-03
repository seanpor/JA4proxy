# Container & Host Infrastructure Observability

> **Prerequisite: Phase 14 (production hardening) must be complete.**
> The monitoring stack (`docker/docker-compose.monitoring.yml`) must be running.

---

## 1. Overview

JA4proxy currently has excellent *security signal* observability — risk scores, block
rates, TLS fingerprint distributions — but near-zero *infrastructure* observability.
We cannot answer:

- "Is the proxy CPU-throttled because Docker capped its quota, not because the host is busy?"
- "Is HAProxy queuing connections waiting for a proxy slot — meaning the proxy is at capacity?"
- "Is the Redis disk filling up from AOF persistence?"
- "Is this connection spike a volumetric attack or organic growth?"
- "Will entropy be depleted in the next ten minutes, stalling TLS handshakes?"
- "Is file descriptor exhaustion imminent at the OS level?"

Answering these requires four things currently absent:

1. **cAdvisor** — per-container CPU, memory, disk I/O, CPU throttling. `node-exporter`
   gives host totals only; you cannot see which container consumes what.

2. **HAProxy exporter** — queue depth is the single best indicator of proxy saturation.
   HAProxy rejects or queues connections *before* JA4proxy sees them; this layer is
   completely blind without a dedicated exporter.

3. **OS-level network and TCP stack metrics** — packet rates, TCP socket states,
   NIC errors, entropy. These signals exist before and below HAProxy, giving earlier
   warning than connection-rate metrics alone.

4. **A dedicated infrastructure dashboard** — separate from the security overview, with
   a layout that fits in three viewport heights regardless of fleet size, using a
   container dropdown instead of infinite parallel timeseries.

---

## 2. Design Decisions

Follow these exactly. They were derived from the constraints of the specific stack;
re-deriving them costs time and risks repeating known mistakes.

### 2.1 Two Dashboards, Not One Mega-Dashboard

| Dashboard | File | Audience | Content |
|---|---|---|---|
| Security Overview (existing) | `ja4proxy-overview.json` | SecOps | Block rates, fingerprints, scores, risk signals |
| Infrastructure & Attack (new) | `ja4proxy-infrastructure.json` | Ops + SecOps | Container health, host resources, HAProxy, attack detection |

The dashboards link to each other via `links` entries. An operator following an
alert lands on the infrastructure dashboard; if they need signal detail they click
through to the security overview.

**Do NOT add infrastructure panels to `ja4proxy-overview.json`.** This was attempted
and reverted during the session that produced this phase document.

### 2.2 No Infinite Scroll — Two Navigation Patterns

**Pattern 1 — Fleet status strip.**
One `stat` panel per container showing memory working-set as a percentage of its
configured limit. All containers fit in a single 24-column row, colour-coded green /
yellow / red. The operator sees the entire fleet health at a glance without scrolling.

**Pattern 2 — Container variable for drill-down.**
A template variable `$container` populated from
`label_values(container_memory_working_set_bytes{name!~".+_[0-9]+"}, name)` filters
all timeseries panels. One container is shown at a time — 12 containers × 4 timeseries
= 48 panels collapses to 4 panels plus a dropdown.

Total dashboard height: ≤5 viewport heights regardless of fleet size.

### 2.3 cAdvisor Is the Missing Piece

`node-exporter` exposes host-aggregated metrics. `cAdvisor` exposes per-container:

| Metric | Why it matters |
|---|---|
| `container_cpu_usage_seconds_total` | CPU consumed per container |
| `container_cpu_cfs_throttled_seconds_total` | Time spent waiting for CPU quota — see §2.7 |
| `container_memory_working_set_bytes` | Working set (what OOM killer uses; excludes page cache) |
| `container_memory_limit_bytes` / `container_spec_memory_limit_bytes` | Configured limit |
| `container_oom_events_total` | OOM kills |
| `container_start_time_seconds` | Resets on container restart — used to detect restart loops |
| `container_fs_reads_bytes_total` / `container_fs_writes_bytes_total` | Disk I/O per container |
| `container_network_receive_bytes_total` / `container_network_transmit_bytes_total` | Net I/O per container |
| `container_network_receive_errors_total` / `container_network_transmit_errors_total` | Per-container net errors |

`container_start_time_seconds` resetting is how we detect restarts without Kubernetes.
`changes(container_start_time_seconds{name=~"..."}[30m]) >= 2` = crashed twice in 30 min.

### 2.4 HAProxy Is a Leading Indicator

HAProxy sits in front of JA4proxy. When the proxy is saturated:

1. HAProxy begins **queueing** connections waiting for a backend slot.
2. The queue depth is visible in `haproxy_backend_current_queue`.
3. **This fires before** `ConnectionRateSustainedHigh` because HAProxy absorbs the
   incoming surge while the proxy is still working through its backlog.

`haproxy_backend_current_queue > 0` for 30 seconds is the earliest reliable signal
that JA4proxy is at capacity. It belongs in the attack-detection alert group.

HAProxy also exposes:
- `haproxy_frontend_current_sessions` / `haproxy_frontend_limit_sessions` — session
  limit approach (alert at 80%, critical at 90%)
- `haproxy_server_status` — individual backend server UP/DOWN
- `haproxy_server_connection_errors_total` — connection failures to proxy backends
- `haproxy_frontend_connections_rate` — sessions/s entering the stack (OS-level view)

The HAProxy exporter (`prom/haproxy-exporter`) scrapes HAProxy's stats endpoint on
`:8404` (already exposed in `docker/docker-compose.poc.yml`) and emits Prometheus metrics.

### 2.5 Load Average vs CPU % — Why Both Matter

`CPU %` measures how busy the processors are. `Load average` measures how many
processes are *waiting* — for CPU, for disk I/O, for network. They answer different
questions:

| Scenario | CPU % | Load avg |
|---|---|---|
| CPU-bound attack (scoring loop saturated) | High | High |
| I/O-bound (Redis AOF fsync + log writes) | Moderate | High |
| Waiting on DNS/AbuseIPDB (async, non-blocking) | Low | Low |
| Memory pressure causing swap | Low–moderate | High |

**Normalized load** = `node_load1 / count(node_cpu_seconds_total{mode="idle"}) without(cpu)`

At 1.0, every CPU core has exactly one process waiting. At 2.0, there is a queue. 
Alert at > 0.8 (warning) and > 1.5 (critical). Show load1, load5, and load15 together
to distinguish spikes (load1 high, load15 normal) from sustained pressure.

### 2.6 File Descriptor Exhaustion

Each active connection through the proxy uses at least **two file descriptors**:
one for the client socket, one for the backend socket. Under a connection flood:

1. FD count climbs rapidly.
2. When `node_filefd_allocated / node_filefd_maximum` exceeds ~80%, the OS begins
   returning `EMFILE` to new `accept()` calls.
3. New connections are refused at the OS level — **invisible to every other metric**.
   The connection-rate counter drops (no new connections) but the attack is still
   hitting the NIC.

Alert at > 70% (warning) and > 85% (critical). This should be on the critical path
for on-call escalation — FD exhaustion can cause a complete service outage silently.

### 2.7 CPU Throttling Is More Actionable Than Raw CPU %

Docker CPU limits work via CFS (Completely Fair Scheduler) quotas. When a container
exhausts its quota in a scheduling period, it is **throttled** — suspended until the
next period (usually 100ms later).

`container_cpu_cfs_throttled_seconds_total` tracks the total time spent throttled.
The throttle ratio is:
```
rate(container_cpu_cfs_throttled_seconds_total[2m])
/ rate(container_cpu_usage_seconds_total[2m])
```

A 20% throttle ratio means the container is suspended for 20ms out of every 100ms.
This translates directly to connection latency spikes. A container can be heavily
throttled even when the *host* CPU% looks healthy — the host has capacity, but the
container's quota is too tight.

Alert when throttle ratio > 20% (warning) and > 50% (critical) for proxy or Redis.

### 2.8 Network Packet Rate vs Byte Rate — SYN Flood Signature

A SYN flood sends many small packets. The signature is:

- `node_network_receive_packets_total` — high packet rate
- `node_network_receive_bytes_total` — low byte rate
- Average packet size = bytes/s ÷ packets/s → close to minimum TCP packet (~60–80 bytes)

Normal HTTPS traffic has large average packet size (1400+ bytes, filling MTU).
A SYN flood or amplification attack looks like: packets/s high but bytes/packet low.

Add a panel showing both bytes/s and packets/s on the same axis, with a derived
metric for average packet size. A rapid divergence between the two is a stronger
attack signal than either alone.

Also track NIC-level drops:
- `node_network_receive_drop_total` — packets dropped at NIC (ring buffer overflow)
- `node_network_transmit_drop_total` — packets dropped on transmit

NIC drops occur *before* HAProxy. If this counter increases under load, the NIC is
saturated and connections are being lost before any application layer sees them.

### 2.9 TCP Socket State Signals

`node_sockstat_*` metrics give OS-level socket state counts. These fire earlier than
application-layer metrics and reveal attack patterns before the proxy reports them.

| Metric | What it signals |
|---|---|
| `node_sockstat_TCP_tw` | TIME_WAIT count. Spikes *before* conn/s when an attack starts (terminated connections pile up before new ones are counted). |
| `node_sockstat_TCP_alloc` | All allocated TCP sockets. Rising steadily = connection accumulation. |
| `node_sockstat_TCP_orphan` | Sockets with no file descriptor. Should be near zero. High = kernel connection leak or FIN flood. |
| `node_netstat_Tcp_AttemptFails` | TCP connection attempts that failed at OS level (SYN timeouts, RST responses). Indicator of SYN flood absorption. |
| `node_netstat_Tcp_RetransSegs` | TCP retransmissions. High = network congestion or RST injection. |

A TIME_WAIT spike (`node_sockstat_TCP_tw`) 30–60 seconds before `ConnectionRateSpike`
fires is the earliest attack signal in this stack.

### 2.10 Entropy Depletion

TLS handshakes consume kernel entropy (`/dev/urandom` draws from the same pool as
`/dev/random`). Under sustained high connection rates, entropy can be depleted.

When `node_entropy_available_bytes < 256`:
- New TLS contexts may stall waiting for entropy to be replenished.
- Connection setup latency increases across all new TLS sessions.
- This is silent — no error is logged; connections just take longer.

Alert at < 512 bytes. The remediation is to ensure `rng-tools` or `haveged` is
running on the host, or to use `getrandom(2)` (Linux 3.17+) which avoids blocking.

### 2.11 Inode Exhaustion

Disk *space* and disk *inodes* are separate resources. A filesystem can be 0% full
by space but 100% full by inodes if many small files exist.

High log write rates (one file per request, rotated frequently) are the most common
cause in proxy deployments. When inodes are exhausted, new files cannot be created —
this means log writes fail, Redis AOF cannot create new files on rotation, and
`tmp` writes from any service fail silently.

Alert at < 20% inodes free (warning) and < 10% (critical):
```promql
node_filesystem_files_free{fstype!~"tmpfs|devtmpfs"}
/ node_filesystem_files{fstype!~"tmpfs|devtmpfs"} * 100 < 20
```

### 2.12 Proactive Alerting — Prediction and SLO Burn Rate

**Disk fill prediction:**
```promql
predict_linear(node_filesystem_avail_bytes{fstype!~"tmpfs|devtmpfs"}[6h], 86400) < 0
```
"At the current rate of change over the last 6 hours, this filesystem will be full
within 24 hours." More actionable than "disk is 85% full" because it tells the
operator *when* to act, not just *that* something is wrong.

**Container memory growth prediction:**
```promql
predict_linear(
  container_memory_working_set_bytes{name="redis"}[1h], 3600
) > container_spec_memory_limit_bytes{name="redis"}
```
"Redis memory is on track to hit its limit within one hour." This fires before
the `ContainerMemoryHigh` alert and gives time to act (flush keys, expand limit)
before an OOM kill occurs.

**SLO burn rate:**
Threshold-based alerting misses brownouts where the proxy is degraded but not
fully down. A burn-rate alert fires based on *how fast* the error budget is being
consumed. Using a 5-minute fast burn:
```promql
# Fast burn (5m): consuming budget at >14.4× normal rate
(1 - avg_over_time(up{job="ja4proxy"}[5m])) > 0.001
```
For a 99.9% monthly SLO, a 5m window of 0.1% errors represents 14.4× the allowed
burn rate. This fires on sustained partial outages that threshold-only alerts miss.

### 2.13 Recording Rules for Dashboard Performance

The existing `recording_rules.yml` references stale metric names (`ja4_requests_total`,
`ja4_blocked_requests_total`) that do not exist — the correct names are
`ja4proxy_connections_total`. This phase fixes the stale recording rules and adds
new ones for the infrastructure metrics to keep dashboard query times low:

```yaml
# New recording rules to add
- record: ja4proxy:cpu_utilization:pct
  expr: 100 - (avg(rate(node_cpu_seconds_total{mode="idle"}[2m])) * 100)

- record: ja4proxy:load_normalized
  expr: node_load1 / count(node_cpu_seconds_total{mode="idle"}) without (cpu)

- record: ja4proxy:filefd_utilization:pct
  expr: node_filefd_allocated / node_filefd_maximum * 100

- record: ja4proxy:container_mem_pct
  expr: >
    container_memory_working_set_bytes
    / clamp_min(container_spec_memory_limit_bytes, 1) * 100

- record: ja4proxy:container_cpu_throttle_ratio
  expr: >
    rate(container_cpu_cfs_throttled_seconds_total[2m])
    / clamp_min(rate(container_cpu_usage_seconds_total[2m]), 1e-6)
```

Also fix stale rules in the existing `ja4proxy_aggregations` and
`ja4proxy_performance` groups to use `ja4proxy_connections_total` instead of the
non-existent `ja4_requests_total` and `ja4_blocked_requests_total`.

### 2.14 Alert Routing — Where Does the Alert Go?

Routing is already defined in `monitoring/alertmanager/alertmanager.yml`:

```
Alert fires
    │
    ├── severity=critical, alert_type=infrastructure  → ops-team
    │     email: ops@example.com + Slack: #ops-alerts
    │
    ├── severity=critical, alert_type=ddos           → oncall-pager (PagerDuty)
    │                                                  AND continues → ops-team
    │
    ├── severity=warning, any alert_type             → ops-team
    │     (group_interval 5m, repeat 3h)
    │
    └── severity=info                                → audit-log (SIEM webhook)
```

Endpoints in `alertmanager.yml` are placeholder values — deployment-time substitution.
The routing logic is correct; credentials are not. This phase adds a new inhibition rule:

```yaml
# Host-level saturation suppresses per-container alerts — same root cause
- source_match_re:
    alertname: 'Node(Critical)(CPU|Memory)'
  target_match:
    alert_type: infrastructure
  equal: ['cluster']
```

### 2.15 Container Names in cAdvisor Metric Labels

cAdvisor uses Docker container names in the `name` label. The mapping:

| compose service | cAdvisor `name=` value |
|---|---|
| `proxy` | `proxy` (no container_name set — uses service name) |
| `redis` | `redis` |
| `analytics` | `analytics` |
| `haproxy` | `haproxy` |
| Monitoring services | `ja4proxy-prometheus-monitoring`, `ja4proxy-alertmanager`, `ja4proxy-grafana`, `ja4proxy-loki`, `ja4proxy-promtail`, `ja4proxy-node-exporter`, `ja4proxy-redis-exporter`, `ja4proxy-cadvisor` |

All alert rules targeting JA4proxy-owned containers must use:
`name=~"ja4proxy.*|proxy|redis|analytics|haproxy"`

---

## 3. Multi-Agent Team

Five agents with non-overlapping file ownership. Can run in parallel.

### Agent A — Infrastructure Foundation

**Branch:** `claude/phase-87-infra-foundation`

**Owns:**
- `docker/docker-compose.monitoring.yml` — add cAdvisor + HAProxy exporter
- `monitoring/prometheus/prometheus.yml` — add cAdvisor + HAProxy scrape jobs

**cAdvisor service:**
```yaml
  cadvisor:
    image: gcr.io/cadvisor/cadvisor:v0.47.2
    container_name: ja4proxy-cadvisor
    privileged: true
    devices:
      - /dev/kmsg:/dev/kmsg
    volumes:
      - /:/rootfs:ro
      - /var/run:/var/run:rw
      - /sys:/sys:ro
      - /var/lib/docker:/var/lib/docker:ro
      - /dev/disk/:/dev/disk:ro
    restart: unless-stopped
    networks:
      - ja4proxy-monitoring
    security_opt:
      - no-new-privileges:true
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.5'
```

`privileged: true` is required — cAdvisor reads cgroupfs to attribute container stats.

**HAProxy exporter service:**
```yaml
  haproxy-exporter:
    image: prom/haproxy-exporter:v0.15.0
    container_name: ja4proxy-haproxy-exporter
    command:
      - '--haproxy.scrape-uri=http://haproxy:8404/stats?stats;csv'
    restart: unless-stopped
    networks:
      - ja4proxy-monitoring
      - ja4proxy_ja4proxy-backend
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    deploy:
      resources:
        limits:
          memory: 64M
          cpus: '0.2'
```

This requires HAProxy to have stats configured. Verify `config/haproxy.cfg` exposes
the stats endpoint on `:8404` with CSV output (it already does based on the port
mapping in `docker/docker-compose.poc.yml`).

**cAdvisor scrape job (prometheus.yml):**
```yaml
  - job_name: 'cadvisor'
    scrape_interval: 15s
    scrape_timeout: 10s
    static_configs:
      - targets: ['cadvisor:8080']
        labels:
          service: cadvisor
          role: container-metrics
    metric_relabel_configs:
      # Drop per-device blkio series — high cardinality, unused
      - source_labels: [__name__]
        regex: 'container_(blkio_device|tasks_state).*'
        action: drop
      # Drop the host cgroup root (name="") — covered by node-exporter
      - source_labels: [name]
        regex: ''
        action: drop
```

**HAProxy exporter scrape job:**
```yaml
  - job_name: 'haproxy'
    scrape_interval: 15s
    static_configs:
      - targets: ['haproxy-exporter:9101']
        labels:
          service: haproxy
          role: load-balancer
```

---

### Agent B — Infrastructure Dashboard

**Branch:** `claude/phase-87-infra-dashboard`

**Owns:**
- `monitoring/grafana/dashboards/ja4proxy-infrastructure.json` — new file
- `monitoring/grafana/provisioning/dashboards/default.yml` — add new dashboard path
- `monitoring/grafana/dashboards/ja4proxy-overview.json` — add link to infra dashboard (`links` array only)

**Dashboard layout — ≤5 viewport heights:**

```
╔══ Fleet Status (y=0, h=1 row header) ═══════════════════════════════╗
║ [proxy] [redis] [analytics] [haproxy] [grafana] [prometheus] [loki]  ║
║ [alertmanager] [promtail] [node-exp] [redis-exp]   (mem% each, h=4) ║
╚═════════════════════════════════════════════════════════════════════╝

╔══ Host Resources (y=5, h=1 row header) ══════════════════════════════╗
║ [CPU%] [Mem%] [Load norm] [Disk%] [FD%] [Entropy]   (stats, h=4)    ║
║ [CPU & Memory history (w=8)] [Load avg 1/5/15 (w=8)] [FD+Entropy (w=8)]  (h=8) ║
╚═════════════════════════════════════════════════════════════════════╝

╔══ Network & TCP Stack (y=17, h=1 row header) ═════════════════════════╗
║ [Net Rx/Tx bytes/s (w=12)] [Packets/s vs Bytes/s (w=12)]  (h=8)     ║
║ [TCP socket states (w=12)] [NIC errors & drops (w=12)]    (h=8)     ║
╚═════════════════════════════════════════════════════════════════════╝

╔══ HAProxy (y=33, h=1 row header) ════════════════════════════════════╗
║ [Sessions/s] [Queue depth] [Session limit%] [Backend health]  (stats, h=4) ║
║ [Sessions + queue history (w=12)] [Connection errors (w=12)]  (h=8) ║
╚═════════════════════════════════════════════════════════════════╝

╔══ Container Drill-Down  [$container ▼] (y=45, h=1 row header) ═══════╗
║ [CPU%] [CPU throttle%] [Mem%] [OOM events] [Restarts]  (stats, h=4) ║
║ [CPU + throttle history (w=12)] [Memory history (w=12)]  (h=8)      ║
║ [Disk I/O (w=12)] [Network bytes + errors (w=12)]        (h=8)      ║
╚═════════════════════════════════════════════════════════════════════╝

╔══ Attack Detection (y=65, h=1 row header) ════════════════════════════╗
║ [Connection rate: live vs 1h baseline (w=24)]              (h=8)     ║
║ [Packets/s vs bytes/s (SYN flood view, w=12)] [TIME_WAIT + orphans (w=12)]  (h=8) ║
║ [New unique IPs/s (w=12)] [Block rate + HAProxy queue (w=12)]  (h=8) ║
╚═════════════════════════════════════════════════════════════════════╝
```

Total height: ~89 grid units ≈ 4.5 viewport heights. Within budget.

**Template variable:**
```json
{
  "name": "container",
  "type": "query",
  "datasource": {"type": "prometheus", "uid": "PBFA97CFB590B2093"},
  "definition": "label_values(container_memory_working_set_bytes{name!~\".+_[0-9]+\"}, name)",
  "refresh": 2,
  "sort": 1,
  "current": {"text": "proxy", "value": "proxy"}
}
```

**Key PromQL expressions:**

```promql
# Normalized load average
node_load1 / count(node_cpu_seconds_total{mode="idle"}) without (cpu)

# File descriptor utilisation %
node_filefd_allocated / node_filefd_maximum * 100

# Container CPU throttle ratio %
rate(container_cpu_cfs_throttled_seconds_total{name=~"$container"}[2m])
/ clamp_min(rate(container_cpu_usage_seconds_total{name=~"$container"}[2m]), 1e-6) * 100

# Average packet size (bytes/packet) — SYN flood shows near 60-80 bytes
rate(node_network_receive_bytes_total{device!~"lo|docker.*|br-.*"}[2m])
/ clamp_min(rate(node_network_receive_packets_total{device!~"lo|docker.*|br-.*"}[2m]), 1)

# TIME_WAIT count (leading attack indicator)
node_sockstat_TCP_tw

# TCP orphan sockets (should be near zero)
node_sockstat_TCP_orphan

# HAProxy backend queue depth
haproxy_backend_current_queue{proxy="ja4proxy"}

# HAProxy session limit approach %
haproxy_frontend_current_sessions / haproxy_frontend_limit_sessions * 100
```

**Threshold lines on the Connection Rate panel:**
Use `fieldConfig.defaults.custom.thresholdsStyle.mode = "line+area"` with:
- Yellow at 200 conn/s (approaching Python proxy ceiling)
- Red at 600 conn/s (absolute capacity alert threshold)

The dashed grey baseline series uses:
```promql
avg_over_time(sum(rate(ja4proxy_connections_total[1m]))[1h:1m])
```

**Alert annotations:** Enable in dashboard JSON:
```json
"annotations": {
  "list": [
    {
      "builtIn": 1,
      "datasource": {"type": "grafana"},
      "enable": true,
      "hide": false,
      "iconColor": "red",
      "name": "Alerts",
      "type": "alert"
    }
  ]
}
```
This overlays alert firing/resolving events as vertical bands on all timeseries panels.

---

### Agent C — Alert Rules, Recording Rules & Runbook

**Branch:** `claude/phase-87-alerts`

**Owns:**
- `monitoring/prometheus/alerts.yml` — append new groups only
- `monitoring/prometheus/recording_rules.yml` — fix stale rules + add new group
- `monitoring/alertmanager/alertmanager.yml` — add one inhibition rule
- `docs/runbooks/infrastructure.md` — new file

**Fix stale recording rules** — replace the `ja4proxy_aggregations` and
`ja4proxy_performance` groups which reference non-existent `ja4_requests_total` and
`ja4_blocked_requests_total` metrics. Use `ja4proxy_connections_total` instead.
Do not change the group names or any rule names — only the `expr` fields.

**New recording rules group to append:**
```yaml
  - name: ja4proxy_infra_aggregations
    interval: 30s
    rules:
      - record: ja4proxy:cpu_utilization:pct
        expr: 100 - (avg(rate(node_cpu_seconds_total{mode="idle"}[2m])) * 100)

      - record: ja4proxy:load_normalized
        expr: >
          node_load1
          / count(node_cpu_seconds_total{mode="idle"}) without (cpu)

      - record: ja4proxy:filefd_utilization:pct
        expr: node_filefd_allocated / node_filefd_maximum * 100

      - record: ja4proxy:container_mem_pct
        expr: >
          container_memory_working_set_bytes
          / clamp_min(container_spec_memory_limit_bytes, 1) * 100

      - record: ja4proxy:container_cpu_throttle_ratio
        expr: >
          rate(container_cpu_cfs_throttled_seconds_total[2m])
          / clamp_min(rate(container_cpu_usage_seconds_total[2m]), 1e-6)

      - record: ja4proxy:network_avg_pkt_size_bytes
        expr: >
          rate(node_network_receive_bytes_total{device!~"lo|docker.*|br-.*"}[2m])
          / clamp_min(
              rate(node_network_receive_packets_total{device!~"lo|docker.*|br-.*"}[2m]),
              1
            )
```

**New alert groups to append to `alerts.yml`:**

#### Group `ja4proxy_infrastructure` (interval: 60s)

```yaml
  - name: ja4proxy_infrastructure
    interval: 60s
    rules:

      # ── Host CPU ───────────────────────────────────────────────────────────
      - alert: NodeHighCPU
        expr: ja4proxy:cpu_utilization:pct > 80
        for: 5m
        labels: {severity: warning, component: infrastructure, alert_type: infrastructure}
        annotations:
          summary: "Host CPU above 80% ({{ $value | humanize }}%)"
          description: >
            CPU has exceeded 80% for 5 minutes. A large attack or misconfigured
            signal module is the most likely cause. Check block rate and tarpit count.
          runbook_url: "docs/runbooks/infrastructure.md#host-cpu-high"

      - alert: NodeCriticalCPU
        expr: ja4proxy:cpu_utilization:pct > 95
        for: 2m
        labels: {severity: critical, component: infrastructure, alert_type: infrastructure}
        annotations:
          summary: "Host CPU saturated ({{ $value | humanize }}%)"
          description: >
            CPU above 95% for 2 minutes. Proxy will begin dropping connections.
            Consider upstream HAProxy rate limiting or lowering the scoring dial.
          runbook_url: "docs/runbooks/infrastructure.md#host-cpu-critical"

      # ── Load Average ───────────────────────────────────────────────────────
      - alert: NodeHighLoad
        expr: ja4proxy:load_normalized > 0.8
        for: 5m
        labels: {severity: warning, component: infrastructure, alert_type: infrastructure}
        annotations:
          summary: "Normalised load above 0.8 ({{ $value | humanize }}×)"
          description: >
            Load average (normalised by CPU count) above 0.8 for 5 minutes.
            Unlike CPU%, high load also catches I/O wait and memory pressure.
            Check disk I/O (Redis AOF fsync), DNS resolution queuing, and swap.
          runbook_url: "docs/runbooks/infrastructure.md#high-load"

      - alert: NodeCriticalLoad
        expr: ja4proxy:load_normalized > 1.5
        for: 2m
        labels: {severity: critical, component: infrastructure, alert_type: infrastructure}
        annotations:
          summary: "Normalised load above 1.5 ({{ $value | humanize }}×)"
          description: >
            Severe load saturation. Every CPU core has more than 1.5 tasks queued.
            Proxy latency will degrade. Investigate I/O bottlenecks before CPU.
          runbook_url: "docs/runbooks/infrastructure.md#critical-load"

      # ── Host Memory ────────────────────────────────────────────────────────
      - alert: NodeHighMemory
        expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100 > 85
        for: 5m
        labels: {severity: warning, component: infrastructure, alert_type: infrastructure}
        annotations:
          summary: "Host memory above 85% ({{ $value | humanize }}%)"
          description: >
            Available memory is low. If Redis has no memory limit, it may be the
            cause. OOM kill risk is elevated for all containers.
          runbook_url: "docs/runbooks/infrastructure.md#host-memory-high"

      - alert: NodeCriticalMemory
        expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100 > 95
        for: 2m
        labels: {severity: critical, component: infrastructure, alert_type: infrastructure}
        annotations:
          summary: "Host memory near exhaustion ({{ $value | humanize }}%)"
          description: >
            Memory above 95%. OOM kill of proxy or Redis is imminent.
            If Redis is killed, the proxy fails open — all connections are allowed.
          runbook_url: "docs/runbooks/infrastructure.md#host-memory-critical"

      # ── File Descriptors ───────────────────────────────────────────────────
      - alert: NodeFileDescriptorsHigh
        expr: ja4proxy:filefd_utilization:pct > 70
        for: 2m
        labels: {severity: warning, component: infrastructure, alert_type: infrastructure}
        annotations:
          summary: "File descriptors above 70% ({{ $value | humanize }}% of {{ node_filefd_maximum }} max)"
          description: >
            Each active connection uses ≥2 file descriptors (client + backend socket).
            At ~80%, new accept() calls will return EMFILE and connections will be
            refused at OS level — silently, without any application log entry.
          runbook_url: "docs/runbooks/infrastructure.md#file-descriptors"

      - alert: NodeFileDescriptorsCritical
        expr: ja4proxy:filefd_utilization:pct > 85
        for: 1m
        labels: {severity: critical, component: infrastructure, alert_type: infrastructure}
        annotations:
          summary: "File descriptors critical ({{ $value | humanize }}%)"
          description: >
            OS is likely already refusing new connections with EMFILE.
            Connection rate will drop (no new accepts) while the attack continues.
            Increase fs.file-max sysctl or reduce active connections immediately.
          runbook_url: "docs/runbooks/infrastructure.md#file-descriptors-critical"

      # ── Disk Space ─────────────────────────────────────────────────────────
      - alert: NodeDiskSpaceLow
        expr: >
          (1 - (
            node_filesystem_avail_bytes{fstype!~"tmpfs|devtmpfs|overlay|squashfs"}
            / node_filesystem_size_bytes{fstype!~"tmpfs|devtmpfs|overlay|squashfs"}
          )) * 100 > 80
        for: 5m
        labels: {severity: warning, component: infrastructure, alert_type: infrastructure}
        annotations:
          summary: "Disk {{ $labels.mountpoint }} above 80% ({{ $value | humanize }}%)"
          description: >
            Disk filling. Common causes: log growth, Redis RDB snapshots, backup
            retention not running. Check log rotation and Redis appendonly config.
          runbook_url: "docs/runbooks/infrastructure.md#disk-low"

      - alert: NodeDiskSpaceCritical
        expr: >
          (1 - (
            node_filesystem_avail_bytes{fstype!~"tmpfs|devtmpfs|overlay|squashfs"}
            / node_filesystem_size_bytes{fstype!~"tmpfs|devtmpfs|overlay|squashfs"}
          )) * 100 > 90
        for: 5m
        labels: {severity: critical, component: infrastructure, alert_type: infrastructure}
        annotations:
          summary: "Disk {{ $labels.mountpoint }} above 90% ({{ $value | humanize }}%)"
          description: >
            Disk critically full. Redis AOF/RDB writes and log rotation will fail.
            Redis may crash. Immediate remediation required.
          runbook_url: "docs/runbooks/infrastructure.md#disk-critical"

      # ── Inode Exhaustion ───────────────────────────────────────────────────
      - alert: NodeInodesLow
        expr: >
          node_filesystem_files_free{fstype!~"tmpfs|devtmpfs|overlay|squashfs"}
          / node_filesystem_files{fstype!~"tmpfs|devtmpfs|overlay|squashfs"} * 100 < 20
        for: 10m
        labels: {severity: warning, component: infrastructure, alert_type: infrastructure}
        annotations:
          summary: "Inodes below 20% free on {{ $labels.mountpoint }}"
          description: >
            Inode exhaustion is independent of disk space. When inodes run out,
            new files cannot be created — Redis AOF rotation, log writes, and
            tmpfile operations all fail even if disk space is available.
          runbook_url: "docs/runbooks/infrastructure.md#inodes"

      # ── Entropy ────────────────────────────────────────────────────────────
      - alert: NodeEntropyLow
        expr: node_entropy_available_bytes < 512
        for: 2m
        labels: {severity: warning, component: infrastructure, alert_type: infrastructure}
        annotations:
          summary: "Kernel entropy pool below 512 bytes ({{ $value }} bytes)"
          description: >
            TLS handshakes consume entropy. Under heavy load, entropy can be
            depleted and new TLS contexts stall waiting for replenishment.
            Ensure rng-tools or haveged is running on the host.
          runbook_url: "docs/runbooks/infrastructure.md#entropy"
```

#### Group `ja4proxy_container` (interval: 60s)

```yaml
  - name: ja4proxy_container
    interval: 60s
    rules:

      - alert: ContainerOOMKilled
        expr: >
          increase(container_oom_events_total{
            name=~"ja4proxy.*|proxy|redis|analytics"
          }[5m]) > 0
        for: 0m
        labels: {severity: critical, component: infrastructure, alert_type: infrastructure}
        annotations:
          summary: "OOM kill in container {{ $labels.name }}"
          description: >
            {{ $labels.name }} was OOM-killed. If proxy: active connections dropped.
            If Redis: proxy fails open until Redis restarts and state is rebuilt.
          runbook_url: "docs/runbooks/infrastructure.md#oom-kill"

      - alert: ContainerRestartLoop
        expr: >
          changes(container_start_time_seconds{
            name=~"ja4proxy.*|proxy|redis|analytics"
          }[30m]) >= 2
        for: 0m
        labels: {severity: critical, component: infrastructure, alert_type: infrastructure}
        annotations:
          summary: "Container {{ $labels.name }} restarting repeatedly ({{ $value }} times in 30m)"
          description: >
            Crash-restart loop detected. Check container logs. If the proxy is
            restarting, traffic is unprotected during restart intervals.
          runbook_url: "docs/runbooks/infrastructure.md#restart-loop"

      - alert: ContainerMemoryHigh
        expr: >
          ja4proxy:container_mem_pct{
            name=~"ja4proxy.*|proxy|redis|analytics"
          } > 85
        for: 5m
        labels: {severity: warning, component: infrastructure, alert_type: infrastructure}
        annotations:
          summary: "Container {{ $labels.name }} memory above 85% of limit"
          description: >
            {{ $labels.name }} is using {{ $value | humanize }}% of its memory limit.
            OOM kill risk is elevated. Review memory limit and recent growth.
          runbook_url: "docs/runbooks/infrastructure.md#container-memory"

      - alert: ContainerCPUThrottleHigh
        # Container is being CPU-throttled — quota too tight for current load.
        # Direct cause of connection latency spikes.
        expr: >
          ja4proxy:container_cpu_throttle_ratio{
            name=~"proxy|redis|analytics"
          } > 0.20
        for: 5m
        labels: {severity: warning, component: infrastructure, alert_type: infrastructure}
        annotations:
          summary: "Container {{ $labels.name }} CPU throttled {{ $value | humanizePercentage }}"
          description: >
            {{ $labels.name }} is spending {{ $value | humanizePercentage }} of its time
            suspended waiting for CPU quota. This directly causes connection latency spikes
            even when host CPU% looks healthy. Increase the container's cpus limit.
          runbook_url: "docs/runbooks/infrastructure.md#cpu-throttle"
```

#### Group `ja4proxy_haproxy` (interval: 30s)

```yaml
  - name: ja4proxy_haproxy
    interval: 30s
    rules:

      - alert: HAProxyBackendQueueing
        # Connections are waiting for a proxy backend slot — proxy is at capacity.
        # This fires BEFORE ConnectionRateSustainedHigh because HAProxy absorbs
        # the surge while the proxy catches up.
        expr: haproxy_backend_current_queue{proxy="ja4proxy"} > 0
        for: 30s
        labels: {severity: warning, component: haproxy, alert_type: infrastructure}
        annotations:
          summary: "HAProxy queuing {{ $value }} connections to JA4proxy backend"
          description: >
            JA4proxy backend is at capacity. HAProxy is holding connections in queue.
            This is the earliest reliable saturation signal. Check proxy CPU and
            active connection count. Consider raising HAProxy backend maxconn.
          runbook_url: "docs/runbooks/infrastructure.md#haproxy-queue"

      - alert: HAProxySessionLimitApproaching
        expr: >
          haproxy_frontend_current_sessions
          / haproxy_frontend_limit_sessions * 100 > 80
        for: 2m
        labels: {severity: warning, component: haproxy, alert_type: infrastructure}
        annotations:
          summary: "HAProxy session limit above 80% ({{ $value | humanize }}%)"
          description: >
            HAProxy is approaching its maximum session count. When the limit is
            reached, new connections are rejected at the load balancer with a 503.
          runbook_url: "docs/runbooks/infrastructure.md#haproxy-sessions"

      - alert: HAProxyBackendDown
        expr: haproxy_server_status{proxy="ja4proxy"} == 0
        for: 1m
        labels: {severity: critical, component: haproxy, alert_type: infrastructure}
        annotations:
          summary: "HAProxy backend {{ $labels.server }} is DOWN"
          description: >
            HAProxy has marked JA4proxy backend {{ $labels.server }} as DOWN.
            Traffic is not being forwarded to this instance.
          runbook_url: "docs/runbooks/infrastructure.md#haproxy-backend-down"

      - alert: HAProxyConnectionErrorRate
        expr: rate(haproxy_server_connection_errors_total{proxy="ja4proxy"}[2m]) > 1
        for: 2m
        labels: {severity: warning, component: haproxy, alert_type: infrastructure}
        annotations:
          summary: "HAProxy connection errors to JA4proxy ({{ $value | humanize }}/s)"
          description: >
            HAProxy is failing to establish connections to JA4proxy backends.
            May indicate proxy crash-restart loop or TCP backlog overflow.
          runbook_url: "docs/runbooks/infrastructure.md#haproxy-connection-errors"
```

#### Group `ja4proxy_capacity` (interval: 60s)

```yaml
  - name: ja4proxy_capacity
    interval: 60s
    rules:

      - alert: DiskWillFillIn24h
        expr: >
          predict_linear(
            node_filesystem_avail_bytes{fstype!~"tmpfs|devtmpfs|overlay|squashfs"}[6h],
            86400
          ) < 0
        for: 30m
        labels: {severity: warning, component: infrastructure, alert_type: infrastructure}
        annotations:
          summary: "{{ $labels.mountpoint }} predicted full within 24h"
          description: >
            Based on the growth rate over the last 6 hours, {{ $labels.mountpoint }}
            will run out of space within 24 hours. Check log rotation schedule and
            Redis RDB/AOF file sizes. Act now — not when the threshold alert fires.
          runbook_url: "docs/runbooks/infrastructure.md#disk-prediction"

      - alert: RedisMemoryWillHitLimitIn1h
        expr: >
          predict_linear(
            container_memory_working_set_bytes{name="redis"}[1h],
            3600
          ) > on() group_left()
            container_spec_memory_limit_bytes{name="redis"}
        for: 10m
        labels: {severity: warning, component: infrastructure, alert_type: infrastructure}
        annotations:
          summary: "Redis memory predicted to hit limit within 1 hour"
          description: >
            Redis working set is growing and will hit its configured memory limit
            within 1 hour. If maxmemory policy is noeviction, new writes will fail.
            If allkeys-lru, eviction will degrade scoring cache hit rate.
          runbook_url: "docs/runbooks/infrastructure.md#redis-memory-growth"

      - alert: ProxyAvailabilitySLOBurn
        # Fast burn rate: consuming 30-day 99.9% SLO budget at >14.4× normal rate.
        # Fires on brownouts (probe occasionally fails) that threshold alerts miss.
        expr: (1 - avg_over_time(up{job="ja4proxy"}[5m])) > 0.001
        for: 2m
        labels: {severity: critical, component: ja4proxy, alert_type: infrastructure}
        annotations:
          summary: "JA4proxy availability SLO burn rate critical"
          description: >
            Fast burn: proxy is unavailable for >0.1% of the last 5 minutes,
            consuming the 30-day error budget at >14.4× the allowed rate.
            This fires on partial outages and brownouts that up==0 misses.
          runbook_url: "docs/runbooks/infrastructure.md#slo-burn"
```

#### Group `ja4proxy_attack_detection` (interval: 30s)

```yaml
  - name: ja4proxy_attack_detection
    interval: 30s
    rules:

      - alert: ConnectionRateSpike
        # Catches sudden bursts from a normal baseline.
        expr: |
          sum(rate(ja4proxy_connections_total[1m]))
          >= 3 * clamp_min(
            avg_over_time(sum(rate(ja4proxy_connections_total[1m]))[1h:1m]),
            0.1
          )
        for: 2m
        labels: {severity: warning, component: ja4proxy, alert_type: ddos}
        annotations:
          summary: "Connection rate 3× above 1h baseline ({{ $value | humanize }} conn/s)"
          description: >
            Rate has been ≥3× its 1-hour rolling average for 2 minutes.
            Open the Infrastructure & Attack dashboard to compare live rate vs baseline.
            Check block/ban rate. Consider raising the dial.
          runbook_url: "docs/runbooks/infrastructure.md#connection-rate-spike"

      - alert: ConnectionRateSustainedHigh
        # Absolute floor — catches attacks that started >1h ago.
        # 600/s ≈ 1.7× Python proxy ceiling (~350/s); revisit when Go proxy (Phase 15) ships.
        expr: sum(rate(ja4proxy_connections_total[1m])) > 600
        for: 5m
        labels: {severity: critical, component: ja4proxy, alert_type: ddos}
        annotations:
          summary: "Connection rate sustained above 600/s ({{ $value | humanize }})"
          description: >
            >600 new TLS connections/second for 5 minutes. Python proxy ceiling
            is ~350/s — service degradation is likely. Consider upstream HAProxy
            rate limiting immediately.
          runbook_url: "docs/runbooks/infrastructure.md#connection-rate-sustained"

      - alert: HAProxyQueueSignalsCapacityAttack
        # HAProxy queue depth is the EARLIEST proxy saturation signal — it fires
        # before ConnectionRateSustainedHigh because HAProxy absorbs the burst.
        expr: haproxy_backend_current_queue{proxy="ja4proxy"} > 5
        for: 1m
        labels: {severity: warning, component: haproxy, alert_type: ddos}
        annotations:
          summary: "HAProxy queuing {{ $value }} connections — proxy at capacity under load"
          description: >
            HAProxy has >5 connections queued for JA4proxy. Combined with any
            connection rate increase, this indicates the proxy is saturated by
            incoming load. Check if block/ban rate is also elevated.
          runbook_url: "docs/runbooks/infrastructure.md#haproxy-queue-attack"

      - alert: SYNFloodIndicator
        # Small average packet size + high packet rate = SYN flood signature.
        # A normal HTTPS session averages ~1000+ bytes/packet (TLS record size).
        # SYN packets are 60-80 bytes. This alerts when the ratio drops near SYN-size.
        expr: ja4proxy:network_avg_pkt_size_bytes < 150
        for: 2m
        labels: {severity: warning, component: infrastructure, alert_type: ddos}
        annotations:
          summary: "Average inbound packet size {{ $value | humanize }} bytes — possible SYN flood"
          description: >
            Average inbound packet size has dropped to {{ $value | humanize }} bytes
            (normal HTTPS ≥1000 bytes/packet). This pattern is consistent with a
            SYN flood or small-packet amplification attack. Check NIC drop counters
            and node_netstat_Tcp_AttemptFails.
          runbook_url: "docs/runbooks/infrastructure.md#syn-flood"

      - alert: TimeWaitSpike
        # TIME_WAIT count spikes BEFORE conn/s when an attack starts — leading indicator.
        # Also signals rapid connection churn from scanning tools.
        expr: node_sockstat_TCP_tw > 5000
        for: 2m
        labels: {severity: warning, component: infrastructure, alert_type: ddos}
        annotations:
          summary: "TCP TIME_WAIT count above 5000 ({{ $value }})"
          description: >
            High TIME_WAIT count indicates rapid connection churn — many connections
            opening and closing quickly. This is a leading attack indicator; it
            precedes ConnectionRateSpike by 30-60 seconds. Check conn/s trend.
          runbook_url: "docs/runbooks/infrastructure.md#time-wait-spike"

      - alert: NICPacketDrops
        # Packets dropped at NIC ring buffer — traffic hitting the host before HAProxy.
        # If this fires, connections are being lost before any application layer sees them.
        expr: rate(node_network_receive_drop_total{device!~"lo|docker.*|br-.*"}[2m]) > 100
        for: 2m
        labels: {severity: warning, component: infrastructure, alert_type: ddos}
        annotations:
          summary: "NIC dropping {{ $value | humanize }} packets/s on {{ $labels.device }}"
          description: >
            Packets are being dropped at the NIC ring buffer on {{ $labels.device }}.
            This happens before HAProxy — the connection count metric underestimates
            the true incoming traffic. NIC is saturated or ring buffer is undersized.
          runbook_url: "docs/runbooks/infrastructure.md#nic-drops"

      - alert: NewUniqueIPsBurst
        expr: rate(ja4proxy_analytics_unique_ips_seen_total[5m]) > 50
        for: 3m
        labels: {severity: warning, component: analytics, alert_type: ddos}
        annotations:
          summary: "New unique source IPs at {{ $value | humanize }}/s — possible distributed attack"
          description: >
            >50 new unique source IPs/second for 3 minutes. Distinct from a single
            scanner — indicates a distributed botnet or coordinated scan campaign.
            Check beaconing suspects leaderboard and campaign detector.
          runbook_url: "docs/runbooks/infrastructure.md#distributed-attack"
```

---

### Agent D — Tests

**Branch:** `claude/phase-87-tests`

**Owns:**
- `tests/unit/test_infra_alerts.py` — new file
- `tests/unit/test_infra_dashboard.py` — new file
- `Makefile` — add `test-phase-87` at the bottom only

**Required tests:**

| Test | Assertion |
|---|---|
| `test_alerts_yaml_valid` | `alerts.yml` parses as valid YAML |
| `test_new_groups_present` | All 5 new groups exist in `alerts.yml` |
| `test_all_new_alerts_have_runbook_url` | Every rule in new groups has `runbook_url` |
| `test_all_new_alerts_have_alert_type` | Every rule in new groups has `alert_type` label |
| `test_existing_groups_unchanged` | Groups `ja4proxy_proxy`, `ja4proxy_redis`, `ja4proxy_security`, `ja4proxy_analytics` are byte-for-byte identical to pre-phase baseline |
| `test_connection_rate_spike_uses_clamp_min` | `ConnectionRateSpike` expr contains `clamp_min` — prevents startup false positives |
| `test_syn_flood_expr_uses_recording_rule` | `SYNFloodIndicator` references `ja4proxy:network_avg_pkt_size_bytes` |
| `test_oom_alert_fires_immediately` | `ContainerOOMKilled` has `for: 0m` |
| `test_recording_rules_yaml_valid` | `recording_rules.yml` parses as valid YAML |
| `test_new_recording_rule_group_present` | `ja4proxy_infra_aggregations` group exists |
| `test_stale_metrics_fixed` | `recording_rules.yml` contains no references to `ja4_requests_total` or `ja4_blocked_requests_total` |
| `test_dashboard_json_valid` | `ja4proxy-infrastructure.json` parses as valid JSON |
| `test_dashboard_has_container_variable` | Template variable named `container` present |
| `test_dashboard_has_all_six_row_sections` | Row panels: Fleet Status, Host Resources, Network & TCP Stack, HAProxy, Container Drill-Down, Attack Detection |
| `test_dashboard_alert_annotations_enabled` | `annotations.list` contains a Grafana alerts entry |
| `test_dashboard_links_to_security_overview` | `links` array references `/d/ja4proxy-overview/` |
| `test_no_infra_panels_in_overview` | `ja4proxy-overview.json` has no panel with id ≥ 70 |
| `test_cadvisor_scrape_job_present` | `prometheus.yml` contains `job_name: 'cadvisor'` |
| `test_haproxy_exporter_scrape_job_present` | `prometheus.yml` contains `job_name: 'haproxy'` |
| `test_cadvisor_drops_blkio_metrics` | cAdvisor scrape config has `metric_relabel_configs` dropping blkio series |
| `test_container_variable_excludes_numeric_suffix` | Variable query regex contains `name!~".+_[0-9]+"` |

---

### Agent E — Critical Review

**Branch:** `claude/phase-87-review`

After Agents A–D have pushed, Agent E reviews and produces `docs/phases/complete/PHASE_87_notes.md`.

**Critical checks:**

1. **Container name consistency** — every `name=~"..."` pattern in new alert rules
   matches actual service names from `docker/docker-compose.poc.yml` and
   `docker-compose.monitoring.yml`. Enumerate all patterns and cross-check.

2. **HAProxy stats endpoint** — verify `config/haproxy.cfg` exposes `/stats?stats;csv`
   on `:8404` (required by the HAProxy exporter). If not, flag and fix.

3. **Recording rule references** — alert rules using `ja4proxy:*` recording rule names
   match exactly the names defined in the new `ja4proxy_infra_aggregations` group.

4. **Division by zero guards** — every expression dividing by
   `container_spec_memory_limit_bytes` or a rate uses `clamp_min(..., 1)` or
   `clamp_min(..., 1e-6)` respectively.

5. **Stale recording rules fixed** — confirm `ja4_requests_total` and
   `ja4_blocked_requests_total` no longer appear anywhere in `recording_rules.yml`.

6. **Dashboard datasource UID** — all panels use `PBFA97CFB590B2093` (matches
   `monitoring/grafana/provisioning/datasources/prometheus.yml`).

7. **No duplicate panel IDs** — between `ja4proxy-overview.json` and
   `ja4proxy-infrastructure.json`.

8. **Threshold alignment** — `ConnectionRateSustainedHigh` alert threshold (600 conn/s)
   matches the red threshold line value in the dashboard attack panel.

9. **Image tags pinned** — cAdvisor `v0.47.2`, HAProxy exporter `v0.15.0`. Not `:latest`.

10. **Alert annotation labels format** — Grafana alert annotations use the correct
    format for Grafana 10.x (uid-based datasource, not string `"grafana"`).

---

## 4. Makefile Targets

Add at the bottom of `Makefile`. Do NOT edit existing targets.

```makefile
## Phase 87 targets
test-phase-87:
	python3 -m pytest tests/unit/test_infra_alerts.py tests/unit/test_infra_dashboard.py -v

test-phase-87-integration:
	@echo "Requires monitoring stack: cd docker && docker compose -f docker-compose.monitoring.yml up -d"
	@./tests/integration/phase-87/check_cadvisor_metrics.sh
	@./tests/integration/phase-87/check_haproxy_exporter.sh
```

---

## 5. Files Touched

| File | Agent | Change |
|---|---|---|
| `docker/docker-compose.monitoring.yml` | A | Add cAdvisor + HAProxy exporter services |
| `monitoring/prometheus/prometheus.yml` | A | Add cAdvisor + HAProxy exporter scrape jobs |
| `monitoring/grafana/dashboards/ja4proxy-infrastructure.json` | B | New file |
| `monitoring/grafana/provisioning/dashboards/default.yml` | B | Add new dashboard path |
| `monitoring/grafana/dashboards/ja4proxy-overview.json` | B | Add link to infra dashboard (`links` only) |
| `monitoring/prometheus/alerts.yml` | C | Append 5 new groups |
| `monitoring/prometheus/recording_rules.yml` | C | Fix stale rules + append new group |
| `monitoring/alertmanager/alertmanager.yml` | C | Add host-saturation inhibition rule |
| `docs/runbooks/infrastructure.md` | C | New file |
| `tests/unit/test_infra_alerts.py` | D | New file |
| `tests/unit/test_infra_dashboard.py` | D | New file |
| `Makefile` | D | Add `test-phase-87` target at bottom only |
| `docs/phases/complete/PHASE_87_notes.md` | E | New file (review findings) |

**Shared file rules:**
- `monitoring/prometheus/alerts.yml` — Agent C **appends only**. Lines above the new
  groups must be byte-for-byte identical before and after.
- `monitoring/prometheus/recording_rules.yml` — Agent C may edit existing `expr`
  fields in stale groups (metric name fixes only) and append the new group.
- `monitoring/grafana/dashboards/ja4proxy-overview.json` — Agent B touches the
  `links` array only. Never modifies any panel.
- `monitoring/alertmanager/alertmanager.yml` — Agent C adds one entry to
  `inhibit_rules` only.
- `Makefile` — Agent D adds at the bottom only.

---

## 6. Runbook Outline

`docs/runbooks/infrastructure.md` must include the following sections, each with:
What is firing / Immediate check / Common causes / Resolution steps / Escalation.

```
## host-cpu-high
## host-cpu-critical
## high-load
## critical-load
## host-memory-high
## host-memory-critical
## file-descriptors
## file-descriptors-critical
## disk-low
## disk-critical
## inodes
## entropy
## oom-kill
## restart-loop
## container-memory
## cpu-throttle
## haproxy-queue
## haproxy-sessions
## haproxy-backend-down
## haproxy-connection-errors
## haproxy-queue-attack
## disk-prediction
## redis-memory-growth
## slo-burn
## connection-rate-spike
## connection-rate-sustained
## syn-flood
## time-wait-spike
## nic-drops
## distributed-attack
```

---

## 7. Acceptance Criteria

- [ ] cAdvisor added to `docker/docker-compose.monitoring.yml`, pinned to `v0.47.2`, no external port, blkio metrics dropped via `metric_relabel_configs`
- [ ] HAProxy exporter added to `docker/docker-compose.monitoring.yml`, pinned to `v0.15.0`, scraping `:8404/stats?stats;csv`
- [ ] Both new scrape jobs present in `monitoring/prometheus/prometheus.yml`
- [ ] `monitoring/prometheus/recording_rules.yml` contains no references to `ja4_requests_total` or `ja4_blocked_requests_total` (stale names fixed)
- [ ] `ja4proxy_infra_aggregations` recording rules group present; all 6 rules verify as valid PromQL
- [ ] `monitoring/grafana/dashboards/ja4proxy-infrastructure.json` exists and is valid JSON
- [ ] Dashboard has template variable `$container` with numeric-suffix exclusion regex
- [ ] Fleet status strip visible in one row without scrolling (all containers, one stat each)
- [ ] Dashboard has 6 named row sections: Fleet Status, Host Resources, Network & TCP Stack, HAProxy, Container Drill-Down, Attack Detection
- [ ] Alert annotations enabled on dashboard (`annotations.list` has Grafana alerts entry)
- [ ] Container drill-down panels include CPU throttle%, disk I/O, and network errors (not just CPU% and memory%)
- [ ] `ja4proxy-overview.json` unchanged except `links` array addition
- [ ] 5 new alert groups appended to `alerts.yml`; existing groups byte-for-byte identical
- [ ] `ContainerOOMKilled` has `for: 0m`
- [ ] `ConnectionRateSpike` uses `clamp_min(..., 0.1)` guard against startup false positives
- [ ] `SYNFloodIndicator` references the `ja4proxy:network_avg_pkt_size_bytes` recording rule
- [ ] `HAProxyBackendQueueing` alert threshold lower (> 0) and `HAProxyQueueSignalsCapacityAttack` higher (> 5) — distinct thresholds for distinct purposes
- [ ] Host-saturation inhibition rule added to `alertmanager.yml`
- [ ] `docs/runbooks/infrastructure.md` present with all 29 sections
- [ ] `make test-phase-87` passes with zero failures
- [ ] Agent E review complete; `docs/phases/complete/PHASE_87_notes.md` written; all critical findings resolved
- [ ] `CHANGELOG.md` updated
- [ ] `docs/phases/manifest.yaml` status set to `COMPLETE` with `completed:` date
- [ ] `python3 scripts/sync-roadmap.py` run; `TODO.md` and `PROJECT_STATUS.md` regenerated
- [ ] `make lint-phases` exits 0
