<!--
title: TAP Mode Operator Runbook
audience: Operators, Security Teams
last_reviewed: 2026-04-03
phase: 20
-->

# TAP Mode Operator Runbook

**Phase:** 20 — Passive TAP/SPAN Mode
**Last updated:** 2026-03-28

---

## Overview

JA4proxy TAP mode is a **passive, out-of-band** deployment that fingerprints traffic
from a SPAN/mirror port without participating in any TCP connections. It does not
decrypt or modify traffic.

TAP mode runs alongside the inline proxy:
- TAP sensor captures raw packets from a SPAN interface
- TAP pipeline scores fingerprints and writes high-confidence ban/block decisions to Redis
- Inline proxy reads these decisions via Redis PubSub and enforces them

---

## Prerequisites

- Linux kernel 3.17+ (AF_PACKET TPACKET_V3 support)
- Python 3.10+
- `CAP_NET_RAW` capability (or run as root during development)
- Redis 6.2+ (shared with inline proxy)
- Network switch configured for SPAN/mirror port to the capture interface

---

## Quick Start

```bash
# 1. Configure the capture interface in config/proxy.yml
#    (See "Configuration" section below)

# 2. Start the TAP sensor
python3 -m src.tap.tap_sensor --config config/proxy.yml

# 3. Verify capture is working
curl http://localhost:9099/tap/health
curl http://localhost:9099/tap/status
```

---

## Configuration

All TAP settings live under `tap:` and `tap_enforcement:` in `config/proxy.yml`.

### Capture Settings

```yaml
tap:
  enabled: true
  interface: eth1                  # SPAN/mirror port interface
  ring_buffer_mb: 64               # AF_PACKET ring buffer size (restart required)
  workers: 4                       # Parallel capture worker processes
  tls_ports: [443, 8443]           # Ports to fingerprint TLS on
  ssh_ports: [22]                  # Ports to run JA4SSH on
  http_ports: [80, 8080]           # Ports to run JA4H on
  stream_timeout_s: 300            # Evict idle streams after this many seconds (hot-reload)
  max_streams: 100000              # Max concurrent stream table entries (restart required)
  http_port: 9099                  # TAP HTTP server port (health, status, EDL)
```

**Hot-reloadable:** `stream_timeout_s`, fingerprint enable/disable, enforcement settings.
**Restart required:** `interface`, `ring_buffer_mb`, `workers`, `max_streams`.

### Enforcement Settings

```yaml
tap_enforcement:
  ban_ttl_s: 3600                  # How long ban entries persist in Redis
  iptables:
    enabled: true
    ipset_name: ja4proxy_ban       # ipset name to add banned IPs to
  bgp:
    enabled: false                 # BGP blackhole routing via ExaBGP
    exabgp_pipe: /var/run/exabgp.cmd
    next_hop: 192.0.2.1            # Blackhole next-hop address
  webhook:
    enabled: false
    url: https://siem.example.com/ja4proxy/bans
    secret: ""                     # HMAC-SHA256 signing secret (X-JA4Proxy-Signature)
    max_retries: 3
    timeout_s: 10
```

---

## Health Checks

```bash
# Basic health
curl http://localhost:9099/tap/health
# Response: {"status": "ok", "workers": 4, "uptime_s": 3600}

# Detailed status
curl http://localhost:9099/tap/status
# Response: {"packets_received": 1234567, "packets_dropped": 0, "streams_active": 4321,
#            "fingerprints_extracted": 98765, "actions": {"observe": 95000, "flag": 2500,
#            "signal_slow": 800, "signal_block": 400, "signal_ban": 65}}
```

---

## Monitoring

### Key Prometheus Metrics

| Metric | Description |
|--------|-------------|
| `ja4proxy_tap_packets_received_total` | Raw packets captured from the interface |
| `ja4proxy_tap_packets_dropped_total` | Packets dropped by the kernel ring buffer |
| `ja4proxy_tap_streams_active` | Current active stream table size |
| `ja4proxy_tap_fingerprints_extracted_total{type}` | Fingerprints extracted per type (ja4, ja4s, ja4t, etc.) |
| `ja4proxy_tap_actions_total{action}` | Actions taken: observe/flag/signal_slow/signal_block/signal_ban |
| `ja4proxy_tap_worker_restarts_total{worker_id}` | Worker crash/restart counter (alert if > 3 in 60s) |

### Alert: Worker Rapid-Crash Loop

Fired when `ja4proxy_tap_worker_restarts_total` > 3 within 60 seconds for the same
worker. Common causes:
- Interface disconnected or renamed
- Insufficient ring buffer (`ring_buffer_mb` too small for traffic rate)
- BPF filter syntax error in config

```bash
# Check worker logs
journalctl -u ja4proxy-tap -n 100 --grep="rapid-crash"
# Restart the TAP sensor
systemctl restart ja4proxy-tap
```

### Alert: Packet Drop Rate

Fired when `ja4proxy_tap_packets_dropped_total / ja4proxy_tap_packets_received_total > 0.01`
(> 1% drop rate). Common causes:
- Ring buffer too small
- Worker count too low
- Python GIL contention

```bash
# Increase ring buffer (requires restart)
# In config/proxy.yml: tap.ring_buffer_mb: 128

# Add more workers (requires restart)
# In config/proxy.yml: tap.workers: 8

# Check drop statistics from kernel
cat /proc/net/packet | grep -A2 "$(ip link show eth1 | head -1 | awk '{print $1}')"
```

---

## Capacity and Sizing

| Traffic rate | Workers | Ring buffer | Notes |
|---|---|---|---|
| < 100 Mbps | 2 | 64 MB | Development / low-traffic |
| 100–500 Mbps | 4 | 128 MB | Typical production |
| 500 Mbps–1 Gbps | 8 | 256 MB | High-traffic |
| > 1 Gbps | 8+ | 512 MB | Consider Go rewrite (Phase 15) |

Stream table sizing: allow ~200 bytes per stream × `max_streams`. At 100k streams that
is ~20 MB of Python heap. If OOM errors occur, reduce `max_streams` or increase worker
count (each worker has its own stream table).

---

## Reconciliation

The `scripts/reconcile_ipset.py` script detects drift between Redis ban keys and
the live iptables ipset. Schedule this to run every 5 minutes:

```bash
# Add to crontab (run as root):
*/5 * * * * /usr/bin/python3 /opt/ja4proxy/scripts/reconcile_ipset.py --redis-url redis://localhost:6379

# Manual dry-run
sudo python3 scripts/reconcile_ipset.py --dry-run --verbose
```

Exit codes:
- `0` — No drift found; ipset is consistent with Redis.
- `1` — Drift found and (if not `--dry-run`) corrected.

---

## GDPR Data Deletion

To delete all fingerprint and connection data associated with an IP:

```bash
make gdpr-delete IP=1.2.3.4
# or directly:
python3 scripts/gdpr_delete.py --ip 1.2.3.4
```

This deletes:
- `fp:conn:*` records where `client_ip` matches
- `fp:ip:{ip}` sorted set
- `fp:os:ip:{ip}` key
- `ban:{ip}` and `tap:ban:{ip}` keys
- Entries in `tap:block_decisions` list (filtered)

The operation logs an audit entry to `management:gdpr_audit` in Redis.

---

## Troubleshooting

### No packets captured

```bash
# Verify interface exists
ip link show eth1

# Verify SPAN port is receiving traffic
tcpdump -i eth1 -c 10 -nn

# Verify CAP_NET_RAW
getcap /usr/bin/python3.10
# If missing: sudo setcap cap_net_raw+eip /usr/bin/python3.10
```

### No fingerprints extracted

```bash
# Check if TLS traffic is reaching the interface on configured ports
tcpdump -i eth1 -nn 'tcp port 443' -c 5

# Verify tls_ports config matches actual traffic ports
grep "tls_ports" config/proxy.yml
```

### Enforcement bridge not banning IPs

```bash
# Check bridge is running
redis-cli subscribe ja4proxy:bans

# Verify ipset exists
sudo ipset list ja4proxy_ban | head -5

# Check iptables rule references the ipset
sudo iptables -L INPUT -v -n | grep ja4proxy_ban

# Create the ipset if missing (normally created by setup script)
sudo ipset create ja4proxy_ban hash:ip timeout 3600
sudo iptables -I INPUT -m set --match-set ja4proxy_ban src -j DROP
```

### High false positive rate

1. Check `test_100_browser_fps_zero_false_positives` test output.
2. Reduce the `flag` threshold: signals below 20 should not produce false positives
   for browser traffic.
3. Review GREASE detection — browsers always send GREASE values; the TAP pipeline
   should not signal on modern browser fingerprints.

```bash
# Run FP corpus test
python3 -m pytest tests/tap/fp_corpus/test_fingerprint_fp_rate.py -v
```

---

## Security Notes

- TAP sensor drops `CAP_NET_RAW` after the AF_PACKET socket is opened.
- A seccomp profile (`config/seccomp_tap.json`) restricts syscalls post-drop.
- The EDL HTTP server requires an API key (`tap_export.edl.api_key`).
- Webhook posts are HMAC-SHA256 signed (`X-JA4Proxy-Signature: sha256=...`).
- BGP announces validate prefix length: IPv4 ≥ /24, IPv6 ≥ /48.
- Never configure TAP mode to read from the proxy's own listening interface —
  it would see its own traffic and could cause feedback loops.
