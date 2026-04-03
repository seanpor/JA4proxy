# PHASE 20 — Passive TAP/SPAN Mode: Deep Fingerprinting at the Internet Edge

---

## 1. Overview

This phase adds a **passive TAP/SPAN capture mode** to JA4proxy. In this mode the
proxy does not sit inline between client and server — it receives **copies** of packets
mirrored from a network switch or TAP device. It reassembles TCP streams, extracts
every fingerprint that can be derived from plaintext metadata, correlates those
fingerprints with IP addresses, scores them, and signals enforcement points (inline
proxies, firewalls, routers) via the shared Redis infrastructure.

### 1.1 Why TAP Mode?

| Scenario | Passthrough mode | TAP mode |
|----------|-----------------|----------|
| Sits inline, can drop/RST traffic | ✓ | ✗ |
| Zero-impact on latency for allowed traffic | ✗ (adds ~1ms) | ✓ (traffic path unchanged) |
| Survives JA4proxy crash gracefully | ✗ (traffic stops) | ✓ (traffic continues) |
| Can block traffic in real time | ✓ | ✗ (signals enforcement layer) |
| Sees **both** sides of TLS handshake | ✗ (client side only) | ✓ (client + server) |
| Can fingerprint the **server** (JA4S, JA4X) | Limited | ✓ |
| Works on read-only mirror port | ✗ | ✓ |
| Can be retrofitted onto existing infra | Needs traffic re-routing | ✓ (just mirror a port) |

TAP mode is ideal for:
- Non-disruptive rollout on existing infrastructure
- Sensor nodes at branch offices or cloud VPC mirror ports
- Generating threat intelligence without risk of false-positive outages
- Running alongside passthrough mode for richer signal collection
- Pre-production learning mode before enabling inline blocking

### 1.2 What Is New vs What Is Reused

**Reused from existing phases (unchanged):**
- Redis schema, LocalCache, PubSubHandler (Phase 0)
- RiskScorer, ActionDecider, dial (Phases 1–2)
- TLS cipher/version signals (Phase 3)
- SNI signals (Phase 4)
- TCP signals (Phase 5, extended in this phase)
- ASN/datacenter classification (Phase 6)
- FCrDNS enrichment (Phase 7)
- Spamhaus DROP checks (Phase 8)
- Beaconing detector (Phase 9)
- AbuseIPDB (Phase 10)
- RDAP enrichment (Phase 11)
- Analytics node (Phase 12)

**New in this phase:**
- Packet capture engine (raw socket / AF_PACKET / libpcap) with VxLAN/GENEVE decapsulation
- TCP stream reassembler (4-tuple state machine with out-of-order, retransmit, duplicate, fragment handling)
- JA4S — TLS **server** fingerprint from ServerHello
- JA4H — HTTP/1.1 header fingerprint from reassembled stream
- JA4L — light-distance estimation from TCP timing (SYN→SYN-ACK→ACK); hardware-timestamp aware
- JA4X — X.509 certificate fingerprint from TLS Certificate message
- JA4SSH — SSH client/server fingerprint from SSH_MSG_KEXINIT
- Enhanced JA4T parsing (full TCP options, not just handshake)
- OS fingerprinting (p0f-style from TCP/IP stack behaviour)
- HTTP/2 SETTINGS-frame fingerprinting (Akamai/GREASE fingerprint)
- QUIC Initial-packet fingerprinting
- TLS extension value fingerprinting (beyond JA4: key_share groups, PSK modes, GREASE)
- Fingerprint correlation store (all variants linked by `conn_id`)
- TAP-mode enforcement signalling (Redis → iptables/BGP/webhook bridge)
- Intelligence export layer — EDL server, F5 BIG-IP REST API, Palo Alto XML API, Kafka streaming, Syslog/CEF, STIX/TAXII 2.1, MISP push
- Mode configuration and runtime mode query API
- PCAP-replay test framework with SyntheticPacketBuilder
- Graceful shutdown, hot-reload boundaries, worker watchdog

---

## 2. Prerequisites

Before starting this phase, the following must be complete:
- Phases 0–12 implemented and all tests passing
- Phase 15 (Go rewrite) should be evaluated; if the Go rewrite is complete, implement
  the packet capture layer in Go (see §14). If still Python, implement in Python first
  and note the Go port path.
- The host OS must be Linux (AF_PACKET is Linux-specific; macOS uses BPF/libpcap).
- Python packages — add all of the following to `requirements.txt`:
  ```
  scapy>=2.5,<3
  dpkt>=1.9.8
  pypcap>=1.3
  sortedcontainers>=2.4    # SortedList for per-stream reorder buffer
  aiokafka>=0.10           # Kafka streaming export (optional feature)
  stix2>=3.0               # STIX/TAXII export (optional feature)
  ```
- System capability: `CAP_NET_RAW` for packet capture; `CAP_NET_ADMIN` only if
  iptables enforcement is enabled. Drop both after socket setup (see §18.1).
- Network switch or TAP device must be configured to mirror the target port before
  running live tests. PCAP-replay tests need no special hardware.

---

## 3. Architecture in TAP Mode

```
                   ┌──────────────────────────────────────────────────┐
  Internet ─────── │  Switch/Router (SPAN port mirror or TAP device)  │ ─── Backend
                   └───────────────────┬──────────────────────────────┘
                                       │ copy of all packets
                                       ▼
                   ┌──────────────────────────────────────────────────┐
                   │              JA4proxy — TAP mode                  │
                   │                                                  │
                   │  ┌──────────────┐   ┌───────────────────────┐   │
                   │  │ Packet       │   │ TCP Stream            │   │
                   │  │ Capture      │──▶│ Reassembler           │   │
                   │  │ (AF_PACKET)  │   │ (4-tuple state)       │   │
                   │  └──────────────┘   └──────────┬────────────┘   │
                   │                                │                 │
                   │              ┌─────────────────▼──────────────┐  │
                   │              │   Fingerprint Extraction Layer  │  │
                   │              │  JA4  JA4S  JA4T  JA4H        │  │
                   │              │  JA4L JA4X  JA4SSH  OS-fp     │  │
                   │              │  HTTP/2-fp  QUIC-fp            │  │
                   │              └─────────────────┬──────────────┘  │
                   │                                │                 │
                   │              ┌─────────────────▼──────────────┐  │
                   │              │   Existing Pipeline (Phases 1-12)│ │
                   │              │   RiskScorer → ActionDecider   │  │
                   │              └─────────────────┬──────────────┘  │
                   │                                │                 │
                   └────────────────────────────────┼─────────────────┘
                                                    │
                        ┌───────────────────────────▼──────────────────┐
                        │              Redis (shared)                   │
                        │  ban:{ip}  fingerprints:{conn}  scores:{ip}  │
                        └───┬──────────────┬────────────────┬────────────────────┘
                            │              │                │
               ┌────────────▼───┐   ┌──────▼──────────┐  ┌▼──────────────────────────┐
               │ Inline         │   │ Enforcement     │  │ Intelligence Export        │
               │ JA4proxy       │   │ Bridge          │  │                            │
               │ (passthrough)  │   │ iptables/ipset  │  │ EDL HTTP server            │
               └────────────────┘   │ BGP (ExaBGP)    │  │ F5 BIG-IP REST API         │
                                    │ Webhook         │  │ Palo Alto XML API          │
                                    └─────────────────┘  │ Kafka streaming            │
                                                          │ Syslog / CEF              │
                                                          │ STIX/TAXII 2.1            │
                                                          │ MISP push                 │
                                                          └────────────────────────────┘
```

### 3.1 Data Flow

1. **Capture**: AF_PACKET ring buffer receives copies of Ethernet frames from the mirrored port.
2. **Decode**: Ethernet → IP (v4/v6) → TCP/UDP/QUIC layer parsed.
3. **Reassemble**: TCP streams tracked by 4-tuple `(src_ip, src_port, dst_ip, dst_port)`. Segments stored in order buffer, reassembled in-order, passed to the extraction layer.
4. **Extract**: Each reassembled stream is inspected for:
   - TLS ClientHello → JA4, partial JA4T
   - TLS ServerHello → JA4S
   - TLS Certificate message → JA4X
   - HTTP/1.1 request headers → JA4H
   - HTTP/2 SETTINGS/WINDOW_UPDATE frames → HTTP/2 fingerprint
   - SSH KEXINIT → JA4SSH
   - QUIC Initial packet → QUIC fingerprint
   - TCP SYN options → full JA4T + OS fingerprint
5. **Score**: Feed extracted signals into the existing `RiskScorer`. Actions in TAP mode are `"observe"`, `"flag"`, `"signal_block"`, `"signal_ban"` (never `"block"` directly — the proxy cannot drop packets).
6. **Signal**: High-score IPs are written to Redis with appropriate TTLs. The enforcement bridge (§10) reads Redis and pushes to firewalls/BGP/iptables.

---

## 4. Configuration

### 4.1 Mode Selection

Add a top-level `mode` key to `config/proxy.yml`. This is the **only** config key that
requires a restart to change — it determines the I/O architecture at startup.

```yaml
# ── Deployment Mode ────────────────────────────────────────────────────────────
mode: passthrough   # "passthrough" | "tap"
                    # passthrough: inline proxy, can block/tarpit directly
                    # tap:         passive sensor on SPAN/mirror port, signals enforcement layer
                    # Changing this key requires a proxy restart.
```

### 4.2 TAP Mode Config

```yaml
tap:
  # Network interface to capture on.
  # Use "any" to capture on all interfaces (Linux only, loses VLAN tags).
  # For production use the specific interface connected to the SPAN/TAP port.
  interface: "eth1"

  # BPF filter applied at the kernel level — drops packets that cannot carry
  # fingerprints before they reach userspace. Reduce this only if you need to
  # capture non-TCP traffic (e.g. QUIC on UDP 443).
  # Syntax: standard tcpdump BPF expression.
  bpf_filter: "tcp or (udp and (port 443 or port 80))"

  # AF_PACKET TPACKET_V3 ring buffer size in megabytes.
  # Increase on high-traffic links to reduce drops.
  # Formula: set to (peak_traffic_bps * expected_processing_latency_s / 8) + 50%.
  # 256MB handles ~10Gbps for up to 20ms processing latency.
  ring_buffer_mb: 256

  # Number of parallel packet-processing workers.
  # Each worker handles a subset of TCP streams (consistent hash by 4-tuple).
  # Recommended: number of physical CPU cores, minus 2 for OS and Redis I/O.
  capture_workers: 6

  # How long (seconds) to keep TCP stream state for connections that have gone
  # silent without a FIN/RST. Too low = miss slow scanners. Too high = OOM.
  stream_timeout_s: 300

  # Maximum number of simultaneous TCP streams tracked.
  # Each stream uses ~4KB of memory. 100k streams = ~400MB.
  max_streams: 100000

  # Maximum bytes captured per packet (snaplen).
  # TLS ClientHello fits in ~500 bytes. Set to 1500 for safe margin.
  # HTTP/2 SETTINGS fits in the first few hundred bytes of the stream.
  # 9000 covers jumbo frames if your network uses them.
  snaplen: 1500

  # Put the capture interface into promiscuous mode.
  # Required on a SPAN port where traffic is not addressed to this host.
  promisc: true

  # PCAP replay file for testing and development.
  # When set, capture_workers read from this file instead of the live interface.
  # Set to null for production.
  # The file is replayed at the packet timestamps embedded in the PCAP.
  pcap_file: null   # e.g. "tests/pcap_corpus/mixed_clients.pcap"

  # Port numbers considered "TLS" for ClientHello parsing.
  # The capture will attempt JA4/JA4S extraction on these destination ports.
  tls_ports: [443, 8443, 465, 587, 993, 995, 8080, 8888]

  # Port numbers considered "SSH".
  ssh_ports: [22, 2222]

  # Port numbers considered "HTTP" (unencrypted, for JA4H).
  http_ports: [80, 8080, 8000, 8888]

  # Maximum bytes to buffer per TCP stream before giving up on reassembly.
  # Prevents memory exhaustion from very long-lived streams (video, downloads).
  max_stream_buffer_bytes: 65536

  # Emit a Prometheus metric for every packet dropped due to ring buffer overflow.
  # Disable on very high-traffic links if the metric itself causes overhead.
  track_drops: true

  # ── Duplicate packet deduplication ─────────────────────────────────────────
  # SPAN ports on bonded/LAG uplinks often deliver each packet twice (once per
  # member port). Dedup by (src_ip, src_port, dst_ip, dst_port, seq, data_len)
  # within this window. Set to 0 to disable.
  dedup_window_ms: 100

  # ── Cloud mirror decapsulation ──────────────────────────────────────────────
  # AWS VPC Traffic Mirroring and Azure vNET TAP deliver packets encapsulated
  # in VxLAN (UDP 4789). GCP Packet Mirroring and physical TAPs deliver raw
  # Ethernet. Set to the correct value for your environment.
  # Options: "none" | "vxlan" | "geneve"
  decapsulation: "none"

  # ── Hardware timestamping ───────────────────────────────────────────────────
  # Kernel software timestamps have ~1ms jitter — adequate for JA4L city-level
  # estimates. Hardware timestamps (supported on Intel i210/i350/X550, Mellanox
  # CX-4+) have <1µs jitter, making JA4L accurate to ~200km.
  # Enable only if the NIC and driver support SO_TIMESTAMPING with hardware mode.
  # When false (default), kernel receive timestamps are used.
  hardware_timestamps: false

  # ── Per-fingerprint-type enable/disable ────────────────────────────────────
  # Disable types that are not relevant to your traffic profile to reduce CPU.
  fingerprint_types:
    ja4:    true    # TLS ClientHello — always recommended
    ja4s:   true    # TLS ServerHello
    ja4t:   true    # TCP SYN options
    ja4h:   true    # HTTP/1.1 headers
    ja4l:   true    # Light distance from TCP timing
    ja4x:   true    # X.509 certificate
    ja4ssh: true    # SSH KEXINIT — disable if no SSH services
    os_fp:  true    # p0f-style OS detection
    h2_fp:  true    # HTTP/2 SETTINGS
    quic:   true    # QUIC Initial packet
    tls_ext: true   # Extended TLS extension values
```

### 4.3 Enforcement Bridge Config (TAP Mode Only)

```yaml
tap_enforcement:
  # Redis-only signalling (always enabled in TAP mode):
  # Writes ban:{ip} and flag:{ip} keys, just like passthrough mode.
  # Passthrough JA4proxy instances read these and enforce immediately.
  redis_signals: true

  # iptables/nftables bridge.
  # When enabled, the enforcement bridge runs as a sidecar process and
  # executes iptables commands when Redis publishes a new ban.
  # Requires CAP_NET_ADMIN. Disabled by default — enable only if this host
  # is also a traffic forwarder (e.g. a router with ip_forward=1).
  iptables_bridge:
    enabled: false
    chain: "JA4PROXY_BLOCK"    # iptables chain to insert rules into
    ipset_name: "ja4proxy_ban" # ipset used for O(1) lookups
    ban_ttl_s: 3600

  # BGP blackhole signalling via ExaBGP.
  # When enabled, banned IPs are announced as /32 (v4) or /128 (v6) with
  # community 65535:666 (RTBH — remotely triggered blackhole).
  # ExaBGP must be running and configured to accept commands from this process.
  bgp_blackhole:
    enabled: false
    exabgp_pipe: "/var/run/exabgp/exabgp.cmd"
    blackhole_community: "65535:666"
    next_hop: "192.0.2.1"   # blackhole next-hop, must be in your RIB
    announce_v4: true
    announce_v6: true
    withdraw_on_unban: true  # send BGP withdraw when Redis ban expires

  # Generic webhook for custom enforcement (pfSense, OPNsense, Palo Alto, etc.)
  webhook:
    enabled: false
    url: "https://firewall.internal/api/v1/block"
    method: "POST"
    headers:
      Authorization: "Bearer ${FIREWALL_API_KEY}"
    body_template: '{"ip": "{ip}", "ttl": {ttl}, "reason": "{reason}"}'
    timeout_s: 5
    retry_count: 3
```

### 4.4 Intelligence Export Config

```yaml
intelligence_export:

  # ── EDL (External Dynamic List) HTTP server ─────────────────────────────────
  # Serves plain-text IP/CIDR/JA4 lists that firewalls poll periodically.
  # Endpoints are added under the existing management HTTP server (port 8090).
  # Compatible with: Palo Alto NGFW, Fortinet FortiGate, Check Point, F5 (external
  # data-group URI), Cisco FTD, any device supporting HTTP threat-feed polling.
  edl:
    enabled: true

    # How often (seconds) to rebuild the lists from Redis.
    # Consuming devices should poll no more frequently than this value.
    refresh_interval_s: 60

    # Do not include entries older than this (seconds) in the EDL.
    # Prevents stale bans from lingering in external devices after Redis TTL expires.
    max_age_s: 3600

    # Access control. If allowed_ips is non-empty, only those source IPs may fetch
    # the EDL. This prevents intel leakage to unauthorised hosts.
    # Combine with api_key for defence in depth.
    allowed_ips: []              # e.g. ["10.0.0.1", "192.168.1.0/24"]

    # If non-empty, require ?key=VALUE query parameter on all EDL requests.
    # Store the key in an environment variable, not in this file.
    api_key: "${EDL_API_KEY}"

    # Include # comment lines with metadata (last-seen timestamp, score).
    # Some devices reject files with comments — set false if needed.
    include_comments: true

    # Threshold: only include IPs whose risk score is >= this value.
    # Keeps the list focused on high-confidence threats.
    min_score: 70

    # Endpoints served (each returns text/plain, one entry per line):
    #   GET /export/edl/banned-ips       → ban:{ip} Redis keys
    #   GET /export/edl/banned-cidrs     → ban_cidr:{cidr} Redis keys
    #   GET /export/edl/flagged-ips      → IPs scored >= min_score but not yet banned
    #   GET /export/edl/ja4-blacklist    → ja4:blacklist Redis set (fingerprint strings)
    #   GET /export/edl/combined         → union of all IP/CIDR lists (convenience)
    # All endpoints support If-None-Match / ETag for efficient polling.
    # Format: one entry per line; comments start with #

  # ── F5 BIG-IP REST API push ──────────────────────────────────────────────────
  # Pushes IP lists to F5 internal data groups via the iControl REST API.
  # The corresponding iRule checks [class match [IP::client_addr] equals {name}].
  # Supports both full-sync (periodic rebuild) and delta-push (on Redis pub/sub).
  f5:
    enabled: false
    host: "https://f5-mgmt.internal"     # F5 management IP/hostname
    username: "admin"
    password: "${F5_PASSWORD}"           # never hardcode; use env var
    verify_tls: true                     # set false only in lab with self-signed cert
    # Data groups to maintain on the F5:
    data_groups:
      banned_ips:
        name: "ja4proxy_banned_ips"
        type: "ip"                       # F5 type: ip (network) | string | integer
      flagged_ips:
        name: "ja4proxy_flagged_ips"
        type: "ip"
      ja4_blacklist:
        name: "ja4proxy_ja4_blacklist"
        type: "string"                   # JA4 fingerprint strings for iRule matching
    # How often to do a full rebuild push (reconciles any drift).
    sync_interval_s: 300
    # Also push immediately when a new ban is published on Redis pub/sub.
    push_on_change: true
    # F5 REST API rate limit (requests per second). The iControl API is not fast.
    max_rps: 5

  # ── Palo Alto Networks XML API push ─────────────────────────────────────────
  # Two integration patterns are supported:
  # 1. Push (this section): JA4proxy calls PA XML API to register dynamic addresses.
  # 2. Pull (EDL above): Configure PA to poll /export/edl/banned-ips.
  # Pull is preferred (simpler, PA handles polling). Use push for sub-minute latency.
  palo_alto:
    enabled: false
    host: "https://panos.internal"
    api_key: "${PANOS_API_KEY}"
    verify_tls: true
    # Dynamic Address Group to add banned IPs to.
    # Create this DAG in PAN-OS first: Objects → Address Groups → type=Dynamic.
    address_group: "ja4proxy-blocked"
    # Tag applied to registered IPs. The DAG filter should match this tag.
    tag: "ja4proxy-ban"
    # Virtual system (vsys). "vsys1" is the default for single-vsys devices.
    vsys: "vsys1"
    sync_interval_s: 60

  # ── Kafka streaming export ───────────────────────────────────────────────────
  # Publishes every fingerprint event, ban, and signal to Kafka topics.
  # Downstream consumers: Splunk, Elastic SIEM, custom analytics, other sensors.
  # Schema: JSON. Optional Avro schema registry support.
  kafka:
    enabled: false
    brokers: ["kafka:9092"]
    # TLS for broker connections.
    tls:
      enabled: false
      ca_cert: "/etc/ja4proxy/kafka-ca.pem"
      client_cert: null
      client_key: null
    # SASL authentication.
    sasl:
      enabled: false
      mechanism: "PLAIN"           # PLAIN | SCRAM-SHA-256 | SCRAM-SHA-512
      username: "${KAFKA_USER}"
      password: "${KAFKA_PASSWORD}"
    topics:
      fingerprints: "ja4proxy.fingerprints"   # one message per closed stream
      bans:         "ja4proxy.bans"            # ban/unban events
      signals:      "ja4proxy.signals"         # every RiskSignal
      raw_events:   "ja4proxy.raw"             # all events (high volume)
    batch_size: 100          # flush when N messages accumulated
    linger_ms: 50            # or after this many ms, whichever comes first
    schema_registry_url: null  # e.g. "http://schema-registry:8081" for Avro

  # ── Syslog / CEF export ──────────────────────────────────────────────────────
  # Forwards events to a SIEM or syslog collector using CEF or RFC 5424 format.
  # Compatible with: Splunk (HEC or syslog), IBM QRadar, Micro Focus ArcSight,
  # LogRhythm, Microsoft Sentinel (via Syslog connector).
  syslog:
    enabled: false
    host: "siem.internal"
    port: 514
    protocol: "udp"          # "udp" | "tcp" | "tcp+tls"
    # TLS settings (only used when protocol: tcp+tls)
    tls:
      verify: true
      ca_cert: null
    format: "cef"            # "cef" (ArcSight CEF) | "rfc5424" | "leef" | "json"
    facility: 16             # 16 = local0
    # Map TAP actions to syslog severity levels.
    severity_map:
      observe:      6        # Informational
      flag:         5        # Notice
      signal_block: 4        # Warning
      signal_ban:   3        # Error
    # Which event types to forward (set false to reduce syslog volume).
    events:
      fingerprint_extracted: false  # very high volume; disable unless SIEM can handle it
      flag:       true
      signal_block: true
      signal_ban: true
      enforcement_error: true

  # ── STIX/TAXII 2.1 server ────────────────────────────────────────────────────
  # Serves a TAXII 2.1 API that other TAXII clients (MISP, OpenCTI, Elastic SIEM,
  # Splunk SIEM, Cortex XSOAR) can subscribe to.
  # Endpoints served under /taxii2/ alongside the management API.
  taxii:
    enabled: false
    # Unique collection identifier (UUID recommended).
    collection_id: "ja4proxy-ioc"
    collection_title: "JA4proxy Threat Intelligence"
    # API key required to access TAXII endpoints.
    api_key: "${TAXII_API_KEY}"
    # How far back to include indicators (seconds).
    max_indicator_age_s: 86400   # 24 hours
    # STIX object types to publish:
    # - indicator: ban:{ip} → ipv4-addr/ipv6-addr Indicator
    # - malware: known scanner JA4 fingerprints → Malware object
    # - relationship: connect Indicator to Malware
    publish_types: ["indicator", "malware", "relationship"]

  # ── MISP push ────────────────────────────────────────────────────────────────
  # Pushes new bans as MISP Events / Attributes to a MISP instance.
  # Useful for sharing threat intel with partner organisations via MISP sync.
  misp:
    enabled: false
    url: "https://misp.internal"
    api_key: "${MISP_API_KEY}"
    verify_tls: true
    event_name: "JA4proxy Threat Intelligence"
    distribution: 0          # 0=your org only; 1=community; 2=connected; 3=all
    threat_level: 2          # 1=high; 2=medium; 3=low; 4=undefined
    analysis: 2              # 0=initial; 1=ongoing; 2=completed
    # Only push bans above this score threshold.
    min_score: 80
    publish_on_ban: true     # auto-publish event after adding attributes
    # Tag applied to all JA4proxy-generated attributes.
    tag: "ja4proxy"
```

### 4.5 Passthrough Mode Config (No Change to Existing)

The existing passthrough config under `proxy:` is unchanged. When `mode: passthrough`,
the `tap:` section is read but ignored (logged at startup as "tap config present but
mode is passthrough — tap section ignored").

### 4.5 Runtime Mode Query

Add a `/mode` endpoint to the existing management HTTP server (Phase 13):

```
GET /api/v1/mode
→ {"mode": "tap", "interface": "eth1", "streams_active": 4821, "packets_captured": 1284732, "packets_dropped": 0}
```

---

## 5. Packet Capture Engine

### 5.1 Why AF_PACKET (Not pcap/Scapy)?

| Method | Throughput | Latency | Drops at 10Gbps | Deps |
|--------|-----------|---------|-----------------|------|
| Scapy (Python sniff) | ~50k pkt/s | ~ms | Very high | Python |
| pypcap + libpcap | ~500k pkt/s | ~µs | Moderate | libpcap |
| AF_PACKET TPACKET_V3 | ~2M pkt/s | ~µs | Low | Linux kernel |
| PF_RING / DPDK | ~10M+ pkt/s | sub-µs | None | Kernel module / dedicated NIC |

For most internet-edge deployments (1–10Gbps), **AF_PACKET TPACKET_V3** is the right
choice: it requires no kernel modules, works on any Linux NIC, and achieves multi-Mpps
throughput via a memory-mapped ring buffer shared between kernel and userspace.

At wire speeds above 10Gbps, consider DPDK or PF_RING — these require dedicated NICs
and kernel module installation, and are outside this phase's scope. Document the path
in the ADR.

### 5.2 AF_PACKET Ring Buffer Design

```
┌─────────────────────────────────────────────────────────┐
│                  Kernel                                 │
│  NIC → softirq → AF_PACKET socket → ring buffer         │
│                              (mmap shared with userspace)│
└────────────────────────────────┬────────────────────────┘
                                 │  mmap (zero-copy)
┌────────────────────────────────▼────────────────────────┐
│                  Userspace (JA4proxy)                    │
│                                                         │
│  Capture thread (1)                                     │
│  ├── polls ring buffer (tpacket_block_desc)             │
│  ├── reads packet metadata (timestamp, len, snaplen)    │
│  └── dispatches to worker via consistent hash (4-tuple) │
│                                                         │
│  Worker threads (N = capture_workers)                   │
│  ├── each owns a shard of the TCP stream state table    │
│  ├── reassembles TCP streams for its shard              │
│  └── calls fingerprint extractor when data is ready     │
└─────────────────────────────────────────────────────────┘
```

**Consistent hashing by 4-tuple** ensures all packets for a given TCP stream always
go to the same worker, eliminating locking on the stream state table.

### 5.3 Packet Parsing

The capture layer must handle the full encapsulation stack before reaching IP:

```
Ethernet frame
  ├── VLAN tag (802.1q) — strip before IP parsing
  ├── QinQ (802.1ad) — strip both tags
  ├── VxLAN (UDP 4789) — decapsulate when decapsulation: "vxlan"
  │     └── Inner Ethernet → IP → TCP (process as normal)
  ├── GENEVE (UDP 6081) — decapsulate when decapsulation: "geneve"
  │     └── Inner Ethernet → IP → TCP (process as normal)
  └── IP (v4 or v6)
        ├── TCP
        │     ├── Capture TCP options from SYN/SYN-ACK
        │     └── Pass segments to reassembler
        ├── UDP port 443/80 → QUIC initial packet parsing
        └── Fragment handling:
              ├── IPv4: check MF flag + fragment offset; reassemble in fragment cache
              │         (30s TTL per incomplete fragment set; discard on timeout)
              └── IPv6: walk extension headers to find Fragment Header (type 44);
                        reassemble using identification field
```

**Duplicate packet detection** must run before the reassembler to prevent double-scoring.
SPAN ports on bonded/LAG uplinks often deliver each packet twice (once per member port).
Without dedup, JA4L RTT measurements are corrupted and fingerprints may be extracted
twice for the same stream.

```python
# Per-worker dedup cache: key=(src_ip, src_port, dst_ip, dst_port, tcp_seq, data_len)
# TTL: tap.dedup_window_ms (default 100ms). Use an LRU with time-based eviction.
# Memory cost: ~100 bytes per entry × estimated_pps × dedup_window_ms / 1000.
# At 100k pps and 100ms window: ~1MB. Acceptable.
```

**ECMP / asymmetric routing warning (document in runbook):** On multi-path networks
the SYN may arrive via path A and the SYN-ACK via path B. If only one path is mirrored
to the SPAN port, JA4L will be wrong (missing one RTT leg) and the reassembler will
never see the full handshake. If this is observed (high rate of streams that never
reach ESTABLISHED despite apparent traffic), check that the SPAN mirrors **both**
directions and all ECMP paths. This is a network configuration issue, not a JA4proxy bug.

**IP fragment reassembly** is required because some TLS ClientHellos exceed 1500 bytes
(many extensions) and may arrive fragmented on low-MTU paths. Use a fragment cache with
a 30s TTL; discard incomplete fragments after timeout.

### 5.4 Implementation: `../../src/tap/capture.py`

```python
class PacketCapture:
    """AF_PACKET TPACKET_V3 capture engine.

    Opens a raw AF_PACKET socket on the configured interface with a
    TPACKET_V3 ring buffer. The single capture thread polls the ring
    and dispatches frames to worker queues via 4-tuple hash.
    """

    def __init__(self, config: TapConfig, workers: list[StreamWorker]) -> None: ...

    async def start(self) -> None:
        """Open the socket, set BPF filter, mmap ring, start poll loop."""
        ...

    async def stop(self) -> None:
        """Signal poll loop to exit, unmap ring, close socket."""
        ...

    def _setup_socket(self) -> socket.socket:
        """Create AF_PACKET SOCK_RAW socket, bind to interface, set TPACKET_V3."""
        ...

    def _set_bpf_filter(self, sock: socket.socket, expr: str) -> None:
        """Compile and attach BPF filter using SO_ATTACH_FILTER."""
        ...

    def _poll_ring(self) -> None:
        """Main capture loop — runs in a dedicated OS thread via asyncio.to_thread()."""
        ...

    def _dispatch(self, frame: memoryview) -> None:
        """Hash 4-tuple, put frame into correct worker queue."""
        ...
```

### 5.5 PCAP Replay (Testing and Development)

When `tap.pcap_file` is set, `PacketCapture` is replaced by `PcapReplay`:

```python
class PcapReplay:
    """Replays a PCAP file into the worker pipeline.

    Reads packets using dpkt, emits them at the timestamps embedded in the
    PCAP (honoring inter-packet delays by default; fast mode available for
    testing). API-compatible with PacketCapture so workers see no difference.
    """

    def __init__(self, pcap_path: Path, workers: list[StreamWorker],
                 realtime: bool = False) -> None: ...
```

In **test mode** (`realtime=False`) packets are injected as fast as possible with no
inter-packet delays, allowing the full test corpus to complete in seconds.

---

## 6. TCP Stream Reassembler

### 6.1 Design Goals

- **Correctness over speed** at first; optimise in Phase 15 Go rewrite.
- Handle out-of-order segments (store in per-stream reorder buffer, flush when gap fills).
- Handle retransmissions (compare seq numbers, ignore retrans payload).
- Handle RST and FIN (close stream state cleanly).
- Expire idle streams after `stream_timeout_s` with a final score emit.
- **Never reassemble beyond `max_stream_buffer_bytes`** — drop and log if a stream
  exceeds this limit (prevents memory exhaustion from video streams etc.).

### 6.2 Stream State Machine

```
               ┌──────────────┐
      SYN ──→  │    SYN_RCVD  │
               └──────┬───────┘
             SYN-ACK  │
               ┌──────▼───────┐
               │  ESTABLISHED │ ←── data segments (both directions)
               └──────┬───────┘
             FIN/RST  │
               ┌──────▼───────┐
               │    CLOSING   │ (wait for FIN-ACK or RST)
               └──────┬───────┘
                      │ FIN-ACK / timeout
               ┌──────▼───────┐
               │    CLOSED    │ → emit final fingerprints, purge state
               └──────────────┘
```

Each stream tracks:
- `client_seq`: next expected sequence number from client (→ server direction)
- `server_seq`: next expected sequence number from server (→ client direction)
- `client_buf`: `SortedList` of `(seq, data)` tuples for out-of-order client data
- `server_buf`: same for server data
- `client_data`: bytes assembled so far from client (capped at `max_stream_buffer_bytes`)
- `server_data`: same for server
- `syn_ts`: timestamp of first SYN packet (for JA4L calculation)
- `synack_ts`: timestamp of SYN-ACK (for JA4L)
- `ack_ts`: timestamp of first ACK (for JA4L)
- `syn_tcp_opts`: raw TCP options from SYN (for JA4T and OS fingerprint)
- `synack_tcp_opts`: raw TCP options from SYN-ACK (for server-side JA4T)
- `client_ip`, `client_port`, `server_ip`, `server_port`
- `fingerprints`: dict of extracted fingerprints populated as handshake progresses
- `score_emitted`: bool — prevent duplicate scoring if stream seen on multiple workers

### 6.3 Out-of-Order Handling

```python
def _on_segment(self, stream: TCPStream, seq: int, data: bytes, direction: str) -> None:
    buf = stream.client_buf if direction == "c2s" else stream.server_buf

    expected = stream.client_seq if direction == "c2s" else stream.server_seq

    if seq == expected:
        # In-order: append directly, then flush any buffered segments
        self._append_data(stream, data, direction)
        self._flush_reorder_buf(stream, direction)
    elif seq > expected:
        # Future segment: buffer it
        buf.add((seq, data))
    else:
        # Retransmission or already-seen segment: discard
        pass
```

### 6.4 Implementation: `../../src/tap/reassembler.py`

```python
class StreamReassembler:
    """Tracks TCP streams for one worker shard.

    Called from StreamWorker with decoded packet fields. Maintains stream
    state and calls FingerprintExtractor when enough data has been assembled.
    """

    def __init__(self, extractor: FingerprintExtractor, config: TapConfig) -> None: ...

    def on_packet(self, pkt: ParsedPacket) -> None:
        """Main entry point — called for every packet in this worker's shard."""
        ...

    def _get_or_create(self, key: StreamKey) -> TCPStream: ...
    def _on_syn(self, stream: TCPStream, pkt: ParsedPacket) -> None: ...
    def _on_synack(self, stream: TCPStream, pkt: ParsedPacket) -> None: ...
    def _on_data(self, stream: TCPStream, pkt: ParsedPacket) -> None: ...
    def _on_fin_rst(self, stream: TCPStream, pkt: ParsedPacket) -> None: ...
    def _expire_idle(self) -> None:
        """Called periodically — evict streams silent for > stream_timeout_s."""
        ...
```

---

## 7. Fingerprint Extraction

All fingerprint extractors live in `src/tap/fingerprints/`. Each is a pure function or
small class that takes a byte buffer and returns a typed dataclass or `None`.

### 7.1 JA4 — TLS Client Fingerprint (Enhanced)

**Already implemented** in `src/security/tls_enforcer.py` for passthrough mode. In TAP
mode, parse from reassembled `client_data` bytes. The parsing logic is shared; only the
data source changes.

**JA4 format recap** (for reference — already implemented):
```
{proto}{tls_ver}{sni?}{num_ciphers}{alpn}{num_exts}_{sorted_cipher_hex}_{sorted_ext_hex}
```
- `proto`: `t`=TLS, `q`=QUIC, `d`=DTLS
- `tls_ver`: `13`=TLS 1.3, `12`=TLS 1.2, `11`=TLS 1.1, `10`=TLS 1.0
- `sni?`: `d`=SNI present (domain), `i`=no SNI (IP or missing)
- `num_ciphers`: zero-padded 2-digit count, e.g. `16`
- `alpn`: first 2 chars of first ALPN, e.g. `h2`, `h1`, `00` if absent
- `num_exts`: zero-padded 2-digit extension count, e.g. `15`
- `sorted_cipher_hex`: 12-char hex of sorted cipher suite IDs (MD5 prefix)
- `sorted_ext_hex`: 12-char hex of sorted extension type IDs (MD5 prefix), excluding SNI and ALPN

**New in TAP mode:** extract from raw byte buffer rather than asyncio StreamReader.

```python
# src/tap/fingerprints/ja4.py

def extract_ja4(client_hello: bytes) -> JA4Result | None:
    """Parse a raw TLS ClientHello record and return JA4 fingerprint.

    Args:
        client_hello: Raw bytes starting at the TLS record header (0x16 0x03 ...).

    Returns:
        JA4Result on success, None if the buffer is not a valid ClientHello
        or is incomplete (caller should buffer more data and retry).
    """
    ...

@dataclass
class JA4Result:
    fingerprint: str           # e.g. "t13d1516h2_8daaf6152771_02713d6af862"
    tls_version_offered: str   # raw version from ClientHello (may differ from negotiated)
    ciphers: list[int]         # cipher suite IDs (unsorted)
    extensions: list[int]      # extension type IDs
    alpn_list: list[str]       # all ALPN values offered
    sni: str | None            # SNI hostname if present
    key_share_groups: list[int]  # for §7.8 TLS extension value fingerprint
    psk_modes: list[int]       # PSK key exchange modes
    supported_groups: list[int] # EC named groups
    signature_algorithms: list[int]
    session_ticket_present: bool
    session_ticket_len: int    # 0 if no session ticket; positive = resumption hint
    grease_values: list[int]   # GREASE values found (browser indicator)
    padding_ext_len: int | None # Chrome pads ClientHello; indicates Chrome
    compress_cert_present: bool # RFC 8879, indicates modern browser
```

**Why store all those extra fields?** They are used by the TLS extension value
fingerprint (§7.8) which goes beyond JA4 to capture the specific *values* inside
extensions, not just their presence.

---

### 7.2 JA4S — TLS Server Fingerprint

**New.** Parsed from the **server's** TLS ServerHello message. In passthrough mode,
the proxy never sees the ServerHello (it forwards bytes without parsing). In TAP mode,
the server-side stream (`server_data`) is also available.

**What the ServerHello contains:**
- Chosen TLS version
- Chosen cipher suite (one, not a list)
- Session ID (presence indicates support for TLS session resumption)
- Extensions selected by server (subset of what client offered)

**JA4S format:**
```
{proto}{tls_ver}{num_ciphers}{alpn}_{cipher_hex}_{sorted_ext_hex}
```
- `proto`: `s` (server)
- `tls_ver`: same as JA4 (`13`, `12`, etc.)
- `num_ciphers`: always `01` (server picks one cipher)
- `alpn`: 2-char ALPN chosen by server, `00` if none
- `cipher_hex`: 4-char hex of the chosen cipher suite (no MD5 — only one cipher)
- `sorted_ext_hex`: 12-char hex of sorted extension types in ServerHello

**Why JA4S matters:**
- Identifies the server-side TLS stack (nginx vs Apache vs IIS vs CDN)
- Fingerprints CDN providers (Cloudflare, Fastly, Akamai have distinct JA4S)
- Detects when the "server" is actually a reverse proxy or TLS terminator in front of the real server
- Detects unusual server configurations that may indicate compromise

```python
# src/tap/fingerprints/ja4s.py

def extract_ja4s(server_hello: bytes) -> JA4SResult | None:
    """Parse a raw TLS ServerHello record and return JA4S fingerprint."""
    ...

@dataclass
class JA4SResult:
    fingerprint: str           # e.g. "s13d01h2_002f_0016"
    tls_version_negotiated: str
    cipher_chosen: int
    alpn_chosen: str | None
    extensions: list[int]
    session_id_present: bool
    supported_versions_ext: list[int]  # TLS 1.3 negotiation via extension
```

---

### 7.3 JA4T — TCP Client Fingerprint (Enhanced)

**Partially implemented** in `src/security/tcp_analyzer.py`. TAP mode adds the full
TCP options from the raw SYN packet, which are available from the packet capture layer.

**What JA4T captures from the TCP SYN:**

| Field | Example values | Meaning |
|-------|---------------|---------|
| Window size | `65535`, `64240`, `8192` | OS-specific; Linux uses 64240, Windows 64240 or 8192 |
| MSS | `1460`, `1380`, `536` | Maximum segment size option |
| TCP options string | `MSTNW` | M=MSS, S=SACK, T=Timestamps, N=NOP, W=Window Scale |
| Window scale | `8`, `7`, `0` | Window scale factor |

**JA4T format:**
```
{window_size}_{MSS}_{tcp_options_order}_{window_scale}
```
Example: `65535_1460_MSTNW_8`

TCP options decode:
- `M` = MSS (0x02)
- `S` = SACK Permitted (0x04)
- `T` = Timestamps (0x08)
- `N` = NOP (0x01)
- `W` = Window Scale (0x03)
- Other options listed by decimal type number

**JA4TS (Server TCP fingerprint) — new in TAP mode:**
Same format but from the SYN-ACK packet (server-chosen options, window, MSS).

```python
# src/tap/fingerprints/ja4t.py

def extract_ja4t_from_syn(syn_tcp_opts: bytes, window_size: int) -> JA4TResult:
    """Parse TCP options from a raw SYN packet's options field."""
    ...

@dataclass
class JA4TResult:
    fingerprint: str           # e.g. "65535_1460_MSTNW_8"
    window_size: int
    mss: int | None
    options_order: str         # e.g. "MSTNW"
    window_scale: int | None
    sack_permitted: bool
    timestamps: bool
    raw_options_hex: str       # full options field for reference
```

---

### 7.4 JA4H — HTTP/1.1 Header Fingerprint

**New.** Parsed from the **reassembled client HTTP/1.1 request** (`client_data` after
TLS is not present, or from plaintext port 80 streams).

**What JA4H captures:**
- HTTP method and version
- Whether a Cookie header is present
- Whether a Referer header is present
- Number of headers sent
- Accept-Language value (first 8 chars, normalised)
- Sorted hash of all header field names (minus Cookie and Referer values)
- First-8 header names in order (preserves ordering fingerprint)

**JA4H format:**
```
{method}{ver}{cookie?}{referer?}_{num_headers}_{accept_lang_hash}_{header_order_hash}
```
- `method`: `ge`=GET, `po`=POST, `pu`=PUT, `de`=DELETE, `he`=HEAD, `op`=OPTIONS
- `ver`: `11`=HTTP/1.1, `10`=HTTP/1.0
- `cookie?`: `c`=cookie present, `n`=no cookie
- `referer?`: `r`=referer present, `n`=no referer
- `num_headers`: 2-digit zero-padded count
- `accept_lang_hash`: 12-char hex of Accept-Language value
- `header_order_hash`: 12-char hex of sorted header names (without values)

Example: `ge11cn_10_en-US,en;q=0_87bceb4bff5a`

**Why JA4H matters:**
- HTTP libraries have very different header ordering (curl, Python requests, Java HttpClient, browser)
- Bots often send minimal headers or headers in an non-browser order
- Language preferences reveal geolocation (even when VPN masks IP)
- Missing expected browser headers (User-Agent structure, Accept-Encoding support) indicates a bot

```python
# src/tap/fingerprints/ja4h.py

def extract_ja4h(http_request: bytes) -> JA4HResult | None:
    """Parse a raw HTTP/1.1 request and return JA4H fingerprint.

    Returns None if the buffer does not start with a valid HTTP request line
    or is incomplete (headers not yet fully received — look for \\r\\n\\r\\n).
    """
    ...

@dataclass
class JA4HResult:
    fingerprint: str
    method: str
    http_version: str
    headers: dict[str, str]     # ordered dict, original case
    accept_language: str | None
    user_agent: str | None       # for correlation and UA fingerprint
    cookie_count: int            # number of cookie values (not Cookie header count)
    referer: str | None
```

---

### 7.5 JA4L — Light Distance Estimation

**New.** Uses TCP handshake timing to estimate the physical distance between the
probe point and the client. "Light distance" = maximum speed of signal in fiber
(~200,000 km/s, ~2/3 speed of light) applied to measured RTT.

**How it works:**

```
Client                 JA4proxy (TAP, at data centre)              Server
  │                              │                                    │
  │─── SYN ─────────────────────►│ ts_syn                             │
  │                              │─── SYN-ACK ───────────────────────►│
  │                              │◄── SYN-ACK ─────────────────────── │ ts_synack
  │◄── SYN-ACK ─────────────────│                                    │
  │─── ACK ─────────────────────►│ ts_ack                             │
```

**Measurement A** (client distance estimate):
```
RTT_client = ts_ack - ts_synack
distance_A = (RTT_client / 2) * 200_000  # km, assuming fiber
```
This estimates the one-way distance from the JA4proxy capture point to the client.

**Measurement B** (server distance estimate):
```
RTT_server = ts_synack - ts_syn   # time for SYN to reach server and SYN-ACK to return
distance_B = (RTT_server / 2) * 200_000  # km
```

**JA4L format:**
```
{distance_A_km}_{distance_B_km}
```
Example: `450_120` (client 450km from probe, server 120km from probe)

**Caveats to document clearly:**
- This is an estimate only. Bufferbloat, CPU scheduler jitter, and TCP processing
  delays can add 1–30ms unrelated to geography.
- Useful for detecting impossible geography claims (VPN user claiming to be nearby
  but with 150ms RTT), not for precise location.
- Compare with GeoIP-reported location: large disagreement = likely VPN.
- **Clock accuracy matters.** Kernel software timestamps have ~1ms jitter → ±100km
  error. Enable `hardware_timestamps: true` on supported NICs (Intel i210/X550,
  Mellanox CX-4+) for <1µs jitter → ±0.2km error. Requires NTP or PPS with
  chrony; set `makestep 1.0 3` and verify offset < 0.5ms before trusting JA4L.
- **ECMP / asymmetric paths** — if SYN and SYN-ACK take different physical paths,
  the timestamps are not a clean RTT measurement. See §5.3 for detection guidance.
- **Duplicate SYN-ACKs** — if dedup is off, a duplicated SYN-ACK with a different
  arrival timestamp will corrupt `synack_ts`. Always enable `dedup_window_ms`.
- The function signature accepts `hardware_ts: bool` to select `SO_TIMESTAMPING`
  hardware vs software timestamps from the packet metadata.

```python
# src/tap/fingerprints/ja4l.py

def extract_ja4l(syn_ts: float, synack_ts: float, ack_ts: float) -> JA4LResult:
    """Calculate JA4L light distance from TCP handshake timestamps.

    Args:
        syn_ts, synack_ts, ack_ts: kernel packet timestamps in seconds (float).
    """
    ...

@dataclass
class JA4LResult:
    fingerprint: str           # e.g. "450_120"
    client_distance_km: float  # estimated distance from probe to client
    server_distance_km: float  # estimated distance from probe to server
    rtt_client_ms: float       # raw RTT used for client estimate
    rtt_server_ms: float       # raw RTT used for server estimate
    geoip_distance_km: float | None  # filled in later if GeoIP available
    distance_mismatch: bool    # True if JA4L and GeoIP disagree by > 500km
```

**Risk signal:** If `distance_mismatch` is True (RTT implies client is far away but
GeoIP says local), add `RiskSignal(source="ja4l", score=+20, reason="geo_rtt_mismatch")`.

---

### 7.6 JA4X — X.509 Certificate Fingerprint

**New.** Parsed from the TLS Certificate message in the **server-to-client** direction.
Available only in TAP mode (in passthrough mode, JA4proxy sees this data but does not
currently parse it).

**What JA4X captures:**

The TLS Certificate message contains the server's certificate chain. Parse the leaf
certificate (first in chain) and extract:

| Field | Notes |
|-------|-------|
| Subject hash | MD5 of the subject DN fields in order |
| Issuer hash | MD5 of the issuer DN fields |
| Key algorithm | `rsa2048`, `rsa4096`, `ec256`, `ec384` |
| Not-before | Year only (e.g. `2024`) |
| Not-after | Year only (e.g. `2025`) |
| SAN hash | MD5 of sorted SAN values (domains/IPs) |
| Self-signed | bool |

**JA4X format:**
```
{issuer_hash}_{subject_hash}_{key_algo}_{san_hash}
```
Example: `3ecf4e0f5e51_a2b4c6d8e0f2_ec256_1a2b3c4d5e6f`

**Why JA4X matters:**
- Detects expired or self-signed certs (likely test/dev servers, possible staging exposed to internet)
- Identifies CDN or cloud provider certificates (Cloudflare uses specific issuers)
- Detects certificate reuse across IPs (the same cert served from multiple IPs = infrastructure pivot)
- Correlates with CT log data for age and reuse analysis

```python
# src/tap/fingerprints/ja4x.py

def extract_ja4x(certificate_message: bytes) -> JA4XResult | None:
    """Parse TLS Certificate message and return JA4X for the leaf certificate."""
    ...

@dataclass
class JA4XResult:
    fingerprint: str
    issuer_dn: str
    subject_dn: str
    key_type: str          # "rsa2048", "ec256", etc.
    not_before: datetime
    not_after: datetime
    san_domains: list[str]
    san_ips: list[str]
    self_signed: bool
    serial: str            # hex
    sha256: str            # full cert hash for CT log correlation
```

---

### 7.7 JA4SSH — SSH Client/Server Fingerprint

**New.** Parsed from the SSH `SSH_MSG_KEXINIT` packet (message type 20), sent by both
client and server immediately after the protocol version exchange.

**What SSH_MSG_KEXINIT contains:**
- 16-byte random cookie
- Preferred key exchange algorithms (list)
- Preferred host key algorithms (list)
- Client→server encryption algorithms (list)
- Server→client encryption algorithms (list)
- Client→server MAC algorithms (list)
- Server→client MAC algorithms (list)
- Client→server compression algorithms (list)
- Server→client compression algorithms (list)
- First-kex-packet-follows (bool)

**JA4SSH format (client):**
```
{num_kex_algs}{num_hostkey_algs}{num_enc_algs}{num_mac_algs}{num_compress_algs}_{kex_hash}_{enc_hash}
```

**JA4SSH format (server):**
Same structure with `s` prefix.

**Why JA4SSH matters:**
- SSH clients have distinct algorithm preferences (OpenSSH 8.x vs PuTTY vs libssh vs Paramiko)
- Scanner tools often send minimal algorithm lists
- Automated attack tools have known JA4SSH signatures

```python
# src/tap/fingerprints/ja4ssh.py

def extract_ja4ssh(kexinit_payload: bytes, direction: str) -> JA4SSHResult | None:
    """Parse SSH_MSG_KEXINIT payload.

    Args:
        direction: "client" or "server"
    """
    ...
```

---

### 7.8 TLS Extension Value Fingerprint (Beyond JA4)

**New.** JA4 hashes extension *types* but discards the *values* inside each extension.
This fingerprint captures the specific values to distinguish clients that present the
same extension types but with different capabilities.

**Additional fields to extract from ClientHello extensions:**

| Extension | Values to capture | Why |
|-----------|------------------|-----|
| supported_groups (0x000a) | EC group IDs in offer order | Chrome offers X25519+P256+P384; old Firefox differs |
| key_share (0x0033) | Group IDs for which keys are included | TLS 1.3 only; reveals preferred group |
| signature_algorithms (0x000d) | Algo IDs in order | Very client-specific ordering |
| psk_key_exchange_modes (0x002d) | Mode values | TLS 1.3 resumption strategy |
| compress_certificate (0x001b) | Algorithms supported | RFC 8879; only modern browsers |
| application_settings (0x4469) | ALPS protocols | Chrome-specific HTTPS ALPS |
| GREASE values (0x?a?a pattern) | Which GREASE values used | Browser indicator; bots rarely send GREASE |

Store these as `JA4TLSExtValues` alongside the main JA4 fingerprint and persist to
Redis so the analytics node can correlate changing extension values from the same IP.

```python
# src/tap/fingerprints/tls_ext_values.py

@dataclass
class JA4TLSExtValues:
    supported_groups: list[int]         # in offer order
    key_share_groups: list[int]         # groups for which public keys sent
    sig_algs: list[int]                 # in offer order
    psk_modes: list[int]
    grease_values: list[int]            # 0x?a?a values found anywhere
    has_compress_cert: bool
    has_alps: bool
    padding_len: int | None             # Chrome pads to avoid fingerprinting; ironic
    session_ticket_len: int             # Hint about resumption history
```

---

### 7.9 OS Fingerprinting (p0f-Style)

**New.** Infers the client OS from TCP/IP stack behaviour visible in the SYN packet.
This is the approach used by p0f, which achieves ~90% accuracy on unmodified stacks.

**Fingerprint fields:**

| Field | Linux defaults | Windows 10/11 | macOS | iOS |
|-------|---------------|---------------|-------|-----|
| TTL | 64 | 128 | 64 | 64 |
| DF bit | Set | Set | Set | Set |
| TCP window size | 64240 | 64240 or 65535 | 65535 | 65535 |
| MSS | 1460 (LAN), 1380 (VLAN) | 1460 | 1460 | 1380 |
| Window scale | 7 | 8 | 6 | 6 |
| TCP option order | MSTNW | MTNWSE | MTNWSE | MTNWSE |
| SACK permitted | Yes | Yes | Yes | Yes |
| Timestamps | Yes | No | Yes | Yes |
| IP ID | Random | Sequential | Random | Random |

**Database approach:** Ship a `../../config/os_fingerprints.yml` file with known signatures.
On each SYN, hash the relevant fields and look up the hash in the database. Provide
a confidence score (exact match = 1.0; partial match = 0.6).

```yaml
# config/os_fingerprints.yml — excerpt
fingerprints:
  - id: "linux_5x_default"
    label: "Linux 5.x (default)"
    ttl: 64
    df: true
    window: 64240
    mss: 1460
    wscale: 7
    options: "MSTNW"
    sack: true
    ts: true

  - id: "windows_10_11"
    label: "Windows 10/11"
    ttl: 128
    df: true
    window: [64240, 65535]   # list = any of these values match
    mss: 1460
    wscale: 8
    options: "MSTNW"
    sack: true
    ts: false
```

**Risk signal:** If the OS fingerprint contradicts the User-Agent (e.g., Chrome/Windows
UA but OS fingerprint matches Linux), add `RiskSignal(score=+15, reason="os_ua_mismatch")`.

```python
# src/tap/fingerprints/os_fingerprint.py

@dataclass
class OSFingerprintResult:
    fingerprint_id: str        # e.g. "linux_5x_default"
    label: str                 # e.g. "Linux 5.x (default)"
    confidence: float          # 0.0 – 1.0
    ttl: int
    df: bool
    window_size: int
    mss: int | None
    wscale: int | None
    options_str: str
    raw_hash: str              # hash of the fields used for lookup
```

---

### 7.10 HTTP/2 SETTINGS Frame Fingerprint

**New.** When a TLS stream carries ALPN `h2`, parse the first HTTP/2 frames from
the **client** direction. The HTTP/2 connection preface is:
```
PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
```
followed immediately by a `SETTINGS` frame and optionally a `WINDOW_UPDATE` frame.

**What to capture:**

| Frame | Fields |
|-------|--------|
| SETTINGS | HEADER_TABLE_SIZE, ENABLE_PUSH, MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, MAX_HEADER_LIST_SIZE, and their **order** |
| WINDOW_UPDATE | Initial window increment value |
| PRIORITY (if sent) | Stream ID and weight of initial PRIORITY frames |

**Known client SETTINGS signatures:**

| Client | HEADER_TABLE_SIZE | ENABLE_PUSH | INITIAL_WINDOW_SIZE | MAX_FRAME_SIZE |
|--------|------------------|-------------|--------------------|--------------|
| Chrome 120 | 65536 | 0 | 6291456 | 16384 |
| Firefox 121 | 65536 | 0 | 131072 | 16384 |
| Safari 17 | 4096 | 0 | 2097152 | 16384 |
| curl 8.x | (omitted) | (omitted) | 65535 | (omitted) |
| Python httpx | 65536 | 0 | 65535 | 16384 |

```python
# src/tap/fingerprints/h2_fingerprint.py

@dataclass
class H2FingerprintResult:
    fingerprint: str           # hash of the SETTINGS values in order
    settings: dict[str, int]   # name → value, e.g. {"INITIAL_WINDOW_SIZE": 6291456}
    settings_order: list[str]  # field names in frame order
    window_update_increment: int | None
    matched_client: str | None # e.g. "Chrome 120" if matched in database
    confidence: float
```

---

### 7.11 QUIC Initial Packet Fingerprint

**New.** QUIC (RFC 9000) is used for HTTP/3. Initial packets are sent in cleartext
and contain the TLS ClientHello embedded in CRYPTO frames. They are carried over UDP,
so the capture BPF filter must include `udp port 443`.

**What to capture:**
- QUIC version field
- Destination Connection ID length and value
- Token length (non-zero = address validation in progress)
- The embedded TLS ClientHello (can compute JA4 from this — set `proto='q'`)
- QUIC transport parameters (available in encrypted extensions, not initial packet)

**QUIC fingerprint format:**
```
q{version_hex}_{dcid_len}_{token_len}_{ja4_from_crypto}
```

Note: QUIC adds another layer of obfuscation; the connection ID and token may not
be stable across connections. Focus on the version and embedded TLS fingerprint.

```python
# src/tap/fingerprints/quic_fingerprint.py

@dataclass
class QUICFingerprintResult:
    quic_version: int          # e.g. 0x00000001 for QUIC v1
    dcid_len: int
    token_len: int
    embedded_ja4: str | None   # JA4 derived from embedded ClientHello
    fingerprint: str
```

---

## 8. Fingerprint Correlation Store

Every extracted fingerprint for a connection must be linked together and to the client
IP. This allows the analytics node to ask: "show me all JA4 fingerprints seen from
this IP" or "find all IPs that have used this JA4 fingerprint."

### 8.1 Per-Connection Fingerprint Record

```python
@dataclass
class ConnectionFingerprints:
    conn_id: str               # UUID generated at stream open
    timestamp: datetime
    client_ip: str
    server_ip: str
    server_port: int

    # Fingerprints (None if not yet extracted or not applicable)
    ja4: str | None
    ja4s: str | None
    ja4t: str | None
    ja4ts: str | None          # server-side TCP fingerprint
    ja4h: str | None
    ja4l: str | None
    ja4x: str | None
    ja4ssh: str | None
    h2_fingerprint: str | None
    quic_fingerprint: str | None
    os_fingerprint: str | None

    # Rich detail (stored separately to keep the main record small)
    tls_ext_values: JA4TLSExtValues | None
    os_detail: OSFingerprintResult | None

    # Derived
    risk_score: int            # 0–100
    action: str                # "observe" | "flag" | "signal_block" | "signal_ban"
    signals: list[dict]        # RiskSignal dicts
```

### 8.2 Redis Keys for Fingerprint Store

```
# Per-connection fingerprint record (TTL 7 days)
fp:conn:{conn_id}                → JSON of ConnectionFingerprints
                                   TTL: 7 days

# IP → connection IDs seen from this IP (Sorted Set, score=timestamp)
fp:ip:{client_ip}                → ZSET {conn_id: timestamp}
                                   Trim to last 1000 entries per IP; TTL 30 days

# JA4 fingerprint → IPs seen using it (HyperLogLog — approximate unique IPs)
fp:ja4:hll:{fingerprint}         → PFADD (12KB, ~0.81% error rate)
                                   TTL: 30 days

# JA4 fingerprint → count (exact counter for alerting)
fp:ja4:count:{fingerprint}       → INCR counter
                                   TTL: 30 days

# OS fingerprint → count per fingerprint
fp:os:count:{fingerprint_id}     → INCR counter
                                   TTL: 30 days

# IP → latest OS fingerprint (overwrite; last seen wins)
fp:os:ip:{client_ip}             → STRING fingerprint_id
                                   TTL: 24 hours

# JA4 → JA4S correlation (which servers does this client fingerprint connect to?)
fp:ja4_to_ja4s:{ja4}             → HSET {ja4s: count}
                                   TTL: 7 days
```

Add these to `docs/REDIS_SCHEMA.md` in the TAP-mode section.

### 8.3 Fingerprint Lookup API (New Management Endpoint)

```
GET /api/v1/fingerprints/ip/{ip}
→ {
    "ip": "1.2.3.4",
    "connection_count": 42,
    "ja4_fingerprints": ["t13d1516h2_...", "t13d1415h2_..."],
    "ja4t_fingerprints": ["65535_1460_MSTNW_8"],
    "os_fingerprints": [{"id": "linux_5x_default", "count": 38, "confidence": 0.95}],
    "latest_risk_score": 67,
    "latest_action": "flag",
    "connections": [ ... last 10 connections ... ]
  }

GET /api/v1/fingerprints/ja4/{fingerprint}
→ {
    "fingerprint": "t13d1516h2_...",
    "unique_ips": 1247,       # HyperLogLog estimate
    "total_connections": 8932,
    "risk_distribution": {"low": 1100, "medium": 80, "high": 67}
  }
```

---

## 9. Risk Scoring Integration

TAP mode feeds the **same** `RiskScorer` used in passthrough mode. The integration
point is `../../src/tap/tap_pipeline.py`, which:

1. Calls each fingerprint extractor as data becomes available.
2. Converts fingerprint results into `RiskSignal` objects.
3. Adds signals from all existing detectors (ASN, Spamhaus, AbuseIPDB, etc.).
4. Calls `RiskScorer.score(signals)`.
5. Translates the resulting score into a TAP-mode action.

### 9.1 TAP-Mode Actions

TAP mode cannot directly block or tarpit. Instead:

| Score range (at dial=100) | Passthrough action | TAP action |
|--------------------------|-------------------|-----------|
| 0–19 | allow | observe (log only) |
| 20–34 | flag | flag (write to Redis, analytics) |
| 35–54 | rate_limit | flag (rate-limit signal via Redis) |
| 55–69 | tarpit | signal_slow (advisory; enforcement layer decides) |
| 70–84 | block | signal_block (write to Redis; enforcement layer blocks) |
| 85–100 | ban | signal_ban (write to Redis; enforcement layer bans) |

`signal_block` and `signal_ban` write the same Redis keys that passthrough mode reads
(`ban:{ip}`, `block_decisions:block:{ip}`), so a passthrough proxy on the same Redis
instance enforces in real time against future connections from that IP.

### 9.2 New Risk Signals From TAP Mode

| Signal source | Score | Condition |
|---------------|-------|-----------|
| `ja4l` | +20 | `distance_mismatch = True` (RTT vs GeoIP disagree > 500km) |
| `os_fingerprint` | +15 | OS fingerprint contradicts User-Agent |
| `tls_ext_values` | +10 | No GREASE values in ClientHello (bots rarely send GREASE) |
| `tls_ext_values` | +20 | JA4 matches known scanner tool signature |
| `ja4s` | +5 | Server cert is self-signed (useful for internal infra visibility) |
| `ja4x` | +15 | Server cert expired (connection to expired cert = unusual) |
| `h2_fingerprint` | +15 | HTTP/2 SETTINGS don't match claimed User-Agent browser/version |
| `ja4ssh` | +25 | SSH kexinit matches known attack tool signature |
| `quic_fingerprint` | +5 | Unknown QUIC version (future-proofing) |

All risk signal additions must pass the existing FP corpus test (Tranco top-10k domains
and known-good browser traffic must produce < 0.5% false positive rate at score > 70).

---

## 10. Enforcement Bridge

The enforcement bridge is a separate asyncio task (`../../src/tap/enforcement_bridge.py`)
that watches Redis for new bans/blocks and pushes them to configured enforcement points.

### 10.1 Redis Subscriber

```python
class EnforcementBridge:
    """Watches Redis pub/sub for ban signals and pushes to enforcement points.

    Runs as an asyncio task inside the TAP-mode proxy process.
    Each enabled enforcement backend (iptables, BGP, webhook) runs independently;
    failure of one does not affect others.
    """

    async def start(self) -> None:
        """Subscribe to ja4proxy:invalidate channel and enforcement-specific channels."""
        ...

    async def _on_ban(self, ip: str, ttl: int, reason: str) -> None:
        """Called when a new ban is published. Dispatches to all enabled backends."""
        results = await asyncio.gather(
            self._iptables_ban(ip, ttl),
            self._bgp_announce(ip),
            self._webhook_ban(ip, ttl, reason),
            return_exceptions=True,
        )
        # Log any backend errors; never let one backend failure affect others.
        ...
```

### 10.2 iptables/ipset Backend

```python
async def _iptables_ban(self, ip: str, ttl: int) -> None:
    """Add IP to the ja4proxy_ban ipset with a TTL.

    ipset handles TTL natively:
        ipset add ja4proxy_ban 1.2.3.4 timeout 3600

    The JA4PROXY_BLOCK chain must have a rule matching this ipset:
        iptables -I INPUT -m set --match-set ja4proxy_ban src -j DROP

    This method runs the ipset command via asyncio.create_subprocess_exec()
    (not shell=True — command injection prevention).
    """
    ...
```

**Setup instructions (document in runbook):**
```bash
# Create ipset with TTL support
ipset create ja4proxy_ban hash:ip timeout 0

# Add iptables rule to use the set
iptables -N JA4PROXY_BLOCK
iptables -I INPUT -m set --match-set ja4proxy_ban src -j DROP
iptables -I FORWARD -m set --match-set ja4proxy_ban src -j DROP

# Persist across reboots
ipset save > /etc/ipset.conf
iptables-save > /etc/iptables/rules.v4
```

### 10.3 BGP Blackhole Backend

```python
async def _bgp_announce(self, ip: str) -> None:
    """Write an ExaBGP command to announce a /32 blackhole route.

    ExaBGP command format:
        announce route 1.2.3.4/32 next-hop 192.0.2.1 community 65535:666

    Written to the ExaBGP named pipe (configured in tap_enforcement.bgp_blackhole.exabgp_pipe).
    """
    ...
```

**ExaBGP config (document in runbook):**
```ini
# /etc/exabgp/exabgp.conf
process ja4proxy-bgp {
    run /usr/bin/python3 -u /opt/ja4proxy/scripts/exabgp_listener.py;
    encoder text;
}

neighbor 192.168.1.1 {
    router-id 192.168.1.2;
    local-as 65000;
    peer-as 65001;

    api {
        processes [ ja4proxy-bgp ];
    }
}
```

### 10.4 Webhook Backend

Generic webhook for any firewall with an HTTP API. Body template substitution:
- `{ip}` → the banned IP
- `{ttl}` → TTL in seconds
- `{reason}` → human-readable reason string
- `{score}` → numeric risk score

Retry with exponential backoff; log persistent failures; emit Prometheus metric
`ja4proxy_tap_enforcement_webhook_errors_total`.

---

## 10.5 Intelligence Export Implementation

### 10.5.1 EDL HTTP Server (`../../src/tap/export/edl_server.py`)

The EDL server is a set of route handlers registered on the existing FastAPI management
server (Phase 13). Lists are rebuilt from Redis on a background task every
`refresh_interval_s` seconds and cached; individual requests are served from the cache.

```python
class EDLServer:
    """Serves External Dynamic Lists (plain-text threat feeds) via HTTP.

    Lists are rebuilt from Redis on a background schedule. Each rebuild
    reads ban:{ip}* keys, ban_cidr:{cidr}* keys, and fp:ip:* scored sets,
    filters by age and min_score, and caches the result with an ETag.

    Endpoints:
        GET /export/edl/banned-ips       → active ban:{ip} keys
        GET /export/edl/banned-cidrs     → active ban_cidr:{cidr} keys
        GET /export/edl/flagged-ips      → IPs scored >= min_score, not yet banned
        GET /export/edl/ja4-blacklist    → ja4:blacklist set members
        GET /export/edl/combined         → union of banned-ips + banned-cidrs
    """

    async def _rebuild_lists(self) -> None:
        """Background task: scan Redis, build lists, update ETag cache."""
        ...

    async def handle_edl_request(
        self, list_name: str, request: Request
    ) -> Response:
        """Serve an EDL list, honouring If-None-Match for efficient polling."""
        cached = self._cache.get(list_name)
        if not cached:
            raise HTTPException(404)
        if request.headers.get("If-None-Match") == cached.etag:
            return Response(status_code=304)
        return Response(
            content=cached.body,
            media_type="text/plain",
            headers={"ETag": cached.etag, "Cache-Control": f"max-age={self.refresh_s}"},
        )
```

**EDL output format example** (for `/export/edl/banned-ips`):
```
# JA4proxy External Dynamic List — banned-ips
# Generated: 2026-03-10T14:23:00Z  Entries: 3  ETag: "a1b2c3d4"
# Fields: ip | last-seen | score | reason
#
1.2.3.4          # 2026-03-10T14:20:00Z score=92 scanner_fingerprint
5.6.7.8          # 2026-03-10T14:10:00Z score=87 tor_exit+datacenter
203.0.113.99     # 2026-03-10T14:05:00Z score=85 abuseipdb_high
```

**Palo Alto NGFW polling setup (Operations → Device → Dynamic Address Groups):**
```
Type: External Dynamic List
Source: http://ja4proxy:8090/export/edl/banned-ips?key=${EDL_API_KEY}
Check for updates: every 1 hour (or 5 minutes for high-sensitivity)
```

**F5 external data group setup (tmsh):**
```tcl
tmsh create ltm data-group external ja4proxy_banned_ips {
    external-file-name ja4proxy_banned_ips
    type ip
}
tmsh create sys file data-group ja4proxy_banned_ips {
    source-path "http://ja4proxy:8090/export/edl/banned-ips?key=SECRET"
}
```

### 10.5.2 F5 BIG-IP Push Client (`../../src/tap/export/f5_client.py`)

```python
class F5Client:
    """Pushes IP lists to F5 BIG-IP internal data groups via iControl REST.

    Maintains an aiohttp.ClientSession (injected at startup — never per-request).
    Performs a full rebuild sync every sync_interval_s and a delta push on
    every ban pub/sub event.

    F5 iControl REST endpoint for data groups:
        PATCH /mgmt/tm/ltm/data-group/internal/{partition}~{name}
    Body: {"records": [{"name": "1.2.3.4/32", "data": "banned"}, ...]}

    Rate limited to max_rps (default 5) because the iControl API is not designed
    for high-frequency updates.
    """

    async def full_sync(self) -> None:
        """Rebuild all configured data groups from Redis and push to F5."""
        ...

    async def delta_push(self, ip: str, action: str) -> None:
        """Add or remove a single IP. action: 'add' | 'remove'"""
        ...

    async def _patch_data_group(self, name: str, records: list[dict]) -> None:
        """PATCH one data group; retry with backoff on 429/5xx."""
        ...
```

**Required iRule on F5 (install once; data group updates automatically):**
```tcl
when CLIENT_ACCEPTED {
    if { [class match [IP::client_addr] equals ja4proxy_banned_ips] } {
        log local0. "JA4proxy: blocking [IP::client_addr]"
        reject
    }
    if { [class match [IP::client_addr] equals ja4proxy_flagged_ips] } {
        # Flagged but not yet banned — log and apply rate limit
        log local0. "JA4proxy: flagging [IP::client_addr]"
    }
}
```

### 10.5.3 Palo Alto Push Client (`../../src/tap/export/palo_alto_client.py`)

```python
class PaloAltoClient:
    """Registers dynamic addresses with Palo Alto NGFW via XML API.

    Uses the PA 'Dynamic Address Group' feature (Objects → Address Groups →
    Type: Dynamic). Tagged IPs are added/removed via the XML API:
        POST /api/?type=user-id&action=set
        Body: <uid-message><payload><register><entry ...><tag><member>
    The DAG filter rule should be: 'tag eq ja4proxy-ban'.

    This requires PAN-OS 8.0+ and a service account with 'User-ID Agent' role.
    """

    async def register_ip(self, ip: str, tags: list[str]) -> None: ...
    async def unregister_ip(self, ip: str, tags: list[str]) -> None: ...
    async def full_sync(self) -> None: ...
```

### 10.5.4 Kafka Producer (`../../src/tap/export/kafka_producer.py`)

```python
class KafkaExporter:
    """Publishes fingerprint events to Kafka topics.

    Uses aiokafka.AIOKafkaProducer. All messages are JSON-encoded. Supports
    optional Avro serialisation via a Confluent Schema Registry.

    Message schema for 'ja4proxy.fingerprints' topic:
    {
      "schema_version": 1,
      "conn_id": "...",
      "timestamp": "2026-03-10T14:23:00Z",
      "client_ip": "1.2.3.4",
      "server_ip": "5.6.7.8",
      "server_port": 443,
      "ja4":  "t13d1516h2_...",
      "ja4s": "s13d01h2_...",
      "ja4t": "65535_1460_MSTNW_8",
      "ja4h": null,
      "ja4l": "450_120",
      "ja4x": "3ecf4e0f5e51_...",
      "os_fingerprint": "linux_5x_default",
      "risk_score": 67,
      "action": "flag",
      "signals": [{"source": "asn", "score": 30, "reason": "datacenter"}]
    }

    Message schema for 'ja4proxy.bans' topic:
    {
      "schema_version": 1,
      "event": "ban" | "unban",
      "ip": "1.2.3.4",
      "score": 87,
      "ttl_s": 3600,
      "reason": "scanner_fingerprint",
      "timestamp": "2026-03-10T14:23:00Z"
    }
    """
```

**Splunk integration** — use the Kafka Connect Splunk Sink or configure a Splunk
Heavy Forwarder with the Kafka consumer app. Index `ja4proxy.bans` to the
`security` index; index `ja4proxy.fingerprints` to `network_traffic`.

**Elastic SIEM integration** — use Filebeat with the Kafka input plugin pointing at
`ja4proxy.*` topics. The `ja4proxy.bans` messages map to the ECS `threat.indicator.*`
field set.

### 10.5.5 Syslog Exporter (`../../src/tap/export/syslog_exporter.py`)

CEF (Common Event Format) is the most widely supported format for security devices.
CEF messages have the structure:
```
CEF:0|JA4proxy|JA4proxy|1.0|{event_id}|{name}|{severity}|{extension}
```

Example ban event in CEF:
```
CEF:0|JA4proxy|JA4proxy|1.0|100|IP Banned|7|src=1.2.3.4 score=87 reason=scanner_fingerprint ja4=t13d1516h2_8daaf6152771_02713d6af862 rt=1741615380000
```

**Severity mapping** (CEF 0–10, higher = more severe):
- `observe` → 3 (Low)
- `flag` → 5 (Medium)
- `signal_block` → 7 (High)
- `signal_ban` → 9 (Very High)

### 10.5.6 STIX/TAXII Server (`../../src/tap/export/taxii_server.py`)

STIX 2.1 indicators are generated from ban events:

```python
# STIX 2.1 Indicator object for a banned IP
indicator = stix2.Indicator(
    name=f"Banned IP: {ip}",
    pattern=f"[ipv4-addr:value = '{ip}']",
    pattern_type="stix",
    valid_from=datetime.now(timezone.utc),
    labels=["malicious-activity"],
    description=f"Risk score: {score}. Reason: {reason}.",
    custom_properties={
        "x_ja4proxy_score": score,
        "x_ja4proxy_ja4": ja4,
        "x_ja4proxy_os": os_fingerprint,
    },
)
```

TAXII 2.1 endpoints (served under `/taxii2/`):
```
GET  /taxii2/                              → TAXII discovery
GET  /taxii2/collections/                  → list collections
GET  /taxii2/collections/{id}/             → collection metadata
GET  /taxii2/collections/{id}/objects/     → STIX bundle (paginated, supports added_after)
POST /taxii2/collections/{id}/objects/     → not supported (read-only feed)
```

### 10.5.7 MISP Push Client (`../../src/tap/export/misp_client.py`)

```python
class MISPClient:
    """Pushes threat indicators to a MISP instance via REST API.

    Creates one MISP Event per day (keyed by date) and adds Attributes to it
    as bans arrive. Publishes the event at EOD or when publish_on_ban is true.

    Attribute types used:
    - 'ip-dst'       for banned destination IPs
    - 'ip-src'       for banned source IPs
    - 'other'        for JA4 fingerprints (custom attribute with comment)

    Avoids creating duplicate attributes by checking existing attributes before
    adding new ones (PyMISP's add_attribute handles this with error check).
    """
```

### 10.5.8 New File Locations for Export Layer

```
src/
  tap/
    export/
      __init__.py
      edl_server.py           # EDL HTTP endpoints (registered on management server)
      f5_client.py            # F5 BIG-IP iControl REST push client
      palo_alto_client.py     # Palo Alto XML API push client
      kafka_producer.py       # Kafka streaming exporter
      syslog_exporter.py      # Syslog / CEF exporter
      taxii_server.py         # STIX/TAXII 2.1 server
      misp_client.py          # MISP push client
      export_manager.py       # Orchestrates all enabled exporters; handles Redis pub/sub

tests/
  tap/
    unit/
      test_edl_server.py      # EDL list building, ETag, age filtering, min_score filter
      test_f5_client.py       # Mock F5 API, full sync, delta push, rate limiting
      test_palo_alto_client.py
      test_kafka_producer.py  # Mock Kafka broker, message schema validation
      test_syslog_exporter.py # CEF format correctness, severity mapping
      test_taxii_server.py    # STIX object structure, TAXII pagination
      test_misp_client.py     # Mock MISP API, dedup logic
    integration/
      test_export_integration.py  # Full pipeline: ban → Redis → all exporters
    chaos/
      test_export_resilience.py   # Each exporter fails; others continue unaffected
```

---

## 11. New File Locations

```
src/
  tap/
    __init__.py
    capture.py              # PacketCapture (AF_PACKET) and PcapReplay
    reassembler.py          # TCPStream, StreamReassembler
    tap_pipeline.py         # TAP-mode orchestration (replaces proxy.py's passthrough loop)
    enforcement_bridge.py   # Redis → iptables / BGP / webhook
    fingerprints/
      __init__.py
      ja4.py                # JA4 from raw bytes (shared with passthrough extractor)
      ja4s.py               # JA4S — TLS server
      ja4t.py               # JA4T — TCP options
      ja4h.py               # JA4H — HTTP/1.1 headers
      ja4l.py               # JA4L — light distance
      ja4x.py               # JA4X — X.509 certificate
      ja4ssh.py             # JA4SSH — SSH kexinit
      tls_ext_values.py     # Extended TLS extension values
      os_fingerprint.py     # p0f-style OS detection
      h2_fingerprint.py     # HTTP/2 SETTINGS fingerprint
      quic_fingerprint.py   # QUIC initial packet fingerprint
      correlation.py        # ConnectionFingerprints dataclass and Redis serialisation

config/
  os_fingerprints.yml       # p0f-style OS signature database
  h2_fingerprints.yml       # Known HTTP/2 SETTINGS signatures per client

tests/
  tap/                      # All TAP-mode tests (separate from passthrough tests)
    __init__.py
    conftest.py             # TAP-specific fixtures: PcapReplay, SyntheticPacketBuilder
    pcap_corpus/            # PCAP files for fingerprint extraction tests
      chrome_120.pcap
      firefox_121.pcap
      safari_17.pcap
      curl_8x.pcap
      python_requests.pcap
      mixed_clients.pcap
      scanner_nmap.pcap
      scanner_masscan.pcap
      ssh_openssh.pcap
      ssh_putty.pcap
      http2_chrome.pcap
      quic_chrome.pcap
    unit/
      test_ja4s.py
      test_ja4h.py
      test_ja4l.py
      test_ja4x.py
      test_ja4ssh.py
      test_os_fingerprint.py
      test_h2_fingerprint.py
      test_quic_fingerprint.py
      test_tls_ext_values.py
      test_reassembler.py
      test_capture.py        # Tests using PcapReplay, not live AF_PACKET
    integration/
      test_tap_pipeline.py   # Full pipeline with PCAP replay
      test_enforcement_bridge.py
    chaos/
      test_tap_resilience.py # OOM, drop events, corrupt packets, truncated streams
    fp_corpus/
      test_fingerprint_accuracy.py  # Known-good fingerprints vs extracted values
```

---

## 11a. Lifecycle Management

### 11a.1 Graceful Shutdown

On `SIGTERM` or `SIGINT`, TAP mode must clean up in order. Unclean shutdown corrupts
stream state, leaks iptables rules, and loses in-flight fingerprint extractions.

```python
async def shutdown(self) -> None:
    """Ordered shutdown sequence for TAP mode.

    1. Stop packet capture — no new packets enter the pipeline.
    2. Signal all workers to finish their current stream buffer (drain mode).
    3. Wait up to 10s for workers to finish. Force-close any remaining streams.
    4. Emit final risk scores for all open streams.
    5. Flush Kafka producer buffer (if enabled).
    6. Flush syslog buffer.
    7. Close enforcement bridge connections.
    8. Close aiohttp ClientSessions (F5, Palo Alto, MISP, AbuseIPDB).
    9. Close Redis connections.
    10. Exit.
    """
    logger.info("tap | event=shutdown_start")
    self._capture.stop()                             # step 1
    await asyncio.wait_for(                          # steps 2–3
        self._drain_workers(), timeout=10.0
    )
    await self._emit_final_scores()                  # step 4
    if self._kafka:
        await self._kafka.flush(timeout=5.0)         # step 5
    self._syslog.close()                             # step 6
    await self._enforcement.close()                  # step 7
    await self._http_sessions.close_all()            # step 8
    await self._redis.close()                        # step 9
    logger.info("tap | event=shutdown_complete")
```

### 11a.2 Hot-Reload Boundaries

On `SIGHUP` or Redis `config_reload` pub/sub, the config is reloaded. The following
table documents exactly which TAP config keys can be hot-reloaded vs require restart:

| Config key | Hot-reloadable? | Notes |
|-----------|----------------|-------|
| `tap.stream_timeout_s` | ✓ | Applied to new streams immediately |
| `tap.tls_ports` / `http_ports` / `ssh_ports` | ✓ | Applied to new streams |
| `tap.max_stream_buffer_bytes` | ✓ | New cap applied to new streams; existing streams use old cap |
| `tap.fingerprint_types.*` | ✓ | New extractions use new config immediately |
| `tap.dedup_window_ms` | ✓ | New window applied to new dedup entries |
| `tap_enforcement.*` | ✓ | New enforcement config applied to next signal |
| `intelligence_export.edl.*` | ✓ | Next rebuild cycle uses new config |
| `intelligence_export.syslog.*` | ✓ | Applied to next event |
| `intelligence_export.kafka.topics.*` | ✓ | New topic names used for new messages |
| `tap.interface` | ✗ restart | AF_PACKET socket must be reopened |
| `tap.ring_buffer_mb` | ✗ restart | Ring buffer mmap must be remapped |
| `tap.capture_workers` | ✗ restart | Thread pool cannot be resized at runtime |
| `tap.promisc` | ✗ restart | Socket option set at bind time |
| `tap.decapsulation` | ✗ restart | Decoder chain set at startup |
| `tap.hardware_timestamps` | ✗ restart | Socket timestamping mode set at open |
| `tap.bpf_filter` | Partial | Can be updated via `SO_ATTACH_FILTER` without restart; emit WARN |
| `intelligence_export.kafka.brokers` | ✗ restart | Producer connection pool must be rebuilt |
| `intelligence_export.f5.host` | ✗ restart | aiohttp session must be rebuilt |
| `mode` | ✗ restart | Changes the I/O architecture |

On hot-reload, log every non-reloadable key change at WARN level:
```
WARN | config | event=reload_requires_restart | key=tap.interface | old=eth0 | new=eth1 | action=change_ignored
```

### 11a.3 Worker Watchdog

Each capture worker runs as an asyncio Task. If a worker raises an unhandled exception,
its shard's TCP streams are orphaned (never evicted, never scored) — a memory leak.

```python
class WorkerWatchdog:
    """Monitors capture worker tasks and restarts crashed workers.

    On worker crash:
    1. Log ERROR with the exception and traceback.
    2. Increment ja4proxy_tap_worker_restarts_total counter.
    3. Evict all streams owned by the crashed shard (emit final scores).
    4. Restart the worker with a fresh state table for that shard.
    5. Emit WARN if the same worker crashes more than 3 times in 60s
       (likely a corrupt packet causing a repeating crash).
    """
    async def _watch(self, worker_id: int, task: asyncio.Task) -> None: ...
    async def _evict_shard(self, shard_id: int) -> None: ...
```

Add metric: `ja4proxy_tap_worker_restarts_total{shard}` — counter, incremented on restart.

---

## 12. Test Framework for TAP Mode

### 12.1 Why TAP Testing Is Different

In passthrough mode, tests inject data via `asyncio.StreamReader` mocks — the proxy
reads from an asyncio stream, which is easily replaced in tests.

In TAP mode, the data path is:
```
Raw socket → ring buffer → packet → reassembler → fingerprint extractor → pipeline
```
There is no asyncio stream to mock. Instead, tests use **PCAP files** as input.

### 12.2 PCAP Corpus

The PCAP corpus lives in `tests/tap/pcap_corpus/`. Each file is a named capture of a
specific client connecting to a test server. Files are committed to git (they are small
— a TLS handshake is < 5KB).

**Generating corpus files:**

```bash
# Capture Chrome 120 TLS handshake to a test server:
tcpdump -i eth0 -w tests/tap/pcap_corpus/chrome_120.pcap \
  'host 192.168.1.100 and tcp port 443' -c 30

# Or use the Scapy-based generator (no real network needed):
python3 scripts/generate_test_pcap.py --client chrome_120 \
  --output tests/tap/pcap_corpus/chrome_120.pcap
```

**PCAP generator** (`../../scripts/generate_test_pcap.py`) builds synthetic captures:
- Takes client profile (known cipher lists, extension lists, TCP options) as input
- Constructs valid Ethernet → IP → TCP → TLS byte sequences using Scapy
- Writes a `.pcap` file with correct per-packet timestamps for JA4L testing

### 12.3 TAP Test Fixtures

```python
# tests/tap/conftest.py

import pytest
from src.tap.capture import PcapReplay
from src.tap.reassembler import StreamReassembler
from src.tap.fingerprints.correlation import ConnectionFingerprints

@pytest.fixture
def pcap_replay(tmp_path):
    """Return a factory: pcap_replay('chrome_120.pcap') → PcapReplay instance."""
    def _make(pcap_name: str, realtime: bool = False):
        pcap_path = Path("tests/tap/pcap_corpus") / pcap_name
        return PcapReplay(pcap_path, realtime=realtime)
    return _make

@pytest.fixture
def synthetic_packets():
    """Return a SyntheticPacketBuilder for constructing arbitrary packet sequences."""
    return SyntheticPacketBuilder()

class SyntheticPacketBuilder:
    """Build synthetic TCP/TLS/HTTP packet sequences for unit testing.

    Usage:
        pkts = (SyntheticPacketBuilder()
                .syn(src="1.2.3.4", sport=12345, dst="5.6.7.8", dport=443,
                     window=65535, mss=1460, wscale=8, options="MSTNW")
                .synack(window=65535, mss=1460)
                .ack()
                .tls_client_hello(ciphers=[...], extensions=[...], sni="example.com")
                .tls_server_hello(cipher=0xc02c, extensions=[...])
                .build())
        # pkts is a list of ParsedPacket ready for StreamReassembler.on_packet()
    """

    def syn(self, src: str, sport: int, dst: str, dport: int, **tcp_opts) -> Self: ...
    def synack(self, **tcp_opts) -> Self: ...
    def ack(self) -> Self: ...
    def tls_client_hello(self, **fields) -> Self: ...
    def tls_server_hello(self, **fields) -> Self: ...
    def http_request(self, method: str, headers: dict[str, str]) -> Self: ...
    def build(self) -> list[ParsedPacket]: ...
```

### 12.4 Fingerprint Accuracy Tests

Each extractor has a test that feeds a known PCAP and asserts the extracted fingerprint
matches the expected value. These are the most important tests — they ensure the
extractors are correct, not just plausible.

```python
# tests/tap/fp_corpus/test_fingerprint_accuracy.py

KNOWN_FINGERPRINTS = {
    "chrome_120.pcap": {
        "ja4": "t13d1516h2_8daaf6152771_02713d6af862",
        "ja4t": "65535_1460_MSTNW_8",
        "os": "linux_5x_default",
        "h2": "chrome_120",
    },
    "firefox_121.pcap": {
        "ja4": "t13d1516h2_003d138fd8c0_11c6a39fef97",
        "ja4t": "65535_1460_MSTNW_7",
        "os": "linux_5x_default",
    },
    "curl_8x.pcap": {
        "ja4": "t13d1516h2_8daaf6152771_72baad21d8c9",
        "ja4t": "65535_1460_MSTNW_7",
        "h2": "curl_8",
    },
    "scanner_nmap.pcap": {
        "ja4": "t13d0100no_0a0a0a0a0a0a_000000000000",
        "ja4t": "1024_1460_M_0",
        "os": "nmap_default",
    },
}

@pytest.mark.parametrize("pcap_name,expected", KNOWN_FINGERPRINTS.items())
def test_fingerprint_extraction_accuracy(pcap_name, expected, pcap_replay):
    """Replay a known PCAP and assert extracted fingerprints match expected values."""
    replay = pcap_replay(pcap_name)
    extractor = FingerprintExtractor(...)
    results = run_replay_to_completion(replay, extractor)

    for fp_type, expected_value in expected.items():
        assert results[fp_type] == expected_value, (
            f"Fingerprint mismatch for {pcap_name} {fp_type}: "
            f"got {results[fp_type]!r}, expected {expected_value!r}"
        )
```

### 12.5 Reassembler Unit Tests

Test the TCP reassembler independently from the fingerprint extractors:

```python
# tests/tap/unit/test_reassembler.py

def test_out_of_order_segments(synthetic_packets):
    """Segments arriving out of order are buffered and flushed in order."""
    ...

def test_retransmission_discarded(synthetic_packets):
    """Retransmitted segments do not corrupt the assembled stream."""
    ...

def test_stream_timeout_emits_score(synthetic_packets, mock_redis):
    """An idle stream is expired and a risk score is emitted after timeout."""
    ...

def test_max_buffer_exceeded_drops_stream(synthetic_packets):
    """A stream exceeding max_stream_buffer_bytes is dropped, not OOM'd."""
    ...

def test_rst_closes_stream(synthetic_packets, mock_redis):
    """A RST packet cleanly closes stream state and emits final score."""
    ...

def test_fragmented_ip_reassembly(synthetic_packets):
    """IPv4 fragments are reassembled before TCP parsing."""
    ...
```

### 12.6 Chaos Tests for TAP Mode

```python
# tests/tap/chaos/test_tap_resilience.py

def test_ring_buffer_drop_metric(mock_af_packet):
    """Simulated ring buffer overflow increments ja4proxy_tap_packets_dropped_total."""
    ...

def test_corrupt_packet_skipped(synthetic_packets):
    """A packet with a truncated IP header is skipped; other packets processed normally."""
    ...

def test_enforcement_bridge_webhook_failure(mock_webhook_server_error, mock_redis):
    """Webhook failure does not prevent iptables or BGP enforcement from succeeding."""
    ...

def test_bgp_pipe_unavailable(mock_redis):
    """Missing ExaBGP pipe increments error counter, does not crash enforcement bridge."""
    ...

def test_stream_table_at_max_capacity(synthetic_packets, mock_redis):
    """When max_streams reached, oldest streams are evicted before adding new ones."""
    ...
```

### 12.7 Running TAP Tests

TAP tests are included in `make test` (they use PCAP replay, not a live interface).
The only tests that require a real network interface are in `tests/tap/integration/` with
a `@pytest.mark.requires_tap_interface` marker. These are excluded by default:

```bash
# Run all tests including TAP (uses PCAP replay — no live interface needed)
make test

# Run TAP tests only
make test-tap

# Run TAP integration tests (requires a real interface and sudo)
make test-tap-live INTERFACE=eth1
```

Add to Makefile:
```makefile
test-tap:
	@python3 -m pytest tests/tap/ -n $(WORKERS) --dist=loadfile --timeout=60 --tb=short $(ARGS)

test-tap-live:
	@[ -n "$(INTERFACE)" ] || (echo "Usage: make test-tap-live INTERFACE=eth1"; exit 1)
	@sudo python3 -m pytest tests/tap/integration/ --timeout=120 --tb=short \
	    -k "requires_tap_interface" -v $(ARGS)

test-tap-perf:
	@python3 scripts/tap_benchmark.py --interface $(INTERFACE) --pcap $(PCAP)
```

### 12.8 False-Positive Corpus Tests

The FP corpus test is the most important correctness gate — it ensures new risk signals
do not produce unacceptable false positive rates against known-good real-world traffic.

**Setup (one-time, not in git):**
```bash
# Download the Tranco top-10k domain list
curl -s https://tranco-list.eu/top-1m.csv.zip | \
  python3 scripts/extract_tranco.py --top 10000 > tests/tap/fp_corpus/tranco_10k.txt

# Collect PCAP samples for those domains (requires a real browser + tcpdump)
# Or use the synthetic generator for a representative sample:
python3 scripts/generate_fp_corpus_pcap.py \
  --domains tests/tap/fp_corpus/tranco_10k.txt \
  --output tests/tap/fp_corpus/tranco_sample.pcap \
  --clients chrome_120,firefox_121,safari_17
```

**Test file** (`../../tests/tap/fp_corpus/test_fingerprint_fp_rate.py`):
```python
def test_fp_rate_tranco_top10k(pcap_replay, mock_redis, tap_pipeline):
    """Risk signals for top-10k traffic should produce < 0.5% FP rate at score > 70.

    FP = a known-good domain/connection scored > 70 and actioned as signal_block or
    signal_ban. Flag (score 20–69) is acceptable for legitimate hosting providers.
    """
    replay = pcap_replay("tranco_sample.pcap")
    results = run_replay_to_completion(replay, tap_pipeline)

    high_score = [r for r in results if r.risk_score > 70]
    fp_rate = len(high_score) / len(results)

    assert fp_rate < 0.005, (
        f"FP rate {fp_rate:.3%} exceeds 0.5% threshold. "
        f"High-scored connections:\n"
        + "\n".join(f"  {r.client_ip} score={r.risk_score} signals={r.signals}"
                    for r in high_score[:20])
    )
```

### 12.9 Performance Benchmark (`../../scripts/tap_benchmark.py`)

```python
"""Benchmark TAP pipeline throughput using tcpreplay.

Usage:
    # Replay a PCAP at 1Gbps and measure packets processed vs dropped:
    sudo python3 scripts/tap_benchmark.py \\
        --interface eth1 \\
        --pcap tests/tap/pcap_corpus/mixed_clients.pcap \\
        --rate-mbps 1000 \\
        --duration 30

Output:
    Packets injected:   1,284,732
    Packets captured:   1,284,730  (99.99%)
    Packets dropped:            2  (0.00%)
    Streams completed:     42,158
    Fingerprints/s:       140,527  (JA4: 42158, JA4S: 42001, JA4T: 42158)
    Throughput: 1,002 Mbps
    Peak ring buffer fill: 18%
    Workers: 6 — max queue depth: 142 (worker 3)
"""
```

The benchmark must pass before accepting the 500k pps claim in acceptance criteria 17b.

---

## 13. Observability

### 13.1 Prometheus Metrics

All new metrics follow the `ja4proxy_tap_{subsystem}_{metric}_{unit}` naming convention.

**Capture metrics:**

| Metric name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `ja4proxy_tap_packets_captured_total` | Counter | `proto` (tcp/udp) | Packets received from ring buffer |
| `ja4proxy_tap_packets_dropped_total` | Counter | — | Ring buffer overflow drops |
| `ja4proxy_tap_packets_duplicates_total` | Counter | — | Packets discarded by dedup filter |
| `ja4proxy_tap_ring_buffer_fill_ratio` | Gauge | — | Ring buffer fill 0.0–1.0 (sample every 100ms) |
| `ja4proxy_tap_capture_interface_up` | Gauge | `interface` | 1 if NIC link is up, 0 if down |
| `ja4proxy_tap_pcap_kernel_drops_total` | Counter | — | Kernel-level drops before ring buffer |

**Stream reassembly metrics:**

| Metric name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `ja4proxy_tap_streams_active` | Gauge | — | Currently tracked TCP streams |
| `ja4proxy_tap_streams_total` | Counter | `close_reason` (fin/rst/timeout/evicted) | Streams completed |
| `ja4proxy_tap_streams_evicted_total` | Counter | `reason` (timeout/capacity) | Separate timeout vs OOM eviction |
| `ja4proxy_tap_stream_buffer_bytes` | Histogram | — | Bytes buffered per stream at close |
| `ja4proxy_tap_reassembly_lag_ms` | Histogram | — | Time from packet receipt to fingerprint |
| `ja4proxy_tap_worker_restarts_total` | Counter | `shard` | Worker crash + restart events |

**Fingerprint metrics:**

| Metric name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `ja4proxy_tap_fingerprint_extracted_total` | Counter | `type` (ja4/ja4s/ja4h/ja4l/ja4x/ja4ssh/os/h2/quic) | Successful extractions |
| `ja4proxy_tap_fingerprint_failed_total` | Counter | `type`, `reason` | Failed/incomplete extractions |
| `ja4proxy_tap_os_match_total` | Counter | `os_label`, `confidence_bucket` (high/medium/low) | OS fingerprint matches |
| `ja4proxy_tap_ja4l_distance_km` | Histogram | `direction` (client/server) | Light distance distribution |
| `ja4proxy_tap_ja4l_mismatch_total` | Counter | — | GeoIP vs RTT distance disagreements |

**Enforcement metrics:**

| Metric name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `ja4proxy_tap_enforcement_signals_total` | Counter | `action`, `backend` | Enforcement signals sent |
| `ja4proxy_tap_enforcement_errors_total` | Counter | `backend`, `error` | Backend errors |
| `ja4proxy_tap_enforcement_latency_ms` | Histogram | `backend` | Per-backend enforcement latency |

**Export metrics:**

| Metric name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `ja4proxy_tap_edl_requests_total` | Counter | `list`, `result` (hit/304) | EDL HTTP requests served |
| `ja4proxy_tap_edl_list_size` | Gauge | `list` | Current entry count per EDL list |
| `ja4proxy_tap_export_messages_total` | Counter | `exporter` (kafka/syslog/f5/pa/misp/taxii) | Messages sent per exporter |
| `ja4proxy_tap_export_errors_total` | Counter | `exporter`, `error` | Per-exporter errors |
| `ja4proxy_tap_export_latency_ms` | Histogram | `exporter` | Time to deliver one event |

### 13.2 Alerting Rules (AlertManager)

Add to `config/alertmanager_rules.yml` (or `../../monitoring/alertmanager/rules/tap.yml`):

```yaml
groups:
  - name: ja4proxy_tap
    rules:

      - alert: TapPacketDropRateHigh
        expr: rate(ja4proxy_tap_packets_dropped_total[1m]) > 100
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "TAP ring buffer dropping packets"
          description: "{{ $value | humanize }} packets/s dropped. Increase ring_buffer_mb or reduce capture_workers load."

      - alert: TapPacketDropRateCritical
        expr: rate(ja4proxy_tap_packets_dropped_total[1m]) > 1000
        for: 30s
        labels:
          severity: critical
        annotations:
          summary: "TAP ring buffer dropping packets at critical rate"

      - alert: TapCaptureInterfaceDown
        expr: ja4proxy_tap_capture_interface_up == 0
        for: 30s
        labels:
          severity: critical
        annotations:
          summary: "TAP capture interface {{ $labels.interface }} is down"
          description: "No traffic is being observed. Check SPAN port configuration."

      - alert: TapStreamTableNearCapacity
        expr: ja4proxy_tap_streams_active / 100000 > 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "TAP stream table at {{ $value | humanizePercentage }} capacity"
          description: "Consider increasing max_streams or reducing stream_timeout_s."

      - alert: TapWorkerCrashing
        expr: rate(ja4proxy_tap_worker_restarts_total[5m]) > 0.1
        labels:
          severity: warning
        annotations:
          summary: "TAP worker shard {{ $labels.shard }} is crashing repeatedly"

      - alert: TapEnforcementBackendFailing
        expr: rate(ja4proxy_tap_enforcement_errors_total[5m]) > 10
        labels:
          severity: warning
        annotations:
          summary: "TAP enforcement backend {{ $labels.backend }} is failing"
          description: "Bans are not being enforced by this backend."

      - alert: TapExportBacklogBuilding
        expr: ja4proxy_tap_export_latency_ms{quantile="0.99"} > 5000
        labels:
          severity: warning
        annotations:
          summary: "TAP export to {{ $labels.exporter }} is slow (p99={{ $value }}ms)"
```

### 13.3 Grafana Dashboard (TAP Sensor)

Create `../../monitoring/grafana/dashboards/tap_sensor.json`. Panel layout:

**Row 1 — Capture Health:**
- `ja4proxy_tap_capture_interface_up` — stat panel (green/red)
- `rate(ja4proxy_tap_packets_captured_total[1m])` — graph, pps
- `rate(ja4proxy_tap_packets_dropped_total[1m])` — graph, red if > 0
- `ja4proxy_tap_ring_buffer_fill_ratio` — gauge (0–100%)

**Row 2 — Stream Reassembly:**
- `ja4proxy_tap_streams_active` — stat
- `rate(ja4proxy_tap_streams_total[1m])` by `close_reason` — stacked bar
- `histogram_quantile(0.99, ja4proxy_tap_reassembly_lag_ms)` — p99 latency
- `rate(ja4proxy_tap_worker_restarts_total[5m])` — alert row

**Row 3 — Fingerprints:**
- `rate(ja4proxy_tap_fingerprint_extracted_total[1m])` by `type` — stacked area
- `ja4proxy_tap_os_match_total` by `os_label` — pie chart (top 10 OS types)
- `histogram_quantile(0.5, ja4proxy_tap_ja4l_distance_km)` — median client distance

**Row 4 — Enforcement & Export:**
- `rate(ja4proxy_tap_enforcement_signals_total[5m])` by `action` — bar
- `rate(ja4proxy_tap_enforcement_errors_total[5m])` by `backend` — alert line
- `ja4proxy_tap_edl_list_size` by `list` — stat panels
- `rate(ja4proxy_tap_export_messages_total[1m])` by `exporter` — stacked bar

**Row 5 — Risk Score Distribution:**
- Reuse `ja4proxy_risk_score_distribution` histogram from passthrough dashboard
- `rate(ja4proxy_tap_ja4l_mismatch_total[5m])` — GeoIP/RTT mismatches

### 13.4 Health Endpoint Extensions

The existing `/health` endpoint (Phase 13) must be extended for TAP mode:

```python
# GET /health response in TAP mode:
{
  "status": "healthy",   # "healthy" | "degraded" | "unhealthy"
  "mode": "tap",
  "capture": {
    "interface": "eth1",
    "link_up": true,
    "packets_captured": 1284732,
    "packets_dropped": 0,
    "ring_buffer_fill": 0.03,    # 0.0 – 1.0
    "status": "healthy"
  },
  "reassembler": {
    "streams_active": 4821,
    "streams_capacity": 100000,
    "fill_ratio": 0.048,
    "status": "healthy"
  },
  "enforcement": {
    "iptables": "healthy",
    "bgp": "not_configured",
    "webhook": "healthy"
  },
  "export": {
    "edl": "healthy",
    "kafka": "not_configured",
    "f5": "healthy",
    "syslog": "degraded",        # if last syslog send failed
    "taxii": "not_configured",
    "misp": "not_configured"
  },
  "redis": "healthy"
}
```

Status rules:
- `healthy` if all checks pass
- `degraded` if non-critical subsystem failing (e.g., one export backend down)
- `unhealthy` if capture interface down, ring buffer critically full, or Redis unreachable

### 13.5 Structured Log Schema

Every TAP-mode log event must follow the existing `key=value` format. New events:

```
# Packet capture
INFO  | tap | event=capture_started    | interface=eth1 | bpf_filter="tcp or udp" | ring_buffer_mb=256 | workers=6
WARN  | tap | event=ring_buffer_drop   | count=142 | interval_ms=1000 | fill_ratio=0.97
WARN  | tap | event=interface_down     | interface=eth1
INFO  | tap | event=interface_up       | interface=eth1

# Stream lifecycle
DEBUG | tap | event=stream_opened      | conn_id=abc | src=1.2.3.4:12345 | dst=5.6.7.8:443
DEBUG | tap | event=stream_closed      | conn_id=abc | reason=fin | duration_ms=342 | bytes_client=1842 | bytes_server=4201
WARN  | tap | event=stream_evicted     | conn_id=abc | reason=timeout | streams_active=98234
WARN  | tap | event=stream_buffer_cap  | conn_id=abc | max_bytes=65536 | action=dropped

# Fingerprint extraction
DEBUG | tap | event=ja4_extracted      | conn_id=abc | fingerprint=t13d1516h2_8daaf6152771_02713d6af862
DEBUG | tap | event=ja4l_calculated    | conn_id=abc | client_km=450 | server_km=120 | mismatch=false
WARN  | tap | event=ja4l_geo_mismatch  | conn_id=abc | client_ip=1.2.3.4 | rtt_km=2100 | geoip_km=50 | delta_km=2050

# Enforcement
INFO  | tap | event=signal_ban         | ip=1.2.3.4 | score=87 | reason=scanner_fingerprint | backends=iptables,redis
WARN  | tap | event=enforcement_fail   | backend=iptables | ip=1.2.3.4 | error=ipset_not_found | retries=3
INFO  | tap | event=bgp_announce       | ip=1.2.3.4 | prefix=1.2.3.4/32 | community=65535:666

# Export
INFO  | tap | event=edl_rebuild        | list=banned-ips | entries=142 | duration_ms=23
WARN  | tap | event=export_error       | exporter=kafka | error=broker_unavailable | message_count=17
INFO  | tap | event=f5_sync            | data_group=ja4proxy_banned_ips | entries=142 | duration_ms=412
```

---

## 14. Mode Switching — Detailed Behaviour

### 14.1 At Startup

`proxy.py` (or `main.go` after Phase 15) reads `config/proxy.yml` and branches:

```python
match config.mode:
    case "passthrough":
        server = PassthroughServer(config)
        await server.run()
    case "tap":
        sensor = TapSensor(config)
        await sensor.run()
    case _:
        raise ConfigError(f"Unknown mode: {config.mode!r}. Must be 'passthrough' or 'tap'.")
```

Both modes share:
- `ConfigLoader` (hot reload via SIGHUP, except `mode` key)
- `LocalCache`
- `PubSubHandler`
- `RiskScorer`
- `ActionDecider`
- All signal collectors (ASN, AbuseIPDB, RDAP, etc.)
- Prometheus metrics server
- Management API server

Only `mode` itself requires a restart. All other config keys follow the existing hot-reload rules.

**Startup log (INFO level):**
```
INFO | startup | event=mode_selected | mode=tap | interface=eth1 | workers=6
INFO | startup | event=mode_note | msg="tap mode: proxy does not block traffic; enforcement via Redis/iptables/BGP"
```

### 14.2 Switching From Passthrough to TAP

1. Edit `config/proxy.yml`: change `mode: passthrough` → `mode: tap`
2. Ensure the network switch/TAP device is configured to mirror the target port to this host's interface.
3. Restart the proxy (`systemctl restart ja4proxy`).
4. Verify with: `curl http://localhost:9090/api/v1/mode`
5. Monitor `ja4proxy_tap_packets_captured_total` — should increase immediately.

**What stops:** The TCP listen socket on port 8080 (passthrough) is closed.
**What starts:** AF_PACKET socket on the configured interface.
**Traffic impact:** Zero — the traffic path does not route through JA4proxy in TAP mode.
**Risk:** If enforcement bridge is enabled, the proxy can now add iptables rules. Verify
the BPF filter and `max_streams` before enabling enforcement in production.

### 14.3 Switching From TAP to Passthrough

1. Edit `config/proxy.yml`: change `mode: tap` → `mode: passthrough`
2. Ensure HAProxy (or the upstream load balancer) is configured to send traffic through
   this host's TCP port 8080.
3. Restart the proxy.
4. Verify with: `curl http://localhost:9090/api/v1/mode`
5. Remove the SPAN/mirror port configuration from the switch (optional — extra traffic
   arriving on the TAP interface is harmless if no AF_PACKET socket is open).

**Warning:** Switching to passthrough mode while the enforcement bridge is active may
leave iptables rules that block traffic the passthrough proxy now needs to allow.
Check `ipset list ja4proxy_ban` and flush if needed: `ipset flush ja4proxy_ban`.

### 14.4 Running Both Modes Simultaneously

Two JA4proxy instances can run on the same host:
- Instance A: `mode: passthrough` on port 8080 — handles inline traffic
- Instance B: `mode: tap` on eth1 — generates intelligence from mirrored traffic

Both instances share the same Redis instance. Bans written by Instance B (TAP) are
enforced by Instance A (passthrough) via the existing `ban:{ip}` Redis key mechanism.
This is the recommended production architecture for maximum coverage.

```yaml
# Instance A: config/proxy.yml (passthrough)
mode: passthrough
passthrough:
  listen_port: 8080

# Instance B: config/proxy-tap.yml (TAP sensor)
mode: tap
tap:
  interface: eth1
```

---

## 14a. Security Hardening

### 14a.1 Privilege Minimisation

TAP mode requires elevated capabilities only during socket setup. Drop them immediately
after:

```python
def _setup_socket_and_drop_privileges(self) -> socket.socket:
    """Open AF_PACKET socket then drop CAP_NET_RAW.

    Requires: CAP_NET_RAW at process start (setcap or sudo).
    After this function, the process has no elevated capabilities.
    """
    import ctypes, ctypes.util
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, ...)
    sock.bind((self.interface, 0))
    if self.config.hardware_timestamps:
        self._set_hardware_timestamps(sock)
    self._set_bpf_filter(sock, self.config.bpf_filter)

    # Drop CAP_NET_RAW via libcap
    libcap = ctypes.CDLL(ctypes.util.find_library("cap"))
    cap = libcap.cap_get_proc()
    libcap.cap_clear(cap)
    if libcap.cap_set_proc(cap) != 0:
        logger.warning("tap | event=cap_drop_failed | msg=could not drop capabilities")
    libcap.cap_free(cap)
    logger.info("tap | event=cap_dropped | msg=CAP_NET_RAW dropped after socket open")
    return sock
```

For iptables enforcement (`CAP_NET_ADMIN`): the enforcement bridge runs as a **separate
subprocess** (`src/tap/enforcement_bridge_process.py`) that retains `CAP_NET_ADMIN` but
communicates only via a Unix socket with the main process. This confines the elevated
capability to the smallest possible scope.

### 14a.2 seccomp Profile

After socket setup, restrict the syscall surface of the capture process to the minimum
needed. A permissive starting profile is provided in `../../config/seccomp_tap.json`.
Key restrictions:
- **Deny** `execve` / `execveat` — prevents shell injection from corrupt packet data
- **Deny** `ptrace` — prevents process inspection
- **Deny** `open` with `O_CREAT` outside of permitted paths — prevents PCAP exfiltration
- **Allow** `recvfrom`, `sendto`, `mmap`, `munmap`, `read`, `write`, `epoll_wait` — needed for capture

Apply at startup:
```python
import seccomp
f = seccomp.SyscallFilter(defaction=seccomp.ALLOW)
for syscall in ("execve", "execveat", "ptrace", "fork", "vfork"):
    f.add_rule(seccomp.KILL, syscall)
f.load()
```

### 14a.3 Webhook TLS Validation and Signing

The webhook enforcement backend (`tap_enforcement.webhook`) must:

1. **Verify TLS** — `verify_tls: true` is the default. When false, emit WARN at startup:
   ```
   WARN | tap | event=webhook_tls_disabled | effect=vulnerable to MITM enforcement manipulation
   ```

2. **Sign requests with HMAC-SHA256** — to prevent a MITM from spoofing 200 OK responses
   and convincing JA4proxy that a ban was applied when it was not:
   ```yaml
   tap_enforcement:
     webhook:
       hmac_secret: "${WEBHOOK_HMAC_SECRET}"   # shared secret with the webhook receiver
   ```
   JA4proxy adds `X-JA4Proxy-Signature: sha256=<hmac>` to every request. The receiver
   validates it. Requests without a valid signature are rejected (HTTP 401).

### 14a.4 BGP Injection Protection

The BGP blackhole backend can cause **serious network disruption** if Redis is
compromised and an attacker writes arbitrary `ban:{ip}` keys:
- An attacker could ban `0.0.0.0/0` → JA4proxy announces a null route for all traffic
- An attacker could ban CDN prefixes → all CDN-served content becomes unreachable

Mitigations:
1. **Prefix length guard** — never announce a prefix broader than `/24` (IPv4) or `/48` (IPv6):
   ```yaml
   bgp_blackhole:
     min_prefix_length_v4: 24    # refuse to announce /23 or broader
     min_prefix_length_v6: 48
   ```
2. **Prefix allow-list** — only announce prefixes that fall within configured ranges:
   ```yaml
   bgp_blackhole:
     allowed_prefix_ranges: ["1.2.3.0/24", "5.6.0.0/16"]  # empty = allow all /32s
   ```
3. **Rate limit** — max N BGP announcements per minute (default 60). Alerts if exceeded.
4. **Redis AUTH + TLS** — already required by Phase 14. Ensure Redis is not exposed.
5. The BGP bridge emits a WARN for every announcement and increments a Prometheus counter.

### 14a.5 PCAP Replay Path Validation

The `tap.pcap_file` config key must be validated to prevent path traversal:

```python
def _validate_pcap_path(path: str, allowed_dirs: list[str]) -> Path:
    """Resolve path and ensure it is within an allowed directory.

    Raises ConfigError for paths outside allowed_dirs or that don't exist.
    Default allowed_dirs: ["tests/tap/pcap_corpus/", "pcap/"]
    """
    resolved = Path(path).resolve()
    for allowed in allowed_dirs:
        if str(resolved).startswith(str(Path(allowed).resolve())):
            return resolved
    raise ConfigError(f"pcap_file {path!r} is outside allowed directories: {allowed_dirs}")
```

### 14a.6 PII / GDPR for Fingerprint Store

The `fp:*` Redis keys store IP addresses (PII in GDPR jurisdictions), SNI hostnames,
User-Agents, and connection timing. Apply the same data-minimisation controls as
passthrough mode (Phase 14):

- All `fp:conn:{conn_id}` keys have a 7-day TTL maximum (reduce in high-privacy deployments).
- Provide a `make gdpr-delete IP=1.2.3.4` target that deletes all `fp:ip:{ip}` and
  associated `fp:conn:{conn_id}` entries for a given IP (data subject erasure request).
- Document in the privacy notice that IP addresses and TLS metadata are processed
  for security purposes under legitimate interest (Article 6(1)(f) GDPR).
- The EDL server, F5, and Palo Alto integrations transmit IP addresses to external
  devices — document data flows in the Record of Processing Activities (RoPA).

### 14a.7 ARP / ND Spoofing — False Ban Risk

In TAP mode, an attacker on the same Layer-2 segment as the probe can:
1. Send ARP replies mapping a victim's IP to the attacker's MAC.
2. Establish a malicious connection that scores poorly (scanner fingerprint, Tor exit, etc.).
3. JA4proxy bans the victim's IP address (which the attacker has temporarily impersonated).

Mitigation: **never ban an IP in TAP mode without corroboration from a second signal source.**
Specifically:
- Single-signal bans (e.g., just a bad JA4 fingerprint alone) require score ≥ 90.
- Bans based on combined signals (JA4 + ASN + AbuseIPDB) can use the normal threshold (≥ 85).
- Document this risk in the runbook. On networks where ARP spoofing is a concern, use
  802.1X port authentication or dynamic ARP inspection (DAI) to prevent impersonation.

---

## 15. Deployment Guide (Runbook)

### 15.1 Switch SPAN Port (Cisco IOS Example)

```
! Mirror port Gi0/1 (internet uplink) to Gi0/10 (TAP interface)
monitor session 1 source interface GigabitEthernet0/1 both
monitor session 1 destination interface GigabitEthernet0/10
```

### 15.2 Switch SPAN Port (Linux Bridge / Open vSwitch)

```bash
# OVS: mirror all traffic on br0 to tap0
ovs-vsctl -- set Bridge br0 mirrors=@m \
  -- --id=@source get Port eth0 \
  -- --id=@tap get Port tap0 \
  -- --id=@m create Mirror name=ja4proxy-mirror select-all=true output-port=@tap
```

### 15.3 Cloud Mirror Ports

| Cloud | Service | Notes |
|-------|---------|-------|
| AWS | VPC Traffic Mirroring | Costs money; mirror filter needed to select TLS traffic |
| GCP | Packet Mirroring | Free for same-zone; policy required |
| Azure | vNET TAP | Preview; limited regions |

### 15.4 Capability Setup (Avoid Running as Root)

```bash
# Grant CAP_NET_RAW to the python binary (or the ja4proxy binary in Go)
sudo setcap cap_net_raw+ep /usr/bin/python3.12

# Or grant it to the specific virtual environment:
sudo setcap cap_net_raw+ep $(which python3)

# Verify:
getcap $(which python3)
# python3 = cap_net_raw+ep
```

For iptables enforcement, `CAP_NET_ADMIN` is only required by the enforcement bridge
subprocess (see §14a.1). If running as a single process:
```bash
sudo setcap 'cap_net_raw,cap_net_admin+ep' /usr/bin/python3.12
```

### 15.5 Diagnostics

**Verify AF_PACKET socket is open and receiving:**
```bash
# See all open AF_PACKET sockets
cat /proc/net/packet
# Columns: sk RefCnt Type Proto Iface  R Rmem   User Inode
# Look for Type=3 (SOCK_RAW), Proto=0x0800 (IP) on your interface

# Check for kernel-level drops
ip -s link show eth1
# RX:  bytes   packets  errors  dropped  missed   mcast
# Look at "dropped" and "missed" — these are before the ring buffer

# AF_PACKET statistics (per socket)
ss -0 --packet

# Monitor ring buffer fill in real time
watch -n1 'python3 -c "
import socket, struct, ctypes
# Read /proc/net/packet for drop stats
with open(\"/proc/net/packet\") as f: print(f.read())
"'
```

**Verify BPF filter is installed correctly:**
```bash
# Dump BPF bytecode for a filter expression
tcpdump -d 'tcp or (udp and port 443)'
# If JA4proxy BPF filter is wrong, it will silently capture nothing or everything
```

**Verify deduplication is working:**
```bash
# Check Prometheus metric: if ja4proxy_tap_packets_duplicates_total is zero on a
# bonded interface, dedup may not be triggering. Capture with tcpdump to verify:
sudo tcpdump -i eth1 -w /tmp/test.pcap -c 1000
tcpdump -r /tmp/test.pcap | sort | uniq -d | head
```

**Verify fingerprint extraction:**
```bash
# Query the fingerprint API for a known test IP
curl http://localhost:8090/api/v1/fingerprints/ip/1.2.3.4 | python3 -m json.tool

# Replay a known PCAP and check extracted fingerprints match expected
python3 -c "
from src.tap.capture import PcapReplay
# ... (see §12 test framework)
"
```

**Diagnose enforcement not working:**
```bash
# Check iptables ipset
sudo ipset list ja4proxy_ban

# Check if JA4PROXY_BLOCK chain is in INPUT/FORWARD
sudo iptables -L INPUT -n | grep JA4PROXY
sudo iptables -L FORWARD -n | grep JA4PROXY

# Check ExaBGP pipe
ls -la /var/run/exabgp/exabgp.cmd
echo "show neighbor summary" > /var/run/exabgp/exabgp.cmd

# Check webhook connectivity
curl -v -X POST "${WEBHOOK_URL}" \
  -H "Authorization: Bearer ${FIREWALL_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"ip":"192.0.2.1","ttl":60,"reason":"test"}'
```

**Check EDL is serving correctly:**
```bash
curl -v "http://localhost:8090/export/edl/banned-ips?key=${EDL_API_KEY}"
# Expect: 200 with text/plain body, ETag header
# Re-request with ETag:
curl -v -H 'If-None-Match: "the-etag-value"' \
  "http://localhost:8090/export/edl/banned-ips?key=${EDL_API_KEY}"
# Expect: 304 Not Modified
```

### 15.6 Rollback — Emergency IP Unban

If the enforcement bridge bans a legitimate IP (false positive), roll back immediately:

```bash
# 1. Remove from Redis (stops future enforcement signals)
redis-cli -a "${REDIS_PASSWORD}" DEL "ban:1.2.3.4"
redis-cli -a "${REDIS_PASSWORD}" PUBLISH "ja4proxy:invalidate" '{"type":"ban_release","value":"1.2.3.4"}'

# 2. Remove from iptables ipset
sudo ipset del ja4proxy_ban 1.2.3.4

# 3. Withdraw BGP route (if BGP is configured)
echo "withdraw route 1.2.3.4/32 next-hop 192.0.2.1" > /var/run/exabgp/exabgp.cmd

# 4. Or use the management API (preferred):
curl -X DELETE "http://localhost:8090/api/v1/ban/1.2.3.4" \
  -H "Authorization: Bearer ${MGMT_API_KEY}"
# This triggers the pub/sub ban_release, iptables removal, and BGP withdraw in one call.

# 5. Flush ALL bans (nuclear option — emergency only):
make flush-redis
sudo ipset flush ja4proxy_ban
# BGP: check with your NOC; withdrawing all blackhole routes may need bgp clear
```

### 15.7 iptables / ipset Drift Reconciliation

Over time, iptables/ipset rules may drift out of sync with Redis if JA4proxy restarts
without clean shutdown. Run a periodic reconciliation:

```bash
# Add to crontab (run every 5 minutes):
*/5 * * * * python3 /opt/ja4proxy/scripts/reconcile_ipset.py \
  --redis-host localhost --redis-password "${REDIS_PASSWORD}" \
  --ipset-name ja4proxy_ban >> /var/log/ja4proxy/reconcile.log 2>&1
```

`../../scripts/reconcile_ipset.py` does:
1. Read all `ban:{ip}` keys from Redis (with TTLs)
2. Read all entries from `ipset list ja4proxy_ban`
3. Add missing entries (in Redis but not in ipset)
4. Remove stale entries (in ipset but not in Redis, or Redis TTL expired)
5. Log a summary; emit `ja4proxy_tap_ipset_reconcile_total` metric

### 15.8 Offline PCAP Analysis

Replay a historical PCAP file to retroactively score IPs from a past incident:

```bash
# Set pcap_file in config (or override via environment):
JA4PROXY_TAP_PCAP_FILE=/path/to/incident.pcap \
  python3 -m ja4proxy --config config/proxy.yml --mode tap --once

# "once" flag: process pcap_file to completion then exit (don't loop).
# Scores are written to Redis as normal; can be queried via management API.
# Use a separate Redis DB (db=1) to avoid polluting production state:
JA4PROXY_REDIS_DB=1 ... python3 -m ja4proxy ...
```

---

## 16. CHANGELOG Entry

```markdown
## [20.0.0] - TBD - TAP/SPAN Passive Fingerprinting Mode + Intelligence Export

### Added
- Passive TAP/SPAN capture mode (`mode: tap` in proxy.yml)
- AF_PACKET TPACKET_V3 ring-buffer capture engine (multi-Mpps throughput)
- VxLAN/GENEVE decapsulation for cloud mirror ports (AWS VPC, Azure vNET TAP)
- Duplicate packet deduplication (bonded/LAG SPAN port dedup)
- Hardware timestamp support (SO_TIMESTAMPING) for sub-µs JA4L accuracy
- PCAP replay and SyntheticPacketBuilder for testing (no live interface required)
- TCP stream reassembler with out-of-order, retransmission, fragment, and IPv6 handling
- Worker watchdog with automatic shard crash recovery
- JA4S: TLS server fingerprint from ServerHello
- JA4H: HTTP/1.1 client header fingerprint
- JA4L: Light-distance estimation from TCP handshake RTT (with GeoIP mismatch signal)
- JA4X: X.509 certificate fingerprint from TLS Certificate message
- JA4SSH: SSH client/server fingerprint from KEXINIT
- OS fingerprinting (p0f-style, 90%+ accuracy from TCP SYN options)
- HTTP/2 SETTINGS-frame fingerprint (distinguishes Chrome/Firefox/Safari/curl)
- QUIC Initial-packet fingerprint
- TLS extension value fingerprint (key_share groups, GREASE, PSK modes)
- Fingerprint correlation store (all variants linked by connection ID in Redis)
- Enforcement bridge: iptables/ipset, BGP blackhole via ExaBGP, webhook (with HMAC)
- Intelligence export: EDL HTTP server, F5 BIG-IP REST API, Palo Alto XML API
- Intelligence export: Kafka streaming, Syslog/CEF, STIX/TAXII 2.1, MISP push
- Fingerprint lookup API: /api/v1/fingerprints/ip/{ip} and /fingerprints/ja4/{fp}
- 30+ new Prometheus metrics (capture, reassembly, fingerprint, enforcement, export)
- AlertManager rules for all critical TAP-mode failure modes
- Grafana TAP sensor dashboard (tap_sensor.json)
- Health endpoint extended with TAP capture, reassembler, enforcement, and export status
- Structured log schema for all TAP-mode events
- Graceful shutdown sequence (ordered 10-step drain)
- Security hardening: privilege drop after socket open, seccomp profile, BGP injection guards
- GDPR data erasure endpoint for fingerprint store
- 13 new risk signals including JA4L geo-mismatch, OS/UA contradiction, GREASE absence
- FP corpus test (Tranco top-10k, < 0.5% FP rate)
- Performance benchmark script (scripts/tap_benchmark.py)
- Offline PCAP analysis mode (--once flag)
- ipset drift reconciliation script (scripts/reconcile_ipset.py)
- Runbook: diagnostics, emergency rollback, reconciliation, offline analysis

### Changed
- `proxy.py` / `main.go` now branches on `mode: passthrough|tap` at startup
- `config/proxy.yml` extended with `tap:`, `tap_enforcement:`, and `intelligence_export:` sections
- `docs/REDIS_SCHEMA.md` extended with TAP-mode `fp:*` key patterns
- `requirements.txt` extended with scapy, dpkt, pypcap, sortedcontainers, aiokafka, stix2
```

---

## 17. Acceptance Criteria

All criteria must pass before this phase is complete.

### 17a. Infrastructure

- [ ] `make test` passes with all TAP tests included (PCAP replay, no live interface)
- [ ] `mode: tap` starts without error; `mode: passthrough` continues to work unchanged
- [ ] Starting with `mode: invalid_value` produces a clear `ConfigError` and exits 1
- [ ] `CAP_NET_RAW` is the only capability required for capture-only operation
- [ ] Running two instances (passthrough + TAP) sharing one Redis instance: bans written by TAP are enforced by passthrough within 1 Redis pub/sub round trip

### 17b. Packet Capture

- [ ] `PacketCapture` can sustain 500k pps on the test machine without drops (verified by `../../scripts/tap_benchmark.py`)
- [ ] VLAN-tagged frames (802.1q) are correctly stripped before IP parsing
- [ ] QinQ (802.1ad) double-tagged frames are correctly stripped
- [ ] VxLAN-encapsulated frames are decapsulated when `decapsulation: vxlan`
- [ ] IPv4 fragments are reassembled correctly (test: ClientHello split across two fragments)
- [ ] IPv6 extension headers are walked correctly to find fragment header (type 44)
- [ ] Duplicate packets from bonded SPAN are discarded and counted by `ja4proxy_tap_packets_duplicates_total`
- [ ] `ja4proxy_tap_packets_dropped_total` increments when ring buffer overflows (chaos test)
- [ ] `ja4proxy_tap_ring_buffer_fill_ratio` gauge reaches 1.0 during the overflow chaos test
- [ ] BPF filter compilation failure emits a clear error and exits 1 (not a silent capture of all traffic)
- [ ] `ja4proxy_tap_capture_interface_up` goes to 0 when the interface link drops (simulated with `ip link set eth1 down`)

### 17c. TCP Reassembler

- [ ] Out-of-order segments: final assembled data is identical to in-order delivery (property test with 1000 permutations)
- [ ] Retransmitted segments do not produce duplicate data in assembled stream
- [ ] Streams idle for `stream_timeout_s` are expired and their state freed
- [ ] Streams exceeding `max_stream_buffer_bytes` are dropped; a metric is emitted; other streams are unaffected
- [ ] RST packet immediately closes stream and emits final score
- [ ] Maximum stream table size (`max_streams`) is respected; oldest idle streams are evicted first
- [ ] Worker crash (unhandled exception in worker Task) triggers watchdog restart within 1s; shard streams evicted; `ja4proxy_tap_worker_restarts_total` incremented
- [ ] Graceful shutdown completes within 15s under normal load (drain + score + flush)

### 17d. Fingerprint Extractors

- [ ] JA4 from PCAP replay matches JA4 computed by an independent reference implementation (FoxIO's `ja4` tool) for all corpus PCAPs
- [ ] JA4S is extracted from ServerHello and stored with the connection record
- [ ] JA4T matches JA4T from reference tool for all corpus PCAPs
- [ ] JA4H is extracted from HTTP/1.1 requests on ports in `tap.http_ports`
- [ ] JA4L: for a synthesised PCAP with known inter-packet timestamps, distance estimates are within ±50km of expected
- [ ] JA4X: extracted cert hash matches `openssl x509 -fingerprint -sha256` for the same cert
- [ ] JA4SSH: extracted fingerprint for OpenSSH 8.x client matches known-good value
- [ ] OS fingerprint: Chrome on Linux is identified as `linux_5x_default` with confidence ≥ 0.8
- [ ] HTTP/2 SETTINGS: Chrome 120 SETTINGS match `chrome_120` entry in `../../config/h2_fingerprints.yml`
- [ ] QUIC Initial packet: QUIC version is extracted correctly for QUIC v1 (0x00000001)
- [ ] Extractors return `None` (not raise) for truncated or malformed input
- [ ] False positive rate of new risk signals against Tranco top-10k corpus: < 0.5% at score threshold 70

### 17e. Fingerprint Store

- [ ] `fp:conn:{conn_id}` is written to Redis within 100ms of stream close
- [ ] `fp:ip:{ip}` Sorted Set is trimmed to 1000 entries per IP
- [ ] `fp:ja4:hll:{fingerprint}` PFADD is called for each unique JA4 observed
- [ ] `/api/v1/fingerprints/ip/{ip}` returns correct data for a known test IP
- [ ] `/api/v1/fingerprints/ja4/{fp}` returns correct count for a known test fingerprint

### 17f. Risk Scoring Integration

- [ ] All new risk signals (§9.2) have unit tests with boundary values
- [ ] Risk score for `scanner_nmap.pcap` is ≥ 70 (nmap should be blocked)
- [ ] Risk score for `chrome_120.pcap` is ≤ 10 (real browser should pass)
- [ ] `signal_ban` action causes `ban:{ip}` to be written to Redis with TTL

### 17g. Enforcement Bridge

- [ ] iptables backend: `ipset add ja4proxy_ban {ip} timeout {ttl}` is executed for each `signal_ban` (chaos test with mock subprocess)
- [ ] BGP backend: correct ExaBGP announce command is written to pipe for each ban (mock pipe test)
- [ ] BGP prefix length guard: prefixes broader than /24 (IPv4) or /48 (IPv6) are rejected and not announced
- [ ] Webhook backend: HMAC-SHA256 signature header present on every request; request rejected on signature mismatch (mock receiver test)
- [ ] Webhook backend: correct JSON body is sent; retries on 5xx; gives up after `retry_count`; emits metric
- [ ] Failure of one backend does not prevent others from running (`asyncio.gather(return_exceptions=True)`)
- [ ] `ban_ttl_s` is respected: iptables/ipset entry has correct timeout

### 17h. Intelligence Export

- [ ] EDL `/export/edl/banned-ips` returns only IPs currently in `ban:{ip}` Redis keys, within `max_age_s`
- [ ] EDL returns 304 Not Modified when ETag matches (efficient polling)
- [ ] EDL requires API key when `api_key` is configured; returns 403 without key
- [ ] EDL IP access control: returns 403 for IPs not in `allowed_ips` when configured
- [ ] F5 client: full sync pushes all banned IPs to the configured data group (mock F5 API test)
- [ ] F5 client: delta push fires within 5s of Redis ban pub/sub event
- [ ] F5 client: respects `max_rps` rate limit (mock F5 API, measure request timing)
- [ ] Palo Alto client: `register_ip` calls XML API with correct tag (mock PA API test)
- [ ] Kafka producer: ban events appear in `ja4proxy.bans` topic with correct JSON schema
- [ ] Kafka producer: message key is the client IP (enables partition affinity for per-IP ordering)
- [ ] Syslog exporter: CEF format is valid per ArcSight CEF specification (validate with test parser)
- [ ] Syslog exporter: severity mapping matches `severity_map` config
- [ ] TAXII server: `GET /taxii2/collections/{id}/objects/` returns valid STIX 2.1 bundle
- [ ] TAXII server: `added_after` query parameter filters correctly
- [ ] MISP client: ban creates an Attribute in the daily event with type `ip-dst`
- [ ] Failure of any one export backend does not affect other exporters

### 17i. Security

- [ ] `CAP_NET_RAW` is dropped after socket `bind()` (verified by reading `/proc/{pid}/status` for `CapEff`)
- [ ] PCAP replay path traversal: `pcap_file: "../../etc/passwd"` raises `ConfigError` and exits 1
- [ ] Webhook TLS validation: `verify_tls: false` emits startup WARN (chaos test checks log)
- [ ] BGP injection guard: attempting to announce a /16 prefix logs ERROR and increments error metric; no BGP command is written
- [ ] GDPR erasure: `make gdpr-delete IP=1.2.3.4` deletes all `fp:ip:1.2.3.4` and linked `fp:conn:*` keys

### 17j. Tests

- [ ] Test-to-code ratio ≥ 1.3× for all new `src/tap/` code
- [ ] All new extractors have at least one test per format field they populate
- [ ] FP corpus test passes: Tranco top-10k PCAP sample scores < 0.5% FP rate at score threshold 70
- [ ] Performance benchmark passes: `../../scripts/tap_benchmark.py` shows ≥ 500k pps without drops
- [ ] PCAP corpus covers: Chrome, Firefox, Safari, curl, Python requests, nmap, masscan, OpenSSH, PuTTY, HTTP/2, QUIC, VxLAN-encapsulated
- [ ] IPv6 corpus: at least one PCAP with IPv6 clients; JA4/JA4T/JA4L extracted correctly
- [ ] `SyntheticPacketBuilder` is tested: builds valid TCP/TLS packet sequences the reassembler processes correctly
- [ ] Chaos tests cover: ring buffer overflow, corrupt packet, truncated TLS record, stream table full, all enforcement backends failing, all export backends failing, worker crash

### 17k. Documentation

- [ ] `docs/REDIS_SCHEMA.md` updated with all `fp:*` key patterns and `intelligence_export` Redis usage
- [ ] Runbook `../runbooks/tap_mode.md`: SPAN setup, capability setup, mode switching, enforcement, export, diagnostics, rollback, reconciliation, offline analysis
- [ ] `config/proxy.yml` inline comments explain every new key in `tap:`, `tap_enforcement:`, and `intelligence_export:`
- [ ] `CHANGELOG.md` updated per §16
- [ ] ADR-020.md: AF_PACKET vs pcap/Scapy vs PF_RING/DPDK decision
- [ ] ADR-021.md: EDL pull vs push for external firewall integration; why both are supported
- [ ] Privacy notice / RoPA updated to document `fp:*` Redis data and EDL/F5/PA data flows

### 17l. Phase 19 Gap Remediation

- [ ] `backup.schedule` config key is wired to an asyncio periodic task that triggers backups
      automatically (P19-G1)
- [ ] Backup loop uses `redis.pipeline()` in batches of 1000 keys (P19-G3)
- [ ] Restore raises `RestoreError` if the fraction of failed key-restores exceeds the
      configured threshold (default 5%); logs count of failed keys (P19-G4)
- [ ] Fakeredis-based encode→backup→restore round-trip integration test passes (P19-G6)

---

## 18. Phase 13 Dependency — Standalone HTTP Server

Phase 20 introduces several HTTP endpoints (EDL, fingerprint lookup, `/mode`, `/health`
extension). These are specified to mount on the Phase 13 management API server (port 8090).
Phase 13 is **DEFERRED** with no timeline. This section defines how Phase 20 provides
these endpoints without requiring Phase 13.

### 18.1 Approach: Lightweight TAP HTTP Server

When `mode: tap` and Phase 13 management server is not running, a lightweight aiohttp
HTTP server (`src/tap/http_server.py`) starts automatically on the same port (8090 by
default, configurable via `tap.http_port`).

This server provides exactly the endpoints Phase 20 needs:

| Endpoint | Implementation | Notes |
|----------|---------------|-------|
| `GET /api/v1/mode` | `TapHttpServer._handle_mode()` | Always available in TAP mode |
| `GET /api/v1/fingerprints/ip/{ip}` | `TapHttpServer._handle_fp_ip()` | Reads `fp:ip:*` from Redis |
| `GET /api/v1/fingerprints/ja4/{fp}` | `TapHttpServer._handle_fp_ja4()` | Reads `fp:ja4:*` from Redis |
| `GET /health` | `TapHttpServer._handle_health()` | TAP-mode health struct (§13.4) |
| `GET /export/edl/*` | `EDLServer.handle_edl_request()` | Registered as route handlers |
| `GET /taxii2/*` | `TaxiiServer.handle_taxii_request()` | Registered as route handlers |

```python
# src/tap/http_server.py

class TapHttpServer:
    """Lightweight aiohttp server providing TAP-mode HTTP endpoints.

    Starts automatically when mode=tap and Phase 13 management server is absent.
    When Phase 13 is later implemented, these routes migrate to it; this server
    is replaced by route registration on the Phase 13 app.

    Port: tap.http_port (default: 8090, same as Phase 13 management server)
    """

    def __init__(self, config: TapConfig, redis: Redis,
                 edl_server: EDLServer, taxii_server: TaxiiServer,
                 sensor: "TapSensor") -> None: ...

    async def start(self) -> None:
        """Create aiohttp.web.Application, register routes, start runner."""
        ...

    async def stop(self) -> None:
        """Graceful shutdown: drain connections, stop runner."""
        ...

    async def _handle_mode(self, request: web.Request) -> web.Response: ...
    async def _handle_fp_ip(self, request: web.Request) -> web.Response: ...
    async def _handle_fp_ja4(self, request: web.Request) -> web.Response: ...
    async def _handle_health(self, request: web.Request) -> web.Response: ...
```

### 18.2 Phase 13 Forward-Compatibility

When Phase 13 is implemented, the `TapHttpServer` is replaced by registering the
same route handler functions on the Phase 13 FastAPI application. No handler logic
changes — only the mount point differs. The transition is a one-line config change
and does not require re-testing the handlers.

Document in `docs/decisions/ADR-022.md`:
- Decision: TAP HTTP server is standalone for Phase 20, migrates to Phase 13 when available
- Why: Phase 13 deferred; TAP mode cannot wait; handlers are decoupled from the server
- How to migrate: register `TapHttpServer` routes on the Phase 13 `app` instance

### 18.3 Prometheus / Metrics Server

The Prometheus `/metrics` endpoint is served by the existing metrics HTTP server
already set up in the proxy (not Phase 13). No change needed — TAP mode registers
its Prometheus metrics at import time (same pattern as all other phases).

### 18.4 Acceptance Criteria (Phase 13 Dependency)

- [ ] Starting `mode: tap` brings up `TapHttpServer` on `tap.http_port` (default 8090)
- [ ] `GET /api/v1/mode` returns `{"mode": "tap", ...}` within 100ms
- [ ] `GET /health` returns a TAP-mode health struct (§13.4)
- [ ] `GET /export/edl/banned-ips` returns the EDL list (with API key auth)
- [ ] `TapHttpServer` shuts down cleanly as step 7 of the graceful shutdown sequence (§11a.1)
- [ ] ADR-022.md written documenting the standalone-to-Phase-13 migration path

---

## 19. Phase 19 Gap Remediation

This section details the four Phase 19 gaps assigned to Phase 20 in `docs/phases/manifest.yaml`.
These are independent of TAP mode and can be implemented first (Group 0 in the work plan).

### 19.1 P19-G1 — Backup Schedule Executor

**Problem:** `backup.schedule` is a documented config key but has no runtime executor.
Backups must be triggered manually or by external cron.

**Fix:** Wire the schedule to an asyncio periodic task inside `BackupManager`.

```python
# src/backup/backup_manager.py — additions

class BackupManager:

    async def start_scheduler(self) -> None:
        """Start the background backup scheduler if backup.schedule is set.

        Reads backup.schedule.cron (cron expression) or backup.schedule.interval_s.
        Creates an asyncio Task that fires run_backup() on schedule.
        Logs at INFO on each backup start/finish; WARN on failure.
        """
        schedule = self.config.get("backup.schedule")
        if not schedule or not schedule.get("enabled", False):
            return
        if "cron" in schedule:
            self._scheduler_task = asyncio.create_task(
                self._cron_loop(schedule["cron"])
            )
        elif "interval_s" in schedule:
            self._scheduler_task = asyncio.create_task(
                self._interval_loop(schedule["interval_s"])
            )

    async def stop_scheduler(self) -> None:
        """Cancel the scheduler task cleanly."""
        if self._scheduler_task:
            self._scheduler_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._scheduler_task

    async def _interval_loop(self, interval_s: int) -> None:
        """Fire run_backup() every interval_s seconds."""
        while True:
            await asyncio.sleep(interval_s)
            try:
                await self.run_backup()
            except Exception as exc:
                logger.warning("backup | event=scheduled_backup_failed | error=%s", exc)
```

Config additions to `config/proxy.yml`:
```yaml
backup:
  schedule:
    enabled: false         # set true to enable automatic scheduled backups
    interval_s: 86400      # backup every 24 hours; mutually exclusive with cron
    cron: null             # e.g. "0 2 * * *" for 2am daily; overrides interval_s
    # Requires: APScheduler if using cron expressions (pip install apscheduler)
    # For simple intervals, interval_s requires no additional dependencies.
```

**Tests (`tests/unit/test_backup_scheduler.py`):**
```python
async def test_scheduler_starts_when_enabled()
async def test_scheduler_does_not_start_when_disabled()
async def test_scheduler_fires_backup_after_interval()
async def test_scheduler_logs_warn_on_backup_failure()
async def test_stop_scheduler_cancels_task()
async def test_scheduler_cron_expression_parsed()
```

### 19.2 P19-G3 — Backup Loop Pipeline Batching

**Problem:** The backup loop calls `redis.dump(key)` sequentially for each key.
At 5M+ keys this is extremely slow (5M round trips).

**Fix:** Batch keys in groups of 1000, send as a Redis pipeline.

```python
# src/backup/backup_manager.py — modification to run_backup()

PIPELINE_BATCH_SIZE = 1000

async def _dump_keys_batched(self, keys: list[str]) -> dict[str, bytes | None]:
    """Dump key values using Redis pipeline batching.

    Processes keys in batches of PIPELINE_BATCH_SIZE to minimise round trips.
    Returns {key: serialised_value} mapping; None values = key expired mid-backup.
    """
    result: dict[str, bytes | None] = {}
    for batch_start in range(0, len(keys), PIPELINE_BATCH_SIZE):
        batch = keys[batch_start : batch_start + PIPELINE_BATCH_SIZE]
        pipe = self.redis.pipeline(transaction=False)
        for key in batch:
            pipe.dump(key)
        values = await pipe.execute(raise_on_error=False)
        for key, value in zip(batch, values):
            result[key] = value if not isinstance(value, Exception) else None
    return result
```

**Tests (`tests/unit/test_backup_pipeline_batching.py`):**
```python
def test_keys_split_into_batches_of_1000()
async def test_pipeline_executed_once_per_batch()
async def test_expired_key_returns_none_not_exception()
async def test_5000_keys_uses_5_pipeline_calls()
```

### 19.3 P19-G4 — RestoreError on Key-Failure Threshold

**Problem:** Restore silently skips failed keys. An operator has no way to know
that 50% of their security state was not restored.

**Fix:** Count failed keys and raise `RestoreError` if the failure fraction exceeds
the configured threshold (default 5%).

```python
# src/backup/backup_manager.py — modification to restore()

class RestoreError(Exception):
    """Raised when restore fails more than the configured threshold of keys."""
    def __init__(self, failed: int, total: int, threshold: float) -> None:
        self.failed = failed
        self.total = total
        self.threshold = threshold
        super().__init__(
            f"Restore aborted: {failed}/{total} keys failed "
            f"({failed/total:.1%} > {threshold:.0%} threshold)"
        )

async def restore(self, backup_path: Path) -> RestoreResult:
    """Restore from backup file.

    Raises RestoreError if fraction of failed keys > backup.restore_error_threshold.
    Default threshold: 0.05 (5%).
    Always logs: total keys, restored keys, failed keys, skipped keys.
    """
    threshold = self.config.get("backup.restore_error_threshold", 0.05)
    failed_keys: list[str] = []
    ...
    if total > 0 and len(failed_keys) / total > threshold:
        logger.error(
            "backup | event=restore_threshold_exceeded | failed=%d | total=%d | threshold=%.0f%%",
            len(failed_keys), total, threshold * 100,
        )
        raise RestoreError(len(failed_keys), total, threshold)
    return RestoreResult(...)
```

**Tests (`tests/unit/test_backup_restore_error.py`):**
```python
async def test_restore_raises_when_failures_exceed_threshold()
async def test_restore_succeeds_when_failures_below_threshold()
async def test_restore_error_message_includes_counts()
async def test_restore_threshold_configurable()
async def test_restore_logs_failed_key_count()
async def test_restore_threshold_zero_means_any_failure_raises()
```

### 19.4 P19-G6 — Fakeredis Round-Trip Integration Test

**Problem:** No integration test verifies that `encode → backup → restore` produces
bit-for-bit identical Redis state.

**Fix:** Add a fakeredis-based test in `tests/integration/test_backup_roundtrip.py`.

```python
# tests/integration/test_backup_roundtrip.py

@pytest.mark.asyncio
async def test_encode_backup_restore_roundtrip(tmp_path):
    """Full round-trip: populate fakeredis → backup → clear → restore → verify identical."""
    redis = fakeredis.aioredis.FakeRedis()
    # Seed representative key types used by the proxy
    await redis.set("ban:1.2.3.4", "1", ex=3600)
    await redis.sadd("ja4:blacklist", "t13d1516h2_aabbccddeeff_aabbccddeeff")
    await redis.hset("visitor:5.6.7.8", mapping={"first_seen": "100", "total": "5"})
    await redis.zadd("beacon:1.2.3.4:t13d", {f"1000.0:abc": 1000.0})

    manager = BackupManager(config=..., redis=redis)
    backup_path = tmp_path / "test.bak"
    await manager.run_backup(output_path=backup_path)

    # Clear all keys
    await redis.flushdb()
    assert await redis.dbsize() == 0

    # Restore
    await manager.restore(backup_path)

    # Verify state is identical
    assert await redis.get("ban:1.2.3.4") == b"1"
    assert await redis.sismember("ja4:blacklist", "t13d1516h2_aabbccddeeff_aabbccddeeff")
    assert await redis.hget("visitor:5.6.7.8", "total") == b"5"
    beacon_members = await redis.zrange("beacon:1.2.3.4:t13d", 0, -1)
    assert len(beacon_members) == 1

@pytest.mark.asyncio
async def test_backup_file_is_deterministic(tmp_path):
    """Two backups of identical state produce identical files (byte-for-byte)."""
    ...

@pytest.mark.asyncio
async def test_restore_preserves_ttls(tmp_path):
    """Keys with TTL are restored with TTL within ±2 seconds of original."""
    ...
```

---
