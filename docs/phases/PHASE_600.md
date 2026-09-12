# QUIC/JA4Q Passive Sensing

## Goal
Implement an **optional** UDP-based QUIC-Initial decoder in the `cmd/ja4-tap` binary to support JA4Q fingerprinting and close the "blind spot" in passive network monitoring.

## Background
Phase 316 (Go TAP/SPAN Passive Sensor) delivered a robust TCP-based sensor (316a-316e) but explicitly deferred QUIC support. As HTTP/3 adoption grows (driven by Cloudflare, Google, and Apple), a significant portion of legitimate and malicious traffic is moving to UDP. Without QUIC support, the TAP sensor cannot see, fingerprint, or enforce against these connections.

## Scope
1.  **Optional Feature**: QUIC support is disabled by default (`--enable-quic` flag or `quic.enabled: false` in `config/tap.yml`). It can be enabled by the operator.
2.  **UDP Capture**: Extend the AF_PACKET capture loop to process UDP frames on port 443 when enabled.
3.  **QUIC-Initial Parsing**: Decode the QUIC Initial packet (Long Header) to extract the Version and DCID.
4.  **QUIC Decryption (Mandatory)**: QUIC Initial packets are AEAD-encrypted. The sensor must have access to decryption keys (via `QUIC_SECRET_LOG` env var pointing to a key log file) to extract the encapsulated TLS ClientHello.
5.  **JA4Q Fingerprinting**: Implement the JA4Q algorithm based on the JA4+ specification.
6.  **Redis Integration**: Write `fp:ja4q:ip:{ip}` to Redis (advisory-only, like Phase 316c).
7.  **Metrics**: Add `ja4proxy_tap_quic_*` counters for QUIC-specific telemetry.

## Implementation Plan

### Step 1: Optional Feature Toggle (cmd/ja4-tap/main.go)

Add a `--enable-quic` flag to the `cmd/ja4-tap` binary. When disabled, UDP packets are dropped immediately in `ProcessPacket`.

```go
// In main.go
var (
    enableQUIC = flag.Bool("enable-quic", false, "enable QUIC/UDP capture and JA4Q fingerprinting (requires QUIC_SECRET_LOG env var for decryption)")
)

// In Sensor struct (internal/tap/sensor.go)
type Sensor struct {
    decoder    *decoder
    pool       *reassembly.StreamPool
    asm        *reassembly.Assembler
    quic       *quic.Decoder  // nil when QUIC disabled
    events     chan HandshakeEvent
}

func NewSensor(linkType layers.LinkType, eventBuffer int, enableQUIC bool) *Sensor {
    s := &Sensor{
        events: make(chan HandshakeEvent, eventBuffer),
    }
    if enableQUIC {
        s.quic = quic.NewDecoder()
    }
    // ... existing TCP setup ...
    return s
}
```

### Step 2: Extend the Decoder for UDP (internal/tap/decode.go)

The current `decoder` returns `(netFlow, *layers.TCP, ttl, ok)`. We replace this with a `decodeResult` struct to support both TCP and UDP.

```go
type Proto int

const (
    ProtoTCP Proto = iota
    ProtoUDP
    ProtoUnsupported
)

type decodeResult struct {
    NetFlow gopacket.Flow
    TCP     *layers.TCP
    UDP     *layers.UDP
    TTL     uint8
    Proto   Proto
}

func (d *decoder) decode(data []byte) decodeResult {
    _ = d.parser.DecodeLayers(data, &d.decoded)
    var res decodeResult
    res.Proto = ProtoUnsupported
    for _, lt := range d.decoded {
        switch lt {
        case layers.LayerTypeIPv4:
            res.NetFlow = d.ip4.NetworkFlow()
            res.TTL = d.ip4.TTL
        case layers.LayerTypeIPv6:
            res.NetFlow = d.ip6.NetworkFlow()
            res.TTL = d.ip6.HopLimit
        case layers.LayerTypeTCP:
            res.TCP = &d.tcp
            res.Proto = ProtoTCP
        case layers.LayerTypeUDP:
            res.UDP = &d.udp
            res.Proto = ProtoUDP
        }
    }
    return res
}
```

### Step 3: Update Sensor.ProcessPacket (internal/tap/sensor.go)

Route UDP packets to the QUIC decoder when enabled.

```go
func (s *Sensor) ProcessPacket(data []byte, ci gopacket.CaptureInfo) {
    PacketsReceivedTotal.Inc()
    res := s.decoder.decode(data)

    switch res.Proto {
    case ProtoTCP:
        if res.TCP == nil { return }
        s.asm.AssembleWithContext(res.NetFlow, res.TCP, &assemblerCtx{ci: ci, ttl: res.TTL})
    case ProtoUDP:
        if s.quic == nil {
            PacketsDroppedTotal.WithLabelValues(dropQUICDisabled).Inc()
            return
        }
        if res.UDP == nil || res.UDP.DstPort != 443 {
            PacketsDroppedTotal.WithLabelValues(dropNonQUICPort).Inc()
            return
        }
        ev, err := s.quic.DecodeInitial(res.NetFlow, res.UDP, ci, res.TTL)
        if err != nil {
            PacketsDroppedTotal.WithLabelValues(dropQUICDecode).Inc()
            return
        }
        if ev != nil {
            s.deliver(*ev)
        }
    default:
        PacketsDroppedTotal.WithLabelValues(dropUnsupported).Inc()
    }
}
```

### Step 4: QUIC Decoder & Eviction (internal/quic/decoder.go)

Place the QUIC decoder in `internal/quic/` (sibling to `internal/tap/`) to avoid circular dependencies.

**Eviction Bounds (DoS Protection):**
```go
const (
    maxQUICActive       = 4096          // max tracked QUIC connections
    maxQUICCryptoBytes  = 16384         // max buffered CRYPTO frame bytes per connection
    quicHandshakeTTL    = 30 * time.Second // matches idleFlushInterval
)
```

**Decoder Structure:**
```go
package quic

import (
    "sync"
    "time"
    "github.com/gopacket/gopacket"
    "github.com/gopacket/gopacket/layers"
)

type Decoder struct {
    active map[quicConnID]*QUICHandshake
    mu     sync.Mutex // Protects active map (though Sensor is single-goroutine, defensive)
}

func NewDecoder() *Decoder {
    return &Decoder{
        active: make(map[quicConnID]*QUICHandshake, 256),
    }
}

// FlushEvicted removes stale entries from the active map.
func (d *Decoder) FlushEvicted() {
    d.mu.Lock()
    defer d.mu.Unlock()
    now := time.Now()
    for k, hs := range d.active {
        if now.Sub(hs.LastSeen) > quicHandshakeTTL {
            delete(d.active, k)
        }
    }
}
```

**Decryption & ClientHello Extraction:**
QUIC Initial packets are AEAD-encrypted. We require a key log file.

```go
func (d *Decoder) DecodeInitial(netFlow gopacket.Flow, udp *layers.UDP, ci gopacket.CaptureInfo, ttl uint8) (*HandshakeEvent, error) {
    // 1. Parse Long Header (Version, DCID, SCID)
    // 2. Skip Version Negotiation (type 0x7f) and Retry (type 0x03) packets
    // 3. Validate DCID length (0-32 bytes)
    // 4. Extract CRYPTO frames (type 0x06)
    // 5. Defragment CRYPTO frames (cap at 16KB)
    // 6. Decrypt using QUIC_SECRET_LOG keys
    // 7. Wrap in synthetic TLS record header: [0x16, 0x03, 0x01, len_hi, len_lo] + payload
    // 8. Parse with crypto/tls to extract SNI, ALPN, etc.
    
    // ... implementation ...
}
```

### Step 5: JA4Q Fingerprinting (internal/quic/ja4q.go)

**Note:** The JA4Q specification is not fully public. This implementation follows the best-effort interpretation of the JA4+ specification. It will be updated when the full FoxIO spec is available.

```go
func ComputeJA4Q(version uint32, ch *ClientHelloFeatures) string {
    // ja4q_t: QUIC version string (quicv1, quicv2, draftNNN, unknown)
    // ja4q_v: SNI (lowercased) or "nosni"
    // ja4q_c: SHA-256(supported_versions + alpn + sig_algos + extension_order)
    
    // ... implementation ...
}
```

### Step 6: Data Flow (cmd/ja4-tap/main.go)

QUIC events flow through the same `events` channel as TCP events. The drain function routes based on `IsQUIC`.

```go
for ev := range s.Events() {
    count++
    wctx, cancel := context.WithTimeout(context.Background(), storeWriteTimeout)

    if ev.IsQUIC {
        // QUIC path: Stack is zero-valued (no TCP SYN for QUIC)
        ja4q := quic.ComputeJA4Q(ev.QUICVersion, ev.ClientHelloFeatures)
        store.WriteJA4Q(wctx, ev.ClientIP, ja4q)
        // No JA4T or OS class for QUIC
    } else {
        // TCP path: existing logic
        class := tap.Classify(ev.Stack)
        ja4t := tap.ComputeJA4T(ev.Stack)
        store.WriteOSClass(wctx, ev.ClientIP, class)
        store.WriteJA4T(wctx, ev.ClientIP, ja4t)
        enforcer.Consider(wctx, ev.ClientIP, ja4t)
    }
    cancel()
}
```

### Step 7: Metrics (internal/tap/metrics.go)

Add QUIC-specific metrics (backward-compatible, no labels on existing counters).

```go
var (
    QUICPacketsReceivedTotal = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "ja4proxy_tap_quic_packets_received_total",
        Help: "Total QUIC UDP packets received by the TAP sensor.",
    })
    QUICPacketsDroppedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "ja4proxy_tap_quic_packets_dropped_total",
        Help: "QUIC packets dropped, by reason.",
    }, []string{"reason"})
    JA4QWrittenTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "ja4proxy_tap_ja4q_written_total",
        Help: "JA4Q fingerprints written to Redis, by result.",
    }, []string{"result"})
)
```

### Step 8: Testing Strategy

1.  **Unit tests** (`internal/quic/decoder_test.go`):
    - Binary fixtures for QUIC v1, v2, draft-29 Initial packets
    - Verify DCID, SCID, version extraction
    - Verify CRYPTO frame defragmentation
    - Verify eviction (entries older than 30s are flushed)
    - Verify max active bounds (4096 limit)

2.  **Unit tests** (`internal/quic/ja4q_test.go`):
    - Known-good JA4Q fingerprints
    - Edge cases: empty SNI, no ALPN, unknown version

3.  **Integration test** (`internal/tap/sensor_test.go`):
    - UDP frames on port 443 with `--enable-quic` → `IsQUIC=true`
    - UDP frames on port 443 without `--enable-quic` → dropped
    - TCP path remains unaffected

4.  **Benchmark** (`internal/quic/bench_test.go`):
    - Target: < 10μs per QUIC Initial + JA4Q computation

---

## Acceptance Criteria
1.  `cmd/ja4-tap --enable-quic` successfully captures and fingerprints QUIC v1/v2 traffic.
2.  `fp:ja4q:ip:{ip}` is written to Redis with the correct fingerprint.
3.  Without `--enable-quic`, UDP packets are dropped immediately (zero overhead).
4.  QUIC decoder evicts stale entries (no unbounded memory growth).
5.  Existing TCP fingerprinting (JA4T/JA4X) remains unaffected.
6.  Documentation updated (README, `docs/architecture/`).

## Out of Scope
*   Active QUIC proxying (JA4proxy remains a TCP proxy).
*   QUIC 0-RTT fingerprinting (JA4Q focuses on the Initial packet).
*   eBPF/NIC-based QUIC decryption (deferred to future work).
*   Full JA4Q spec conformance (pending FoxIO spec access).

## Dependencies
*   Phase 316a (AF_PACKET capture) - **COMPLETE**
*   Phase 316c (Advisory blocklist) - **COMPLETE**
*   `gopacket` library (already in go.mod)
*   `crypto/tls` (stdlib) for parsing the wrapped ClientHello
*   `QUIC_SECRET_LOG` environment variable for decryption keys
