# QUIC/JA4Q Passive Sensing

## Goal
Implement a UDP-based QUIC-Initial decoder in the `cmd/ja4-tap` binary to support JA4Q fingerprinting and close the "blind spot" in passive network monitoring.

## Background
Phase 316 (Go TAP/SPAN Passive Sensor) delivered a robust TCP-based sensor (316a-316e) but explicitly deferred QUIC support. As HTTP/3 adoption grows (driven by Cloudflare, Google, and Apple), a significant portion of legitimate and malicious traffic is moving to UDP. Without QUIC support, the TAP sensor cannot see, fingerprint, or enforce against these connections.

## Scope
1.  **UDP Capture**: Extend the AF_PACKET capture loop to process UDP frames on port 443.
2.  **QUIC-Initial Parsing**: Decode the QUIC Initial packet (Long Header) to extract:
    *   Version (to distinguish QUIC v1, v2, and draft versions).
    *   Destination Connection ID (DCID).
    *   SNI (Server Name Indication) from the TLS ClientHello encapsulated in the Initial packet.
3.  **JA4Q Fingerprinting**: Implement the JA4Q algorithm:
    *   `ja4q_t`: Version.
    *   `ja4q_v`: SNI.
    *   `ja4q_c`: Supported_versions, alpn, signature_algorithms, extension_order (from the encapsulated ClientHello).
4.  **Redis Integration**: Write `fp:ja4q:ip:{ip}` to Redis (advisory-only, like Phase 316c).
5.  **Metrics**: Add `ja4t_packets_received`, `ja4t_packets_dropped`, `ja4t_active_streams` (reuse existing metrics or add `ja4q_*` variants).

## Implementation Plan

### Step 1: Unified Capture Layer (TCP + UDP)
The current `Sensor` (in `internal/tap/sensor.go`) is TCP-only. To support QUIC, we must extend the capture loop to process UDP frames on port 443 without breaking the existing TCP reassembly logic.

*   **Modify `internal/tap/sensor.go`**:
    *   Update `ProcessPacket` to inspect the IP protocol field.
    *   If TCP: Feed to the existing `reassembly.Assembler`.
    *   If UDP: Extract the payload and pass it to a new `QUICDecoder`.
*   **Proposed Structure**:
    ```go
    // internal/tap/sensor.go

    // Sensor reassembles mirrored TCP traffic and decodes QUIC Initial packets.
    type Sensor struct {
        decoder    *decoder
        pool       *reassembly.StreamPool
        asm        *reassembly.Assembler
        quic       *QUICDecoder        // New
        events     chan HandshakeEvent
    }

    func (s *Sensor) ProcessPacket(data []byte, ci gopacket.CaptureInfo) {
        PacketsReceivedTotal.Inc()
        netFlow, tcp, udp, ttl, proto, ok := s.decoder.decode(data) // Modified
        if !ok {
            PacketsDroppedTotal.WithLabelValues(dropUnsupported).Inc()
            return
        }

        switch proto {
        case layers.IPProtocolTCP:
            s.asm.AssembleWithContext(netFlow, tcp, &assemblerCtx{ci: ci, ttl: ttl})
        case layers.IPProtocolUDP:
            if udp != nil && udp.DstPort == 443 {
                if ev, err := s.quic.DecodeUDP(netFlow, udp, ci, ttl); err == nil {
                    s.deliver(*ev)
                }
            }
        }
    }
    ```

### Step 2: QUIC Decoder & JA4Q Fingerprinting
This new module handles the parsing of the QUIC Initial packet and the extraction of the TLS ClientHello for fingerprinting.

*   **Create `internal/tap/quic/decoder.go`**:
    *   `QUICDecoder` manages state for connection ID tracking (to link multiple packets to one handshake).
    *   `DecodeInitial` extracts the CRYPTO frames from a QUIC Initial packet.
*   **Create `internal/tap/quic/ja4q.go`**:
    *   `ComputeJA4Q(version, sni string, ch *tls.ClientHelloInfo) string` implements the JA4Q algorithm.
*   **Proposed Structures**:
    ```go
    // internal/tap/quic/decoder.go

    type QUICDecoder struct {
        // In-flight QUIC connections (keyed by Destination Connection ID)
        active map[quicConnID]*QUICHandshake
        mu     sync.Mutex
    }

    type QUICHandshake struct {
        Version    uint32
        DCID       []byte
        ClientHello []byte // The encapsulated TLS ClientHello bytes
        Seen       int
    }

    // DecodeInitial processes a QUIC Initial packet and returns a completed HandshakeEvent
    // if the ClientHello was fully extracted.
    func (d *QUICDecoder) DecodeInitial(netFlow gopacket.Flow, udp *layers.UDP, ci gopacket.CaptureInfo, ttl uint8) (*HandshakeEvent, error) {
        // ... parse Long Header, extract Version, DCID, SCID ...
        // ... extract CRYPTO frames ...
        // ... defragment if necessary ...
        // ... extract TLS ClientHello ...
        return &HandshakeEvent{
            ClientIP:   netFlow.Src().String(),
            ServerIP:   netFlow.Dst().String(),
            ClientPort: uint16(udp.SrcPort),
            ServerPort: uint16(udp.DstPort),
            ClientHello: chBytes,
            FirstSeen:  ci.Timestamp,
            IsQUIC:     true, // New field in HandshakeEvent
        }, nil
    }
    ```

### Step 3: Redis Integration
Extend the `Store` to write QUIC fingerprints to a dedicated Redis prefix (`fp:ja4q:ip`).

*   **Modify `internal/tap/store.go`**:
    ```go
    // internal/tap/store.go

    func (s *Store) WriteJA4Q(ctx context.Context, ip, fingerprint string) {
        if s.adapter == nil {
            return
        }
        key := "fp:ja4q:ip:" + ip
        _ = s.adapter.Set(ctx, key, fingerprint, 24*time.Hour) // 24h TTL
    }
    ```

### Step 4: Integration & Testing
1.  **Unit Tests**: Create `internal/tap/quic/decoder_test.go` using a hand-crafted QUIC Initial packet (binary fixture) to verify parsing.
2.  **Integration Tests**: Create a `net/http/httptest.Server` with QUIC enabled to generate real traffic.
3.  **Benchmarks**: Update `make bench-hostnative` to include a `QUIC_BENCH=true` scenario.

## Acceptance Criteria
1.  `cmd/ja4-tap` successfully captures and fingerprints QUIC v1/v2 traffic.
2.  `fp:ja4q:ip:{ip}` is written to Redis with the correct fingerprint.
3.  QUIC packets do not cause panics or high CPU usage under load.
4.  Existing TCP fingerprinting (JA4T/JA4X) remains unaffected.
5.  Documentation updated (README, `docs/architecture/`).

## Out of Scope
*   Active QUIC proxying (JA4proxy remains a TCP proxy).
*   QUIC 0-RTT fingerprinting (JA4Q currently focuses on the Initial packet).
*   UDP load balancing (not required for passive sensing).

## Dependencies
*   Phase 316a (AF_PACKET capture) - **COMPLETE**
*   Phase 316c (Advisory blocklist) - **COMPLETE**
*   `gopacket` library (already in go.mod) for potential UDP reassembly.
*   `crypto/tls` (stdlib) for parsing the encapsulated ClientHello.
