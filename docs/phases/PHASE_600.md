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
1.  **Step 1: UDP Capture Layer**
    *   Modify `cmd/ja4-tap/main.go` and `internal/tap/capture.go` to support `syscall.IPPROTO_UDP` on the AF_PACKET socket.
    *   Add a `UDPStream` reassembly buffer (simplified compared to TCP, as QUIC has its own reliability).
2.  **Step 2: QUIC Decoder**
    *   Create `internal/tap/quic/decoder.go`.
    *   Implement `ParseQUICInitial(data []byte) (*QUICInitial, error)`.
    *   Handle version negotiation and retry packets.
3.  **Step 3: JA4Q Algorithm**
    *   Create `internal/tap/quic/ja4q.go`.
    *   Extract the encapsulated TLS ClientHello from the QUIC CRYPTO frame.
    *   Reuse `internal/tls/` helpers where possible (SNI, ALPN, etc.).
4.  **Step 4: Integration & Testing**
    *   Add unit tests for QUIC packet parsing.
    *   Add integration tests with a real QUIC server (e.g., `net/http/httptest` with QUIC enabled or a mock QUIC client).
    *   Update `make bench-hostnative` to include a QUIC traffic scenario.

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
