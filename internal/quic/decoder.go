// Package quic implements QUIC Initial packet parsing and JA4Q fingerprinting
// for the passive TAP sensor (Phase 600).
package quic

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// QUIC version constants (RFC 9000 §15).
const (
	Version1       uint32 = 0x00000001 // RFC 9000
	Version2       uint32 = 0x6b3343cf // draft-ietf-quic-v2
	VersionDraft29 uint32 = 0xff00001d // draft-29
)

// Eviction bounds (DoS protection).
const (
	// MaxActive is the maximum number of tracked QUIC connections.
	MaxActive = 4096
	// MaxCryptoBytes is the maximum buffered CRYPTO frame bytes per connection.
	MaxCryptoBytes = 16384
	// HandshakeTTL is how long a QUIC handshake entry persists before eviction.
	HandshakeTTL = 30 * time.Second
)

// quicConnID is a fixed-size key for the active-connections map.
type quicConnID [32]byte

func connIDKey(id []byte) quicConnID {
	var k quicConnID
	copy(k[:], id)
	return k
}

// Handshake tracks in-flight QUIC handshakes keyed by DCID.
type Handshake struct {
	Version  uint32
	DCID     []byte
	SCID     []byte
	LastSeen time.Time
	Seen     int
}

// Decoder manages state for QUIC connection tracking. It is NOT safe for
// concurrent use — the Sensor is single-goroutine, so this is fine.
type Decoder struct {
	active map[quicConnID]*Handshake
	mu     sync.Mutex // Defensive; single-goroutine in practice.
}

// NewDecoder builds a decoder with a pre-allocated map.
func NewDecoder() *Decoder {
	return &Decoder{
		active: make(map[quicConnID]*Handshake, 256),
	}
}

// ActiveCount returns the number of tracked connections (for metrics).
func (d *Decoder) ActiveCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.active)
}

// FlushEvicted removes stale entries from the active map.
func (d *Decoder) FlushEvicted() {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	for k, hs := range d.active {
		if now.Sub(hs.LastSeen) > HandshakeTTL {
			delete(d.active, k)
		}
	}
}

// DecodeInitial parses a QUIC Initial packet from a UDP frame.
// Returns a HandshakeEvent-like data structure (or nil for non-Initial packets).
// Returns an error only for malformed/crafted packets that should be counted as drops.
func (d *Decoder) DecodeInitial(
	netFlow gopacket.Flow,
	udp *layers.UDP,
	ci gopacket.CaptureInfo,
	ttl uint8,
) (*QUICResult, error) {
	payload := udp.Payload
	if len(payload) == 0 {
		return nil, nil
	}

	// --- Long Header detection (RFC 9000 §17.2) ---
	if payload[0]&0x80 == 0 {
		return nil, nil // Short Header — not an Initial
	}

	// Bits 6-4 (0x70) encode the Header Form type:
	//   0x00 = Initial, 0x20 = 0-RTT, 0x40 = Handshake, 0x60 = Retry
	ptype := (payload[0] >> 4) & 0x07
	if ptype != 0x00 {
		return nil, nil // not an Initial packet
	}

	// --- Parse fields ---
	off := 1
	version, n := binary.Uvarint(payload[off:])
	if n <= 0 {
		return nil, fmt.Errorf("quic: invalid version varint at offset %d", off)
	}
	off += n

	// DCID
	if off >= len(payload) {
		return nil, errors.New("quic: truncated DCID length")
	}
	dcidLen := int(payload[off])
	off++
	if dcidLen > 32 {
		return nil, errors.New("quic: DCID length exceeds 32 bytes")
	}
	if off+dcidLen > len(payload) {
		return nil, errors.New("quic: truncated DCID")
	}
	dcid := make([]byte, dcidLen)
	copy(dcid, payload[off:off+dcidLen])
	off += dcidLen

	// SCID
	if off >= len(payload) {
		return nil, errors.New("quic: truncated SCID length")
	}
	scidLen := int(payload[off])
	off++
	if off+scidLen > len(payload) {
		return nil, errors.New("quic: truncated SCID")
	}
	scid := make([]byte, scidLen)
	copy(scid, payload[off:off+scidLen])
	off += scidLen

	// --- Deduplicate ---
	key := connIDKey(dcid)
	d.mu.Lock()
	hs, exists := d.active[key]
	if exists {
		hs.Seen++
		hs.LastSeen = ci.Timestamp
		d.mu.Unlock()
		return nil, nil // already processed
	}

	// Check capacity before inserting
	if len(d.active) >= MaxActive {
		d.mu.Unlock()
		return nil, errors.New("quic: active connection limit exceeded")
	}

	d.active[key] = &Handshake{
		Version:  uint32(version),
		DCID:     dcid,
		SCID:     scid,
		LastSeen: ci.Timestamp,
		Seen:     1,
	}
	d.mu.Unlock()

	return &QUICResult{
		ClientIP:   netFlow.Src().String(),
		ServerIP:   netFlow.Dst().String(),
		ClientPort: uint16(udp.SrcPort),
		ServerPort: uint16(udp.DstPort),
		Version:    uint32(version),
		DCID:       dcid,
		FirstSeen:  ci.Timestamp,
		TTL:        ttl,
	}, nil
}

// QUICResult holds the parsed output of a QUIC Initial packet.
type QUICResult struct {
	ClientIP   string
	ServerIP   string
	ClientPort uint16
	ServerPort uint16
	Version    uint32
	DCID       []byte
	FirstSeen  time.Time
	TTL        uint8
}
