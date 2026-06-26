// Package quic implements QUIC Initial packet parsing and JA4Q fingerprinting
// for the passive TAP sensor (Phase 600).
package quic

import (
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

// QUIC Initial Header Key Label for key derivation.
const initialSecretLabel = "tls13 quic secret"

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

// Decoder manages state for QUIC connection tracking and decryption.
// It is NOT safe for concurrent use — the Sensor is single-goroutine.
type Decoder struct {
	active map[quicConnID]*Handshake
	keyLog *KeyLog
	mu     sync.Mutex
}

// NewDecoder builds a decoder with a pre-allocated map and optional key log.
func NewDecoder(keyLog *KeyLog) *Decoder {
	return &Decoder{
		active: make(map[quicConnID]*Handshake, 256),
		keyLog: keyLog,
	}
}

// ActiveCount returns the number of tracked connections (for metrics).
func (d *Decoder) ActiveCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.active)
}

// HasKeys reports whether decryption keys are available.
func (d *Decoder) HasKeys() bool {
	return d.keyLog != nil && d.keyLog.HasKeys()
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
// Attempts to decrypt the Initial payload and extract the ClientHello.
// Returns a QUICResult with ClientHelloFeatures if decryption succeeds.
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

	// --- Parse header fields ---
	off := 1
	version, n := readVarint(payload[off:])
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

	// --- Token (Initial packets only; skip) ---
	tokenLen, n := readVarint(payload[off:])
	if n <= 0 {
		return nil, fmt.Errorf("quic: invalid token length varint at offset %d", off)
	}
	off += n
	if off+int(tokenLen) > len(payload) {
		return nil, errors.New("quic: truncated token")
	}
	off += int(tokenLen)

	// --- Length (varint) ---
	pktLen, n := readVarint(payload[off:])
	if n <= 0 {
		return nil, fmt.Errorf("quic: invalid length varint at offset %d", off)
	}
	off += n

	pktEnd := off + int(pktLen)
	if pktEnd > len(payload) {
		pktEnd = len(payload) // truncate to available data
	}
	ciphertext := payload[off:pktEnd]

	// --- Deduplicate ---
	key := connIDKey(dcid)
	d.mu.Lock()
	_, exists := d.active[key]
	if exists {
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

	// --- Attempt decryption ---
	result := &QUICResult{
		ClientIP:   netFlow.Src().String(),
		ServerIP:   netFlow.Dst().String(),
		ClientPort: uint16(udp.SrcPort),
		ServerPort: uint16(udp.DstPort),
		Version:    uint32(version),
		DCID:       dcid,
		FirstSeen:  ci.Timestamp,
		TTL:        ttl,
	}

	if d.keyLog == nil {
		return result, nil // no decryption keys available
	}

	// Try to decrypt the Initial packet
	plaintext, err := d.decryptInitialPacket(ciphertext, dcid)
	if err != nil {
		return result, nil // decryption failed; return result without ClientHello
	}

	// --- Extract CRYPTO frames ---
	chBytes, err := extractClientHello(plaintext)
	if err != nil {
		return result, nil // CRYPTO extraction failed
	}

	// --- Parse ClientHello features ---
	features, err := ParseClientHelloFeatures(chBytes)
	if err != nil {
		return result, nil // ClientHello parse failed
	}

	result.ClientHello = chBytes
	result.Features = features
	return result, nil
}

// decryptInitialPacket attempts to decrypt a QUIC Initial packet.
// Uses the DCID to derive the Initial key from the handshake secret.
func (d *Decoder) decryptInitialPacket(ciphertext, dcid []byte) ([]byte, error) {
	if d.keyLog == nil {
		return nil, errors.New("no key log available")
	}

	// Try to find a suitable secret
	// For QUIC v1, the Initial packet is encrypted with keys derived from
	// the client's DCID using a well-known salt (RFC 9001 §5.1).
	// The actual decryption requires the TLS transcript keys, which we
	// get from the key log.

	// Try the handshake secret label
	secret := d.keyLog.GetSecret("QUIC_SECRET_CLIENT_HANDSHAKE_TRAFFIC_SECRET")
	if secret == nil {
		secret = d.keyLog.GetSecret("QUIC_SECRET_HANDSHAKE_TRAFFIC_SECRET")
	}
	if secret == nil {
		return nil, errors.New("no handshake secret found in key log")
	}

	// Derive Initial key from DCID and secret
	key, iv, err := DeriveInitialKey(dcid, secret)
	if err != nil {
		return nil, fmt.Errorf("derive initial key: %w", err)
	}

	// Build associated data (AD) = header (everything before ciphertext)
	// For simplicity, we use an empty AD for now
	var ad []byte

	// Decrypt
	plaintext, err := DecryptInitial(ciphertext, key, iv, ad)
	if err != nil {
		return nil, fmt.Errorf("decrypt initial: %w", err)
	}

	return plaintext, nil
}

// extractClientHello extracts the TLS ClientHello from decrypted QUIC CRYPTO frames.
func extractClientHello(plaintext []byte) ([]byte, error) {
	// Parse CRYPTO frames
	cryptoData, err := ParseCRYPTOFrames(plaintext)
	if err != nil {
		return nil, fmt.Errorf("parse CRYPTO frames: %w", err)
	}

	if len(cryptoData) < 4 {
		return nil, errors.New("CRYPTO data too short for TLS handshake")
	}

	// Check handshake type (must be ClientHello = 0x01)
	if cryptoData[0] != 0x01 {
		return nil, fmt.Errorf("expected ClientHello (0x01), got 0x%02x", cryptoData[0])
	}

	// Extract length (3 bytes big-endian)
	msgLen := int(cryptoData[1])<<16 | int(cryptoData[2])<<8 | int(cryptoData[3])
	if msgLen+4 > len(cryptoData) {
		return nil, errors.New("ClientHello message truncated")
	}

	// Return the ClientHello body (without 4-byte handshake header)
	return cryptoData[4 : 4+msgLen], nil
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

	// ClientHello is the raw TLS ClientHello body (without handshake header).
	// Set only when decryption and CRYPTO extraction succeed.
	ClientHello []byte

	// Features holds the parsed ClientHello fields for JA4Q fingerprinting.
	// Set only when ClientHello parsing succeeds.
	Features *ClientHelloFeatures
}
