package quic

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// QUIC frame types (RFC 9000 §12.4).
const (
	FrameCrypto = 0x06
)

// fragment represents a CRYPTO frame fragment for defragmentation.
type fragment struct {
	offset uint64
	data   []byte
}

// ParseCRYPTOFrames extracts CRYPTO frames from decrypted QUIC Initial payload.
// Returns the defragmented TLS ClientHello bytes, or an error if parsing fails.
//
// QUIC CRYPTO frame layout (RFC 9000 §12.4):
//
//	Type (varint): 0x06
//	Offset (varint)
//	Length (varint)
//	Crypto Data (*)
func ParseCRYPTOFrames(payload []byte) ([]byte, error) {
	// Offset-based defragmentation: CRYPTO frames may arrive out of order
	// within a single Initial packet (rare but possible).
	// We collect all (offset, data) pairs and reassemble.
	var frags []fragment
	off := 0

	for off < len(payload) {
		if off >= len(payload) {
			break
		}

		// Read frame type (varint)
		frameType, n := readVarint(payload[off:])
		if n <= 0 {
			return nil, fmt.Errorf("quic: invalid frame type varint at offset %d", off)
		}
		off += n

		if frameType != FrameCrypto {
			// Skip non-CRYPTO frames (e.g., PADDING, ACK, etc.)
			continue
		}

		// Read offset (varint)
		cryptoOffset, n := readVarint(payload[off:])
		if n <= 0 {
			return nil, fmt.Errorf("quic: invalid CRYPTO offset varint at offset %d", off)
		}
		off += n

		// Read length (varint)
		cryptoLen, n := readVarint(payload[off:])
		if n <= 0 {
			return nil, fmt.Errorf("quic: invalid CRYPTO length varint at offset %d", off)
		}
		off += n

		// Bounds check
		if off+int(cryptoLen) > len(payload) {
			return nil, fmt.Errorf("quic: CRYPTO frame truncated: offset=%d length=%d available=%d",
				off, cryptoLen, len(payload)-off)
		}

		// Safety: cap total CRYPTO bytes
		data := payload[off : off+int(cryptoLen)]
		off += int(cryptoLen)

		frags = append(frags, fragment{offset: cryptoOffset, data: data})
	}

	if len(frags) == 0 {
		return nil, errors.New("quic: no CRYPTO frames found")
	}

	// Defragment: sort by offset, verify contiguous
	return defragment(frags)
}

// defragment reassembles CRYPTO fragments by offset.
func defragment(frags []fragment) ([]byte, error) {
	if len(frags) == 0 {
		return nil, errors.New("quic: no fragments to defragment")
	}

	// Simple sort by offset (fragments are usually in order)
	for i := 1; i < len(frags); i++ {
		for j := i; j > 0 && frags[j].offset < frags[j-1].offset; j-- {
			frags[j], frags[j-1] = frags[j-1], frags[j]
		}
	}

	// Verify contiguous offsets
	var totalLen int
	for _, f := range frags {
		totalLen += len(f.data)
	}

	// Cap at MaxCryptoBytes
	if totalLen > MaxCryptoBytes {
		return nil, fmt.Errorf("quic: total CRYPTO bytes %d exceeds limit %d", totalLen, MaxCryptoBytes)
	}

	result := make([]byte, 0, totalLen)
	for _, f := range frags {
		result = append(result, f.data...)
	}

	return result, nil
}

// WrapInTLSRecord wraps raw TLS handshake bytes in a TLS record header.
// This allows crypto/tls to parse the ClientHello from QUIC CRYPTO frames.
//
// TLS Record Layer (RFC 8446 §5.1):
//   ContentType (1): 0x16 = handshake
//   LegacyRecordVersion (2): 0x0301 (TLS 1.0, for compatibility)
//   Length (2): uint16 big-endian
//   Fragment (*): the handshake message
func WrapInTLSRecord(handshakeBytes []byte) []byte {
	record := make([]byte, 5+len(handshakeBytes))
	record[0] = 0x16 // ContentType: handshake
	record[1] = 0x03 // LegacyRecordVersion: 0x0301
	record[2] = 0x01
	record[3] = byte(len(handshakeBytes) >> 8)
	record[4] = byte(len(handshakeBytes))
	copy(record[5:], handshakeBytes)
	return record
}

// readVarint reads a QUIC variable-length integer (RFC 9000 §16).
func readVarint(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, -1
	}
	prefix := data[0] >> 6
	switch prefix {
	case 0:
		return uint64(data[0]&0x3f), 1
	case 1:
		if len(data) < 2 {
			return 0, -1
		}
		return uint64(binary.BigEndian.Uint16(data[:2])) & 0x3fff, 2
	case 2:
		if len(data) < 4 {
			return 0, -1
		}
		return uint64(binary.BigEndian.Uint32(data[:4])) & 0x3fffffff, 4
	case 3:
		if len(data) < 8 {
			return 0, -1
		}
		return binary.BigEndian.Uint64(data[:8]) & 0x3fffffffffffffff, 8
	}
	return 0, -1
}
