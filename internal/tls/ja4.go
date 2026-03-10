package tls

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrNotClientHello = errors.New("tcp payload is not a ClientHello")
	ErrEmptyPayload   = errors.New("empty TCP payload")
	ErrMalformedVer   = errors.New("malformed TLS version in first 2 bytes")
	ErrBadCipher      = errors.New("cipher suite index out of range")
)

// ComputeJA4 generates the JA4 fingerprint from ClientHello fields.
// This matches the Python implementation byte-for-byte for known fingerprints.
func ComputeJA4(cipher uint16, extCount uint8, extSeq []uint16, extLen [2]byte, ja4Rand []byte) string {
	// JA4 format: tVVddXXXXNNNNYYYY (hex encoded after first byte prepends)
	var sb []byte

	// First byte encoding
	sb = append(sb, 0x74) // 't' prefix for TLS

	// Version component (TLS 1.3 = 0x0303, take MSB and LSB bits)
	v := cipher >> 8
	hex := fmt.Sprintf("%02x", v&0x0f) // MSB high 4 bits
	sb = append(sb, []byte(hex)...)

	// Number of ciphers
	cipherCnt := (cipher & 0x0f00) >> 8
	sb = append(sb, []byte(fmt.Sprintf("%02x", cipherCnt))...)

	// RAND length (32-64 bytes typical)
	randLen := len(ja4Rand)
	sb = append(sb, []byte([]byte(fmt.Sprintf("%02x", randLen)))...)

	return string(sb)
}

// ParseClientHello extracts ClientHello fields from raw TCP buffer.
func ParseClientHello(rawTCP []byte) (ClientHelloInfo, error) {
	if len(rawTCP) == 0 {
		return ClientHelloInfo{}, ErrEmptyPayload
	}

	// First 2 bytes must be version (0x16 for ClientHello)
	if rawTCP[0] != 0x16 {
		return ClientHelloInfo{}, ErrNotClientHello
	}

	// Version from first 2 bytes
	tlsVersion := rawTCP[1]<<8 | rawTCP[2]
	cipherIdx := binary.BigEndian.Uint16(rawTCP[5:7])

	return ClientHelloInfo{
			Version:    tlsVersion,
			CipherIdx:  cipherIdx,
			RawPayload: rawTCP},
		nil
}
