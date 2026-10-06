package tlsfixture

import (
	"encoding/binary"
)

// Extension describes a single TLS extension.
type Extension struct {
	Type uint16
	Data []byte
}

// Spec describes a ClientHello specification for builder.
type Spec struct {
	LegacyVersion uint16      // Default: 0x0303 (TLS 1.2)
	Ciphers       []uint16    // Default: standard TLS 1.3 / 1.2 ciphers
	Extensions    []Extension // Wire order
	SNI           string      // Optional server_name extension
	ALPN          []string    // Optional ALPN protocol list
	SupportedVers []uint16    // Optional supported_versions extension
}

// Build constructs a full TLS Record Layer frame containing a ClientHello handshake.
func Build(s Spec) []byte {
	version := s.LegacyVersion
	if version == 0 {
		version = 0x0303
	}

	ciphers := s.Ciphers
	if len(ciphers) == 0 {
		ciphers = []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f}
	}

	var extensions []Extension
	extensions = append(extensions, s.Extensions...)

	if s.SNI != "" {
		sniName := []byte(s.SNI)
		sniData := make([]byte, 2+1+2+len(sniName))
		binary.BigEndian.PutUint16(sniData[0:2], uint16(1+2+len(sniName))) // #nosec G115 -- test fixture SNI length bounded
		sniData[2] = 0x00                                                  // host_name type 0
		binary.BigEndian.PutUint16(sniData[3:5], uint16(len(sniName)))     // #nosec G115 -- test fixture name length bounded
		copy(sniData[5:], sniName)
		extensions = append(extensions, Extension{Type: 0x0000, Data: sniData})
	}

	if len(s.ALPN) > 0 {
		var alpnBuf []byte
		for _, p := range s.ALPN {
			alpnBuf = append(alpnBuf, byte(len(p))) // #nosec G115 -- ALPN protocol name length <= 255
			alpnBuf = append(alpnBuf, []byte(p)...)
		}
		alpnData := make([]byte, 2+len(alpnBuf))
		binary.BigEndian.PutUint16(alpnData[0:2], uint16(len(alpnBuf))) // #nosec G115 -- ALPN total length bounded
		copy(alpnData[2:], alpnBuf)
		extensions = append(extensions, Extension{Type: 0x0010, Data: alpnData})
	}

	if len(s.SupportedVers) > 0 {
		versData := make([]byte, 1+len(s.SupportedVers)*2)
		versData[0] = byte(len(s.SupportedVers) * 2) // #nosec G115 -- Supported versions count bounded
		for i, v := range s.SupportedVers {
			binary.BigEndian.PutUint16(versData[1+i*2:], v)
		}
		extensions = append(extensions, Extension{Type: 0x002b, Data: versData})
	}

	// Build Handshake Body
	var body []byte

	// Handshake Protocol Version
	var verBuf [2]byte
	binary.BigEndian.PutUint16(verBuf[:], version)
	body = append(body, verBuf[:]...)

	// Client Random (32 bytes)
	random := make([]byte, 32)
	copy(random, []byte("01234567890123456789012345678901"))
	body = append(body, random...)

	// Session ID (32 bytes)
	body = append(body, 32)
	sessionID := make([]byte, 32)
	body = append(body, sessionID...)

	// Cipher Suites
	cipherLen := uint16(len(ciphers) * 2) // #nosec G115 -- test fixture ciphers count bounded
	var cipherLenBuf [2]byte
	binary.BigEndian.PutUint16(cipherLenBuf[:], cipherLen)
	body = append(body, cipherLenBuf[:]...)
	for _, c := range ciphers {
		var cBuf [2]byte
		binary.BigEndian.PutUint16(cBuf[:], c)
		body = append(body, cBuf[:]...)
	}

	// Compression Methods (1 byte: null compression)
	body = append(body, 1, 0)

	// Extensions
	var extBuf []byte
	for _, e := range extensions {
		var head [4]byte
		binary.BigEndian.PutUint16(head[0:2], e.Type)
		binary.BigEndian.PutUint16(head[2:4], uint16(len(e.Data))) // #nosec G115 -- extension data length bounded
		extBuf = append(extBuf, head[:]...)
		extBuf = append(extBuf, e.Data...)
	}

	var extLenBuf [2]byte
	binary.BigEndian.PutUint16(extLenBuf[:], uint16(len(extBuf))) // #nosec G115 -- extensions total length bounded
	body = append(body, extLenBuf[:]...)
	body = append(body, extBuf...)

	// Handshake Record Header (4 bytes: Type=1 ClientHello, Length=len(body))
	var hsHead [4]byte
	hsHead[0] = 0x01 // ClientHello
	hsHead[1] = byte(len(body) >> 16) // #nosec G115 -- handshake body length byte 1
	hsHead[2] = byte(len(body) >> 8)  // #nosec G115 -- handshake body length byte 2
	hsHead[3] = byte(len(body))       // #nosec G115 -- handshake body length byte 3

	hsPayload := append(hsHead[:], body...)

	// TLS Record Layer Header (5 bytes: Type=0x16 Handshake, Version=0x0301, Length=len(hsPayload))
	var recHead [5]byte
	recHead[0] = 0x16 // Handshake
	recHead[1] = 0x03
	recHead[2] = 0x01
	binary.BigEndian.PutUint16(recHead[3:5], uint16(len(hsPayload))) // #nosec G115 -- record length bounded

	return append(recHead[:], hsPayload...)
}

// Split divides a byte slice into chunks according to sizes.
func Split(record []byte, sizes ...int) [][]byte {
	var chunks [][]byte
	curr := 0
	for _, sz := range sizes {
		if curr >= len(record) {
			break
		}
		end := curr + sz
		if end > len(record) {
			end = len(record)
		}
		chunks = append(chunks, record[curr:end])
		curr = end
	}
	if curr < len(record) {
		chunks = append(chunks, record[curr:])
	}
	return chunks
}
