package tls

import (
	"unsafe"
	"encoding/binary"
	"errors"
	"fmt"
)

// Minimum valid ClientHello size:
// TLS record header (5) + handshake header (4) + legacy_version (2) +
// random (32) + session_id_len (1) = 44 bytes minimum before cipher suites.
const minClientHelloSize = 44

// ErrNotTLS is returned when the input does not look like a TLS record.
var ErrNotTLS = errors.New("not a TLS record")

// ErrNotClientHello is returned when the handshake type is not ClientHello.
var ErrNotClientHello = errors.New("not a ClientHello message")

// ErrTruncated is returned when the record is too short to parse.
var ErrTruncated = errors.New("truncated ClientHello")

// ParseClientHello parses raw bytes containing a TLS ClientHello record
// and returns the structured ClientHelloInfo.
//
// It never panics on malformed input; all errors are returned as values.
// The caller should treat any error as "not a recognisable ClientHello" and
// fail open.
func ParseClientHello(data []byte) (*ClientHelloInfo, error) {
	if len(data) < 5 {
		return nil, ErrTruncated
	}

	// TLS Record Layer:
	//   byte 0:    content type (0x16 = Handshake)
	//   bytes 1-2: legacy record version
	//   bytes 3-4: record length (uint16 big-endian)
	if data[0] != 0x16 {
		return nil, ErrNotTLS
	}
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if recordLen > 16384 {
		return nil, errors.New("TLS record too large")
	}
	if len(data) < 5+recordLen {
		return nil, ErrTruncated
	}

	// Handshake Header (within record body):
	//   byte 0:    handshake type (0x01 = ClientHello)
	//   bytes 1-3: body length (uint24 big-endian)
	body := data[5 : 5+recordLen]
	if len(body) < 4 {
		return nil, ErrTruncated
	}
	if body[0] != 0x01 {
		return nil, ErrNotClientHello
	}

	helloLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if len(body) < 4+helloLen {
		return nil, ErrTruncated
	}
	if 4+helloLen < minClientHelloSize {
		return nil, ErrTruncated
	}

	hello := body[4 : 4+helloLen]

	info := &ClientHelloInfo{}
	info.Raw = data

	// ClientHello body:
	//   bytes 0-1:  legacy_version
	//   bytes 2-33: random (32 bytes)
	//   byte 34:    session_id length
	//   bytes 35..34+sid_len: session_id
	if len(hello) < 34 {
		return nil, ErrTruncated
	}
	info.LegacyVersion = binary.BigEndian.Uint16(hello[0:2])

	pos := 2 + 32 // skip version + random
	if pos >= len(hello) {
		return nil, ErrTruncated
	}
	sidLen := int(hello[pos])
	pos++
	pos += sidLen // skip session ID

	// Cipher suites: uint16 length + pairs of uint16
	if pos+2 > len(hello) {
		return nil, ErrTruncated
	}
	csLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2
	if pos+csLen > len(hello) {
		return nil, ErrTruncated
	}
	if csLen%2 != 0 {
		return nil, fmt.Errorf("invalid cipher suites length %d", csLen)
	}
	for i := 0; i < csLen; i += 2 {
		cs := binary.BigEndian.Uint16(hello[pos+i : pos+i+2])
		if info.CipherSuites == nil { info.CipherSuites = make([]uint16, 0, csLen/2) }
		info.CipherSuites = append(info.CipherSuites, cs)
	}
	pos += csLen

	// Compression methods: uint8 length + bytes
	if pos+1 > len(hello) {
		return nil, ErrTruncated
	}
	compLen := int(hello[pos])
	pos++
	if pos+compLen > len(hello) {
		return nil, ErrTruncated
	}
	info.CompressionMethods = hello[pos : pos+compLen]
	pos += compLen

	// Extensions (optional — may be absent for very old clients)
	if pos >= len(hello) {
		return info, nil
	}
	if pos+2 > len(hello) {
		return nil, ErrTruncated
	}
	extTotalLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2
	if pos+extTotalLen > len(hello) {
		return nil, ErrTruncated
	}

	extData := hello[pos : pos+extTotalLen]
	if err := parseExtensions(info, extData); err != nil {
		return nil, err
	}

	return info, nil
}

// parseExtensions iterates the extensions block and populates info.
func parseExtensions(info *ClientHelloInfo, data []byte) error {
	pos := 0
	for pos < len(data) {
		if pos+4 > len(data) {
			return ErrTruncated
		}
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > len(data) {
			return ErrTruncated
		}
		extBody := data[pos : pos+extLen]
		pos += extLen

		if info.Extensions == nil { info.Extensions = make([]uint16, 0, 16) }
		info.Extensions = append(info.Extensions, extType)

		switch extType {
		case 0x0000: // SNI
			info.SNIPresent = true
			parseSNI(info, extBody)
		case 0x0010: // ALPN
			parseALPN(info, extBody)
		case 0x002b: // SupportedVersions
			parseSupportedVersions(info, extBody)
		case 0x000a: // SupportedGroups
			parseSupportedGroups(info, extBody)
		case 0x000d: // SignatureAlgorithms
			parseSignatureAlgorithms(info, extBody)
		}
	}
	return nil
}

// parseSNI extracts the server name from the SNI extension body.
// SNI body format:
//
//	server_name_list_length (uint16) + entries:
//	  name_type (uint8, 0=host_name) + name_length (uint16) + name_bytes
func parseSNI(info *ClientHelloInfo, data []byte) {
	if len(data) < 5 {
		return
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if listLen < 3 || 2+listLen > len(data) {
		return
	}
	// Only the first server name entry is used (TLS SNI carries one name in practice).
	p := 2
	if p+3 > len(data) {
		return
	}
	// nameType := data[p] // 0 = host_name
	nameLen := int(binary.BigEndian.Uint16(data[p+1 : p+3]))
	p += 3
	if p+nameLen > len(data) {
		return
	}
	info.SNI = unsafeString(data[p : p+nameLen])
}

// parseALPN extracts protocol names from the ALPN extension body.
// ALPN body format:
//
//	protocol_name_list_length (uint16) + entries:
//	  name_length (uint8) + name_bytes
func parseALPN(info *ClientHelloInfo, data []byte) {
	if len(data) < 2 {
		return
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+listLen > len(data) {
		return
	}
	p := 2
	end := 2 + listLen
	for p < end {
		if p+1 > end {
			return
		}
		nameLen := int(data[p]) //nolint:gosec // bounds checked: p < end <= len(data)
		p++
		if p+nameLen > end {
			return
		}
		info.ALPNProtocols = append(info.ALPNProtocols, unsafeString(data[p:p+nameLen]))
		p += nameLen
	}
}

// parseSupportedVersions extracts TLS versions from the supported_versions extension.
// Body format (ClientHello): list_length (uint8) + uint16 versions
func parseSupportedVersions(info *ClientHelloInfo, data []byte) {
	if len(data) < 1 {
		return
	}
	listLen := int(data[0])
	if 1+listLen > len(data) || listLen%2 != 0 {
		return
	}
	for i := 0; i < listLen; i += 2 {
		v := binary.BigEndian.Uint16(data[1+i : 3+i])
		info.SupportedVersions = append(info.SupportedVersions, v)
	}
}

// parseSupportedGroups extracts named groups from extension 0x000a.
func parseSupportedGroups(info *ClientHelloInfo, data []byte) {
	if len(data) < 2 {
		return
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+listLen > len(data) || listLen%2 != 0 {
		return
	}
	for i := 0; i < listLen; i += 2 {
		g := binary.BigEndian.Uint16(data[2+i : 4+i])
		info.SupportedGroups = append(info.SupportedGroups, g)
	}
}

// parseSignatureAlgorithms extracts signature algorithms from extension 0x000d.
func parseSignatureAlgorithms(info *ClientHelloInfo, data []byte) {
	if len(data) < 2 {
		return
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+listLen > len(data) || listLen%2 != 0 {
		return
	}
	for i := 0; i < listLen; i += 2 {
		s := binary.BigEndian.Uint16(data[2+i : 4+i])
		info.SignatureAlgorithms = append(info.SignatureAlgorithms, s)
	}
}

func unsafeString(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}
