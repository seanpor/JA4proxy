// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 Sean O'Riordain.

package quic

import (
	"fmt"
)

// ParseClientHelloFeatures parses a raw TLS ClientHello message and extracts
// the features needed for JA4Q fingerprinting. This is a minimal parser that
// handles the fields JA4Q needs; it does not implement full TLS 1.3 ClientHello
// validation.
//
// The input is the ClientHello body (without the 4-byte handshake header).
func ParseClientHelloFeatures(body []byte) (*ClientHelloFeatures, error) {
	if len(body) < 38 {
		return nil, fmt.Errorf("tls: ClientHello body too short: %d bytes", len(body))
	}

	features := &ClientHelloFeatures{}
	off := 0

	// client_version (2 bytes) — skip
	off += 2

	// random (32 bytes) — skip
	off += 32

	// session_id_length (1 byte) + session_id
	if off >= len(body) {
		return nil, fmt.Errorf("tls: truncated session ID length")
	}
	sessionIDLen := int(body[off])
	off++
	off += sessionIDLen

	// cipher_suites_length (2 bytes) + cipher_suites
	if off+2 > len(body) {
		return nil, fmt.Errorf("tls: truncated cipher suites length")
	}
	cipherSuitesLen := int(body[off])<<8 | int(body[off+1])
	off += 2
	off += cipherSuitesLen

	// compression_methods_length (1 byte) + compression_methods
	if off >= len(body) {
		return nil, fmt.Errorf("tls: truncated compression methods length")
	}
	compressionLen := int(body[off])
	off++
	off += compressionLen

	// extensions_length (2 bytes)
	if off+2 > len(body) {
		return nil, fmt.Errorf("tls: truncated extensions length")
	}
	extensionsLen := int(body[off])<<8 | int(body[off+1])
	off += 2

	extensionsEnd := off + extensionsLen
	if extensionsEnd > len(body) {
		extensionsEnd = len(body)
	}

	// Parse extensions
	for off < extensionsEnd {
		if off+4 > extensionsEnd {
			break
		}
		extType := uint16(body[off])<<8 | uint16(body[off+1])
		extLen := int(body[off+2])<<8 | int(body[off+3])
		off += 4

		if off+extLen > extensionsEnd {
			break
		}

		features.ExtensionOrder = append(features.ExtensionOrder, extType)

		switch extType {
		case 0x0000: // server_name (SNI)
			features.SNI = parseSNI(body[off : off+extLen])
		case 0x000d: // signature_algorithms
			features.SignatureAlgorithms = parseSignatureAlgorithms(body[off : off+extLen])
		case 0x0010: // application_layer_protocol_negotiation (ALPN)
			features.ALPN = parseALPN(body[off : off+extLen])
		case 0x002b: // supported_versions
			features.SupportedVersions = parseSupportedVersions(body[off : off+extLen])
		}

		off += extLen
	}

	return features, nil
}

// parseSNI extracts the first SNI hostname from the server_name extension.
func parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// list_length (2) + name_type (1) + name_length (2)
	nameLen := int(data[3])<<8 | int(data[4])
	if 5+nameLen > len(data) {
		return ""
	}
	return string(data[5 : 5+nameLen])
}

// parseSignatureAlgorithms extracts the signature algorithms extension.
func parseSignatureAlgorithms(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(data[0])<<8 | int(data[1])
	var sigs []uint16
	for i := 2; i+1 < len(data) && i+1 < 2+listLen; i += 2 {
		sigs = append(sigs, uint16(data[i])<<8|uint16(data[i+1]))
	}
	return sigs
}

// parseALPN extracts ALPN protocol identifiers.
func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(data[0])<<8 | int(data[1])
	off := 2
	var protos []string
	for off < 2+listLen && off < len(data) {
		protoLen := int(data[off])
		off++
		if off+protoLen > len(data) {
			break
		}
		protos = append(protos, string(data[off:off+protoLen]))
		off += protoLen
	}
	return protos
}

// parseSupportedVersions extracts the supported versions extension.
func parseSupportedVersions(data []byte) []uint16 {
	if len(data) < 1 {
		return nil
	}
	listLen := int(data[0])
	var vers []uint16
	for i := 1; i+1 < len(data) && i+1 < 1+listLen; i += 2 {
		vers = append(vers, uint16(data[i])<<8|uint16(data[i+1]))
	}
	return vers
}
