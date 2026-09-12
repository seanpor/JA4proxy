// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 Sean O'Riordain.

package quic

// ClientHelloFeatures holds the raw ClientHello fields needed for TLS/QUIC fingerprinting.
// Unlike tls.ClientHelloInfo, this preserves wire-order information.
type ClientHelloFeatures struct {
	SNI                 string
	SupportedVersions   []uint16
	ALPN                []string
	SignatureAlgorithms []uint16
	ExtensionOrder      []uint16 // extension type codes in wire order
}
