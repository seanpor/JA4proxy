// Package tls provides TLS ClientHello parsing and JA4 fingerprint computation.
package tls

// ClientHelloInfo contains all parsed fields from a TLS ClientHello message
// needed to compute JA4 and other fingerprints.
type ClientHelloInfo struct {
	// Raw ClientHello record bytes (TLS record layer + handshake header)
	Raw []byte

	// Version from ClientHello legacy_version field (e.g. 0x0303 for TLS 1.2)
	LegacyVersion uint16

	// CipherSuites lists all cipher suite values including GREASE
	CipherSuites []uint16

	// CompressionMethods lists the offered compression methods
	CompressionMethods []byte

	// Extensions lists all extension type codes in order of appearance
	Extensions []uint16

	// SNIPresent is true if extension type 0 (SNI) appears in the ClientHello
	SNIPresent bool

	// SNI is the server name from the SNI extension, if present
	SNI string

	// SupportedVersions lists TLS versions from the supported_versions extension (0x002b)
	SupportedVersions []uint16

	// ALPNProtocols lists the protocol names from the ALPN extension (0x0010)
	ALPNProtocols []string

	// SignatureAlgorithms from extension 0x000d
	SignatureAlgorithms []uint16

	// SupportedGroups from extension 0x000a
	SupportedGroups []uint16
}
