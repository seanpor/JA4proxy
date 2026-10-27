package tls

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
)

// greaseValues is the set of GREASE values defined in RFC 8701.
// These are reserved values that well-behaved implementations must ignore.
var greaseValues = map[uint16]bool{
	0x0A0A: true, 0x1A1A: true, 0x2A2A: true, 0x3A3A: true,
	0x4A4A: true, 0x5A5A: true, 0x6A6A: true, 0x7A7A: true,
	0x8A8A: true, 0x9A9A: true, 0xAAAA: true, 0xBABA: true,
	0xCACA: true, 0xDADA: true, 0xEAEA: true, 0xFAFA: true,
}

// isGREASE reports whether value is a GREASE value.
func isGREASE(v uint16) bool {
	return greaseValues[v]
}

const hexChars = "0123456789abcdef"

func appendHexUint16(dst []byte, v uint16) []byte {
	return append(dst,
		hexChars[(v>>12)&0xf],
		hexChars[(v>>8)&0xf],
		hexChars[(v>>4)&0xf],
		hexChars[v&0xf],
	)
}

// ComputeJA4 generates the JA4 fingerprint from a parsed ClientHelloInfo.
//
// Format: {proto}{version}{sni}{cipher_count:02d}{ext_count:02d}{alpn}_{cipher_hash}_{ext_hash}
// Example: t13d1516h2_8daaf6152771_02713d6af862
//
// Aligned with FoxIO JA4 Specification.
func ComputeJA4(info *ClientHelloInfo) string {
	// ── Protocol ──────────────────────────────────────────────────────────
	// Always 't' for TLS; 'q' for QUIC (not handled here — placeholder 't').
	proto := "t"

	// ── TLS Version ───────────────────────────────────────────────────────
	// Use supported_versions extension if present, otherwise legacy_version.
	version := tlsVersionString(info.LegacyVersion)
	if len(info.SupportedVersions) > 0 {
		highest := uint16(0)
		for _, v := range info.SupportedVersions {
			if !isGREASE(v) && v > highest {
				highest = v
			}
		}
		if highest != 0 {
			version = tlsVersionString(highest)
		}
	}

	// ── SNI ───────────────────────────────────────────────────────────────
	// 'd' if SNI extension (type 0) appears in raw extension list, 'i' otherwise.
	sni := "i"
	if info.SNIPresent {
		sni = "d"
	}

	// ── Cipher suites ─────────────────────────────────────────────────────
	// Filter GREASE; count; hash sorted list.
	filteredCiphers := make([]uint16, 0, len(info.CipherSuites))
	for _, cs := range info.CipherSuites {
		if !isGREASE(cs) {
			filteredCiphers = append(filteredCiphers, cs)
		}
	}
	cipherCount := len(filteredCiphers)
	if cipherCount > 99 {
		cipherCount = 99
	}
	cipherHash := hashCiphers(filteredCiphers)

	// ── Extensions ────────────────────────────────────────────────────────
	// Filter GREASE; SNI *is* included in the count but excluded from the hash.
	filteredExts := make([]uint16, 0, len(info.Extensions))
	hashableExts := make([]uint16, 0, len(info.Extensions))
	for _, ext := range info.Extensions {
		if !isGREASE(ext) {
			filteredExts = append(filteredExts, ext)
			// Exclude SNI (0x0000) and ALPN (0x0010) from hash per spec.
			if ext != 0x0000 && ext != 0x0010 {
				hashableExts = append(hashableExts, ext)
			}
		}
	}
	extCount := len(filteredExts)
	if extCount > 99 {
		extCount = 99
	}

	// ── Section C Hash (Extensions + Signature Algorithms) ────────────────
	filteredSigAlgs := make([]uint16, 0, len(info.SignatureAlgorithms))
	for _, sa := range info.SignatureAlgorithms {
		if !isGREASE(sa) {
			filteredSigAlgs = append(filteredSigAlgs, sa)
		}
	}
	extHash := hashSectionC(hashableExts, filteredSigAlgs)

	// ── ALPN ──────────────────────────────────────────────────────────────
	// First + last char of first ALPN value, or "00" if none.
	alpn := alpnString(info.ALPNProtocols)

	// Build output string directly with 36 chars: {proto(1)}{version(2)}{sni(1)}{cc(2)}{ec(2)}{alpn(2)}_{ch(12)}_{eh(12)} = 36
	var buf [36]byte
	buf[0] = proto[0]
	buf[1] = version[0]
	buf[2] = version[1]
	buf[3] = sni[0]
	buf[4] = '0' + byte(cipherCount/10)
	buf[5] = '0' + byte(cipherCount%10)
	buf[6] = '0' + byte(extCount/10)
	buf[7] = '0' + byte(extCount%10)
	buf[8] = alpn[0]
	buf[9] = alpn[1]
	buf[10] = '_'
	copy(buf[11:23], cipherHash)
	buf[23] = '_'
	copy(buf[24:36], extHash)

	return string(buf[:])
}

// ComputeJA4FromFields generates the JA4 fingerprint from raw fields.
func ComputeJA4FromFields(
	legacyVersion uint16,
	cipherSuites []uint16,
	extensionTypes []uint16,
	supportedVersions []uint16,
	alpnProtocols []string,
	signatureAlgorithms []uint16,
	sniPresent bool,
) string {
	info := &ClientHelloInfo{
		LegacyVersion:       legacyVersion,
		CipherSuites:        cipherSuites,
		Extensions:          extensionTypes,
		SupportedVersions:   supportedVersions,
		ALPNProtocols:       alpnProtocols,
		SignatureAlgorithms: signatureAlgorithms,
		SNIPresent:          sniPresent,
	}
	return ComputeJA4(info)
}

// tlsVersionString converts a TLS version uint16 to the two-digit JA4 string.
func tlsVersionString(v uint16) string {
	switch v {
	case 0x0301:
		return "10"
	case 0x0302:
		return "11"
	case 0x0303:
		return "12"
	case 0x0304:
		return "13"
	case 0x0300:
		return "03"
	default:
		return "00"
	}
}

// alpnString returns the JA4 ALPN component.
func alpnString(protocols []string) string {
	if len(protocols) == 0 {
		return "00"
	}
	first := protocols[0]
	switch len(first) {
	case 0:
		return "00"
	case 1:
		return string([]byte{first[0], '0'})
	default:
		return string([]byte{first[0], first[len(first)-1]})
	}
}

// hashCiphers returns the Section B component (12 hex chars).
func hashCiphers(ciphers []uint16) string {
	if len(ciphers) == 0 {
		return "000000000000"
	}
	sorted := make([]uint16, len(ciphers))
	copy(sorted, ciphers)
	slices.Sort(sorted)

	// Each cipher is 4 hex chars, comma separated: 4*N + (N-1) = 5*N - 1 bytes
	buf := make([]byte, 0, len(sorted)*5)
	for i, cs := range sorted {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = appendHexUint16(buf, cs)
	}
	h := sha256.Sum256(buf)
	return hex.EncodeToString(h[:6])
}

// hashSectionC returns the Section C component (12 hex chars).
func hashSectionC(exts []uint16, sigAlgs []uint16) string {
	if len(exts) == 0 {
		return "000000000000"
	}

	// 1. Sort Extensions
	sortedExts := make([]uint16, len(exts))
	copy(sortedExts, exts)
	slices.Sort(sortedExts)

	buf := make([]byte, 0, len(sortedExts)*5+len(sigAlgs)*5+1)
	for i, ext := range sortedExts {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = appendHexUint16(buf, ext)
	}

	// 2. Original order for SigAlgs
	if len(sigAlgs) > 0 {
		buf = append(buf, '_')
		for i, sa := range sigAlgs {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = appendHexUint16(buf, sa)
		}
	}

	h := sha256.Sum256(buf)
	return hex.EncodeToString(h[:6])
}
