package tls

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
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
	var filteredCiphers []uint16
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
	var filteredExts []uint16
	var hashableExts []uint16
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
	var filteredSigAlgs []uint16
	for _, sa := range info.SignatureAlgorithms {
		if !isGREASE(sa) {
			filteredSigAlgs = append(filteredSigAlgs, sa)
		}
	}
	extHash := hashSectionC(hashableExts, filteredSigAlgs)

	// ── ALPN ──────────────────────────────────────────────────────────────
	// First + last char of first ALPN value, or "00" if none.
	alpn := alpnString(info.ALPNProtocols)

	return fmt.Sprintf("%s%s%s%02d%02d%s_%s_%s",
		proto, version, sni,
		cipherCount, extCount, alpn,
		cipherHash, extHash,
	)
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
		return string(first[0]) + "0"
	default:
		return string(first[0]) + string(first[len(first)-1])
	}
}

// hashCiphers returns the Section B component.
func hashCiphers(ciphers []uint16) string {
	if len(ciphers) == 0 {
		return "000000000000"
	}
	sorted := make([]uint16, len(ciphers))
	copy(sorted, ciphers)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	parts := make([]string, len(sorted))
	for i, cs := range sorted {
		parts[i] = fmt.Sprintf("%04x", cs)
	}
	s := strings.Join(parts, ",")
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)[:12]
}

// hashSectionC returns the Section C component.
func hashSectionC(exts []uint16, sigAlgs []uint16) string {
	if len(exts) == 0 {
		return "000000000000"
	}

	// 1. Sort Extensions
	sortedExts := make([]uint16, len(exts))
	copy(sortedExts, exts)
	sort.Slice(sortedExts, func(i, j int) bool { return sortedExts[i] < sortedExts[j] })

	extParts := make([]string, len(sortedExts))
	for i, ext := range sortedExts {
		extParts[i] = fmt.Sprintf("%04x", ext)
	}
	extStr := strings.Join(extParts, ",")

	// 2. Original order for SigAlgs
	var combined string
	if len(sigAlgs) > 0 {
		sigParts := make([]string, len(sigAlgs))
		for i, sa := range sigAlgs {
			sigParts[i] = fmt.Sprintf("%04x", sa)
		}
		sigStr := strings.Join(sigParts, ",")
		combined = extStr + "_" + sigStr
	} else {
		combined = extStr
	}

	h := sha256.Sum256([]byte(combined))
	return fmt.Sprintf("%x", h)[:12]
}
