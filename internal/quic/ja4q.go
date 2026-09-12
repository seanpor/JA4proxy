// SPDX-License-Identifier: LicenseRef-FoxIO-1.1
//
// Portions of this file implement JA4Q, a JA4+ fingerprinting method.
// Copyright (c) 2024, FoxIO, LLC. All rights reserved. Patent Pending.
// JA4+ methods are licensed under the FoxIO License 1.1 (non-commercial
// use only). See LICENSE.foxio at the repository root, or
// https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE
//
// The remainder of this file is (c) 2026 Sean O'Riordain, MIT License.
//
// Header style mirrors the convention used in the canonical FoxIO
// repository (see rust/ja4/src/main.rs there).

//go:build !no_ja4plus

package quic

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// JA4Q format (FoxIO JA4+ specification):
//
//	{version}_{sni}_{hash}
//
// Where:
//	version = "quicv1", "quicv2", "draftNNN", or "unknown"
//	sni     = Server Name Indication (lowercased), or "nosni"
//	hash    = SHA-256 truncation of: supported_versions + alpn + sig_algos + ext_order

// ComputeJA4Q computes the JA4Q fingerprint from a QUIC version number and
// the parsed ClientHello features. Returns "" if parsing failed.
func ComputeJA4Q(version uint32, features *ClientHelloFeatures) string {
	if features == nil {
		return ""
	}

	// --- ja4q_t: QUIC version ---
	var ver string
	switch version {
	case Version1:
		ver = "quicv1"
	case Version2:
		ver = "quicv2"
	default:
		if version >= 0xff000000 {
			ver = "draft" + fmt.Sprintf("%d", version&0xff)
		} else {
			ver = "unknown"
		}
	}

	// --- ja4q_v: SNI ---
	sni := strings.ToLower(features.SNI)
	if sni == "" {
		sni = "nosni"
	}

	// --- ja4q_c: hash of ClientHello features ---
	hash := computeJA4QHash(features)

	return ver + "_" + sni + "_" + hash
}

// computeJA4QHash produces the truncated SHA-256 hash of the ClientHello
// features. The hash input is a concatenation of:
//
//	supported_versions (hex, sorted, comma-joined)
//	alpn (in order, comma-joined)
//	signature_algorithms (hex, comma-joined)
//	extension_order (hex, comma-joined)
func computeJA4QHash(ch *ClientHelloFeatures) string {
	var b strings.Builder

	// Supported versions (sorted)
	vers := make([]string, 0, len(ch.SupportedVersions))
	for _, v := range ch.SupportedVersions {
		vers = append(vers, fmt.Sprintf("%04x", v))
	}
	// Sort for consistency
	for i := 1; i < len(vers); i++ {
		for j := i; j > 0 && vers[j] < vers[j-1]; j-- {
			vers[j], vers[j-1] = vers[j-1], vers[j]
		}
	}
	b.WriteString(strings.Join(vers, ","))
	b.WriteByte('|')

	// ALPN protocols (in wire order)
	b.WriteString(strings.Join(ch.ALPN, ","))
	b.WriteByte('|')

	// Signature algorithms (hex pairs, comma-joined)
	sigs := make([]string, 0, len(ch.SignatureAlgorithms))
	for _, s := range ch.SignatureAlgorithms {
		sigs = append(sigs, fmt.Sprintf("%04x", s))
	}
	b.WriteString(strings.Join(sigs, ","))
	b.WriteByte('|')

	// Extension order (hex, comma-joined)
	exts := make([]string, 0, len(ch.ExtensionOrder))
	for _, e := range ch.ExtensionOrder {
		exts = append(exts, fmt.Sprintf("%04x", e))
	}
	b.WriteString(strings.Join(exts, ","))

	// SHA-256 and truncate to 12 hex chars (48 bits)
	hash := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(hash[:6])
}

