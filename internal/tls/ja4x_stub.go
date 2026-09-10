// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 Sean O'Riordain.
// Pure MIT fallback stub for royalty-free / non-FoxIO builds.

//go:build no_ja4plus

package tls

const sentinelHash = "000000000000"

// ExtractJA4X is a stub returning the all-zero sentinel when built under no_ja4plus.
// This excludes FoxIO License 1.1 / patent-pending JA4X code.
func ExtractJA4X(certDER []byte) string {
	return sentinelHash + "_" + sentinelHash + "_" + sentinelHash
}

// ExtractJA4XFromPEM is a stub returning the all-zero sentinel when built under no_ja4plus.
func ExtractJA4XFromPEM(pemData []byte) string {
	return sentinelHash + "_" + sentinelHash + "_" + sentinelHash
}
