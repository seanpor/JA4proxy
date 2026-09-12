// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 Sean O'Riordain.
// Pure MIT fallback stub for royalty-free / non-FoxIO builds.

//go:build no_ja4plus

package quic

// ComputeJA4Q returns empty string when built with no_ja4plus.
// This excludes FoxIO License 1.1 / patent-pending JA4Q code.
func ComputeJA4Q(version uint32, features *ClientHelloFeatures) string {
	return ""
}
