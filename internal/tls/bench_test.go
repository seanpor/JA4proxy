// Copyright 2026 Anomaly Collective
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at:
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under the License.
package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math"
	"math/big"
	"testing"
)

// TestParserPerformance benchmarks TLS ClientHello parsing at scale.
func BenchmarkClientHelloParse(b *testing.B) {
	// Generate a realistic ClientHello buffer
	hello, err := generateTestClientHello()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ResetMemallocs()

	for i := 0; i < b.N; i++ {
		_, err = ParseClientHello(hello)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkJA4Compute benchmarks JA4 fingerprint computation.
func BenchmarkJA4Compute(b *testing.B) {
	hello, err := generateTestClientHello()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ResetMemallocs()

	for i := 0; i < b.N; i++ {
		_ = ComputeJA4(hello)
	}
}

// BenchmarkClientHelloParseAdversarial benchmarks parsing adversarial inputs.
func BenchmarkClientHelloParseAdversarial(b *testing.B) {
	adversarialCases := []struct {
		name string
		data []byte
	}{
		{"truncated", ClientHelloWithTruncation(4)},
		{"GREASE-heavy", ClientHelloWithManyGreaseValues()},
		{"empty", []byte{}},
		{"non-tls", []byte("HTTP/1.1\r\n")},
	}

	b.ResetTimer()
	b.ResetMemallocs()

	for i := 0; i < b.N; i++ {
		for _, tc := range adversarialCases {
			_, err = ParseClientHello(tc.data)
			if err != nil && !bytes.Equal(tc.data, []byte{}) {
				b.Fatalf("%s: %v\n", tc.name, err)
			}
		}
	}
}

// generateTestClientHello constructs a minimal-but-realistic ClientHello buffer for benchmarking.
func generateTestClientHello() (data []byte, _ error) {
	// TLS 1.3 ClientHello: 5 bytes header + version + random(32) + session ticket len = ~46 bytes min
	// Add extensions and certificate/compression lists for realistic size

	// Version: TLS 1.3
	data = append(data, 0x16, 0x03, 0x03)

	// Random (32 bytes — pseudo-random for testing)
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	data = append(data, random...)

	// Session ticket length (0)
	data = append(data, 0x00)

	// Cipher suites list (fake)
	data = append(data, byte(1), 0xf8, 0xf7) // TLS_FALLBACK_SCSV + 2 fake suites (4 bytes total)

	// Compression methods (1 byte: null)
	data = append(data, byte(0))

	// Extensions length (3 bytes)
	extLen := []byte{0x00, 0x00, 0xdc}
	data = append(data, extLen...)

	// Extension: Ellipse Curve Point Formats (10 bytes)
	data = append(data, 0x00, 0x13, byte(4), 0x01, 0x00, 0x23, 0x00, 0x05, 0x00, 0x05)

	// Extension: Elliptic Curve Parameters (13 bytes)
	data = append(data, 0x00, 0x17, byte(4), 0x02, 0x00, 0x1e, 0xc0, 0x2b, 0xcb, 0xb5, 0xa4, 0xf9, 0x8d)

	// Extension: Named Groups (7 bytes)
	data = append(data, 0x00, 0x12, byte(3), 0x00, 0x1d, 0xe6, 0x50, 0xad)

	// Extension: Signature Algorithms (48 bytes)
	data = append(data, 0x00, 0x0d, byte(4), 0x00, 0x0d, 0x00, 0x04, 0x00, 0x17, 0x00, 0x0a, 0xf2, 0xff)

	return data, nil
}

// ClientHelloWithTruncation returns a ClientHello truncated to N bytes (fails parse gracefully).
func ClientHelloWithTruncation(n int) []byte {
	base, _ := generateTestClientHello()
	if len(base) < n {
		return base
	}
	return base[:n]
}

// ClientHelloWithManyGreaseValues returns a ClientHello with maximum GREASE values (stress test parser).
func ClientHelloWithManyGreaseValues() []byte {
	data, _ := generateTestClientHello()

	// Add GREASE extensions until buffer is near 4KB
	greaseExt := []byte{0x00, 0x01, byte(5) /* greasetag */, 0x17, 0x2b, 0x00, 0x1c, 0x98, 0x31, 0x2a, 0x85, 0x9f, 0xf3, 0x86, 0xe3}

	for len(data) < 4096 {
		data = append(data, 0x00, 0xd7) // Extension type: Server Name List
		data = append(data, byte(len(greaseExt)))
		data = append(data, greaseExt...)
	}

	return data
}
