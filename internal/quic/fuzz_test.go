// Package quic implements QUIC Initial packet parsing and JA4Q fingerprinting.
package quic

import (
	"bytes"
	"testing"
)

func FuzzParseClientHelloFeatures(f *testing.F) {
	// Seed with minimal valid/invalid payloads
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0x00}, 38))
	f.Add([]byte{
		0x03, 0x03, // client_version (TLS 1.2 / 1.3)
		// random 32 bytes
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
		0x00,       // session_id_length = 0
		0x00, 0x02, // cipher_suites_length = 2
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0x01, 0x00, // compression_methods_length = 1, compression = null
		0x00, 0x00, // extensions_length = 0
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		features, err := ParseClientHelloFeatures(data)
		if err != nil {
			if features != nil {
				t.Fatalf("expected nil features on error, got: %+v", features)
			}
			return
		}
		if features == nil {
			t.Fatalf("expected non-nil features when err is nil")
		}

		// Verify ComputeJA4Q does not panic on any parsed features
		_ = ComputeJA4Q(Version1, features)
		_ = ComputeJA4Q(Version2, features)
		_ = ComputeJA4Q(0xff00001d, features)
		_ = ComputeJA4Q(0x12345678, features)
	})
}
