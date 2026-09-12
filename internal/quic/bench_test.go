package quic

import (
	"testing"
)

func BenchmarkComputeJA4Q(b *testing.B) {
	features := &ClientHelloFeatures{
		SNI:               "benchmark.example.com",
		SupportedVersions: []uint16{0x0303},
		ALPN:              []string{"h3", "h3-29", "h2"},
		SignatureAlgorithms: []uint16{0x0403, 0x0503, 0x0603, 0x0401, 0x0501, 0x0601},
		ExtensionOrder:    []uint16{0x0000, 0x000d, 0x0010, 0x002b, 0x0012, 0xff01},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComputeJA4Q(Version1, features)
	}
}

func BenchmarkParseClientHelloFeatures(b *testing.B) {
	// Minimal ClientHello with SNI and ALPN extensions
	body := make([]byte, 100)
	body[0] = 0x03 // client_version TLS 1.2
	body[1] = 0x03
	// session_id_len = 0 (at offset 34)
	body[35] = 0 // cipher_suites_len high byte
	body[36] = 4 // cipher_suites_len low byte
	body[37] = 0x13 // cipher_suites[0] = TLS_AES_128_GCM_SHA256
	body[38] = 0x01
	body[39] = 0x13 // cipher_suites[1] = TLS_AES_256_GCM_SHA384
	body[40] = 0x02
	body[41] = 0 // compression_methods_len

	// extensions
	body[42] = 0 // extensions_len high byte
	body[43] = 48 // extensions_len low byte

	// SNI extension (type=0x0000)
	body[44] = 0x00
	body[45] = 0x00
	body[46] = 0x00 // SNI len high byte
	body[47] = 16 // SNI len low byte
	body[48] = 0x00 // list_len high byte
	body[49] = 0x14 // list_len low byte (20)
	body[50] = 0x00 // name_type
	body[51] = 0x0e // name_len (14)
	copy(body[52:66], "example.com")

	// ALPN extension (type=0x0010)
	body[66] = 0x00
	body[67] = 0x10
	body[68] = 0x00 // ALPN len high byte
	body[69] = 0x08 // ALPN len low byte
	body[70] = 0x00 // list_len high byte
	body[71] = 0x06 // list_len low byte
	body[72] = 0x02 // proto1 len
	copy(body[73:75], "h3")
	body[75] = 0x01 // proto2 len
	body[76] = 'h'  // proto2
	body[77] = 0x00 // pad

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseClientHelloFeatures(body)
	}
}

func BenchmarkParseCRYPTOFrames(b *testing.B) {
	// 3 CRYPTO frames
	payload := []byte{
		0x06, 0x00, 0x04, 1, 2, 3, 4,
		0x06, 0x04, 0x04, 5, 6, 7, 8,
		0x06, 0x08, 0x04, 9, 10, 11, 12,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseCRYPTOFrames(payload)
	}
}

func BenchmarkDeriveInitialKey(b *testing.B) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04}
	secret := []byte{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = DeriveInitialKey(dcid, secret)
	}
}

func BenchmarkDecryptInitial(b *testing.B) {
	key := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	iv := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
	ciphertext := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecryptInitial(ciphertext, key, iv, nil)
	}
}
