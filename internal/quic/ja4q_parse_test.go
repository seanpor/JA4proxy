package quic

import (
	"testing"
)

func TestParseClientHelloFeatures_Minimal(t *testing.T) {
	// Minimal valid ClientHello body (after handshake header)
	// client_version(2) + random(32) + session_id_len(1) + cipher_suites_len(2) + cipher_suites(2) + compression(1) + extensions_len(2)
	// Total: 2 + 32 + 1 + 2 + 2 + 1 + 2 = 42 bytes minimum
	body := make([]byte, 42)
	body[0] = 0x03 // client_version TLS 1.2
	body[1] = 0x03
	// session_id_len = 0 (at offset 34)
	body[35] = 0 // cipher_suites_len high byte
	body[36] = 2 // cipher_suites_len low byte (2 bytes)
	// cipher_suites: TLS_AES_128_GCM_SHA256
	body[37] = 0x13
	body[38] = 0x01
	// compression_methods_len = 0 (at offset 40)
	body[40] = 0 // extensions_len high byte
	body[41] = 0 // extensions_len low byte (no extensions)

	features, err := ParseClientHelloFeatures(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if features.SNI != "" {
		t.Fatalf("expected empty SNI, got: %s", features.SNI)
	}
	if len(features.ExtensionOrder) != 0 {
		t.Fatalf("expected 0 extensions, got: %d", len(features.ExtensionOrder))
	}
}

func TestParseClientHelloFeatures_TooShort(t *testing.T) {
	body := make([]byte, 30)
	_, err := ParseClientHelloFeatures(body)
	if err == nil {
		t.Fatal("expected error for short body")
	}
}
