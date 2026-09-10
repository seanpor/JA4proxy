//go:build !no_ja4plus

package quic

import (
	"testing"
)

func TestComputeJA4Q_Version1(t *testing.T) {
	features := &ClientHelloFeatures{
		SNI:               "example.com",
		SupportedVersions: []uint16{0x0303}, // TLS 1.3
		ALPN:              []string{"h3"},
	}

	result := ComputeJA4Q(Version1, features)
	if result == "" {
		t.Fatal("expected non-empty result")
	}
	// Should start with quicv1_example.com_ and end with 12 hex chars
	if len(result) < 30 {
		t.Fatalf("result too short: %s", result)
	}
	// Check the structure: version_sni_hash
	for i, c := range result {
		if c == '_' {
			if i > 0 {
				// Found underscore, check prefix
				if result[:i] != "quicv1" {
					t.Fatalf("unexpected version prefix: %s", result[:i])
				}
			}
			break
		}
	}
	// Last 12 chars should be hex
	hash := result[len(result)-12:]
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("unexpected char in hash: %c", c)
		}
	}
}

func TestComputeJA4Q_Version2(t *testing.T) {
	features := &ClientHelloFeatures{
		SNI:               "test.org",
		SupportedVersions: []uint16{0x0303},
	}

	result := ComputeJA4Q(Version2, features)
	if len(result) < 25 {
		t.Fatalf("result too short: %s", result)
	}
	if result[:7] != "quicv2_" {
		t.Fatalf("unexpected version prefix: %s", result[:7])
	}
}

func TestComputeJA4Q_DraftVersion(t *testing.T) {
	features := &ClientHelloFeatures{
		SNI: "draft.example.com",
	}

	result := ComputeJA4Q(0xff00001d, features)
	if len(result) < 28 {
		t.Fatalf("result too short: %s", result)
	}
	// draft-29 produces "draft29" prefix
	if result[:7] != "draft29" {
		t.Fatalf("unexpected version prefix: %s", result[:7])
	}
}

func TestComputeJA4Q_UnknownVersion(t *testing.T) {
	features := &ClientHelloFeatures{
		SNI: "unknown.example.com",
	}

	result := ComputeJA4Q(0x12345678, features)
	if len(result) < 28 {
		t.Fatalf("result too short: %s", result)
	}
	if result[:7] != "unknown" {
		t.Fatalf("unexpected version prefix: %s", result[:7])
	}
}

func TestComputeJA4Q_NoSNI(t *testing.T) {
	features := &ClientHelloFeatures{
		SupportedVersions: []uint16{0x0303},
	}

	result := ComputeJA4Q(Version1, features)
	if result[:13] != "quicv1_nosni_" {
		t.Fatalf("unexpected prefix: %s", result)
	}
}

func TestComputeJA4Q_NilFeatures(t *testing.T) {
	result := ComputeJA4Q(Version1, nil)
	if result != "" {
		t.Fatalf("expected empty result for nil features, got: %s", result)
	}
}

func TestComputeJA4Q_Consistency(t *testing.T) {
	features := &ClientHelloFeatures{
		SNI:               "consistent.example.com",
		SupportedVersions: []uint16{0x0303},
		ALPN:              []string{"h3", "h3-29"},
		SignatureAlgorithms: []uint16{0x0403, 0x0503, 0x0603},
		ExtensionOrder:    []uint16{0x0000, 0x000d, 0x0010, 0x002b},
	}

	result1 := ComputeJA4Q(Version1, features)
	result2 := ComputeJA4Q(Version1, features)

	if result1 != result2 {
		t.Fatalf("inconsistent results: %s != %s", result1, result2)
	}
}
