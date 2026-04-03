package tls

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestExtractJA4X_Empty(t *testing.T) {
	result := ExtractJA4X(nil)
	if result != "000000000000_000000000000_000000000000" {
		t.Errorf("empty cert: got %q, want sentinel", result)
	}
}

func TestExtractJA4X_EmptyBytes(t *testing.T) {
	result := ExtractJA4X([]byte{})
	if result != "000000000000_000000000000_000000000000" {
		t.Errorf("empty bytes: got %q, want sentinel", result)
	}
}

func TestExtractJA4X_InvalidDER(t *testing.T) {
	result := ExtractJA4X([]byte{0x00, 0x01, 0x02, 0x03})
	if result != "000000000000_000000000000_000000000000" {
		t.Errorf("invalid DER: got %q, want sentinel", result)
	}
}

func TestExtractJA4X_Format(t *testing.T) {
	result := ExtractJA4X([]byte(`-----BEGIN CERTIFICATE-----`))
	parts := strings.Split(result, "_")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}
	for _, p := range parts {
		if len(p) != 12 {
			t.Errorf("each part should be 12 chars, got %q", p)
		}
	}
}

func TestExtractJA4X_RealCertificate(t *testing.T) {
	certB64 := "MIIDWTCCAkGgAwIBAgITJOxzb4jON/Jq7qKW5MoNZZ7xnDANBgkqhkiG9w0BAQsFADAuMRkwFwYDVQQDDBB0ZXN0LmV4YW1wbGUuY29tMREwDwYDVQQKDAhUZXN0IE9yZzAeFw0yNjAzMjgxOTM1MDlaFw0yNzAzMjgxOTM1MDlaMC4xGTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5jb20xETAPBgNVBAoMCFRlc3QgT3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2yC33VO2kamhtB6i18unclfbsLKgBfKhLzCgGLZRXzZ0j/h3TuwUBPCmcEFsW1rW1kXP/svWH0Du5K9WtwsjCQzBLd4dR4Ogc56737Hi87SpDrRBFduzm8ISbXFRKqStFASIY7BBbwOR/kHnX9JQwNP093FZxsgVKNjVKcAlFioqVEu4ga0x20rlvNmhFcYxVjTI29cGtRbwS50MhZ48ZRd2h8PlLXffdIWSrMVCmsRXdugI+yOYmL76i6GTrUzNVdyJF2QdvKYJ3cL+TIt9x8lc8WzMVsliMkS21uRKHfbzXAzuSBUeMcNjQb3O+x8+v/vWhwuGJ6wPRenDYGm9OQIDAQABo3AwbjAdBgNVHQ4EFgQURRU+BR06yBtA48PMeoWMniKio7IwHwYDVR0jBBgwFoAURRU+BR06yBtA48PMeoWMniKio7IwDwYDVR0TAQH/BAUwAwEB/zAbBgNVHREEFDASghB0ZXN0LmV4YW1wbGUuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQB3AY78EHi1SISfcofvjeAPnhl7SiMGTJd5mZub7MYrjui55qmJfwFDB5MsUYDQ0FtPytKirwrL6WQjiZoMiMIBRp/gdksofdogijyvNcQWAJNYYIZhpTaT4m9/2jseLp2qmpky9sr8g7sM2sg+9dPnhvKu2GB8Z3bvObslSaR+R4D47rIzDxN94ncIp7/4akAblAuG/pO+kTNwSS8USosAmlYQEXUEYK78STjPxT6affswsaeXHDA4ri6mTHh61E6YRur3v8LwB66GdFOCPOTbqmjSSEqsbat32iNpfPJuddQCEYP8M/p+SZ/5bjJ1VeDz5Zoqfe89Uw8VePkMKYxx"
	certDER, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		t.Fatalf("failed to decode test certificate: %v", err)
	}

	result := ExtractJA4X(certDER)
	parts := strings.Split(result, "_")

	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d: %q", len(parts), result)
	}

	for i, p := range parts {
		if len(p) != 12 {
			t.Errorf("part %d: expected 12 chars, got %d: %q", i, len(p), p)
		}
		if !isHex(p) {
			t.Errorf("part %d: not valid hex: %q", i, p)
		}
	}

	if parts[0] == "000000000000" {
		t.Error("issuer hash should not be sentinel for valid cert")
	}
	if parts[1] == "000000000000" {
		t.Error("subject hash should not be sentinel for valid cert")
	}
	if parts[2] == "000000000000" {
		t.Error("SAN hash should not be sentinel for cert with SAN")
	}
}

func TestExtractJA4X_ParityWithPython(t *testing.T) {
	certB64 := "MIIDWTCCAkGgAwIBAgITJOxzb4jON/Jq7qKW5MoNZZ7xnDANBgkqhkiG9w0BAQsFADAuMRkwFwYDVQQDDBB0ZXN0LmV4YW1wbGUuY29tMREwDwYDVQQKDAhUZXN0IE9yZzAeFw0yNjAzMjgxOTM1MDlaFw0yNzAzMjgxOTM1MDlaMC4xGTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5jb20xETAPBgNVBAoMCFRlc3QgT3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2yC33VO2kamhtB6i18unclfbsLKgBfKhLzCgGLZRXzZ0j/h3TuwUBPCmcEFsW1rW1kXP/svWH0Du5K9WtwsjCQzBLd4dR4Ogc56737Hi87SpDrRBFduzm8ISbXFRKqStFASIY7BBbwOR/kHnX9JQwNP093FZxsgVKNjVKcAlFioqVEu4ga0x20rlvNmhFcYxVjTI29cGtRbwS50MhZ48ZRd2h8PlLXffdIWSrMVCmsRXdugI+yOYmL76i6GTrUzNVdyJF2QdvKYJ3cL+TIt9x8lc8WzMVsliMkS21uRKHfbzXAzuSBUeMcNjQb3O+x8+v/vWhwuGJ6wPRenDYGm9OQIDAQABo3AwbjAdBgNVHQ4EFgQURRU+BR06yBtA48PMeoWMniKio7IwHwYDVR0jBBgwFoAURRU+BR06yBtA48PMeoWMniKio7IwDwYDVR0TAQH/BAUwAwEB/zAbBgNVHREEFDASghB0ZXN0LmV4YW1wbGUuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQB3AY78EHi1SISfcofvjeAPnhl7SiMGTJd5mZub7MYrjui55qmJfwFDB5MsUYDQ0FtPytKirwrL6WQjiZoMiMIBRp/gdksofdogijyvNcQWAJNYYIZhpTaT4m9/2jseLp2qmpky9sr8g7sM2sg+9dPnhvKu2GB8Z3bvObslSaR+R4D47rIzDxN94ncIp7/4akAblAuG/pO+kTNwSS8USosAmlYQEXUEYK78STjPxT6affswsaeXHDA4ri6mTHh61E6YRur3v8LwB66GdFOCPOTbqmjSSEqsbat32iNpfPJuddQCEYP8M/p+SZ/5bjJ1VeDz5Zoqfe89Uw8VePkMKYxx"
	certDER, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		t.Fatalf("failed to decode test certificate: %v", err)
	}

	result := ExtractJA4X(certDER)

	expectedFromPython := "d4e9368ed7f9_d4e9368ed7f9_4c48f54aa568"
	if result != expectedFromPython {
		t.Errorf("JA4X parity failed with Python: got %q, want %q", result, expectedFromPython)
	}
}

func TestHash12_Empty(t *testing.T) {
	h := hash12("")
	if h != "000000000000" {
		t.Errorf("empty: got %q, want sentinel", h)
	}
}

func TestHash12_NonEmpty(t *testing.T) {
	h := hash12("test")
	if h == "000000000000" {
		t.Error("non-empty should not return sentinel")
	}
	if len(h) != 12 {
		t.Errorf("hash length: got %d, want 12", len(h))
	}
}

func TestHash12_Deterministic(t *testing.T) {
	h1 := hash12("test")
	h2 := hash12("test")
	if h1 != h2 {
		t.Error("same input should produce same hash")
	}
}

func TestHash12_DifferentInputs(t *testing.T) {
	h1 := hash12("a")
	h2 := hash12("b")
	if h1 == h2 {
		t.Error("different inputs should produce different hashes")
	}
}

func BenchmarkExtractJA4X(b *testing.B) {
	certB64 := "MIIDWTCCAkGgAwIBAgITJOxzb4jON/Jq7qKW5MoNZZ7xnDANBgkqhkiG9w0BAQsFADAuMRkwFwYDVQQDDBB0ZXN0LmV4YW1wbGUuY29tMREwDwYDVQQKDAhUZXN0IE9yZzAeFw0yNjAzMjgxOTM1MDlaFw0yNzAzMjgxOTM1MDlaMC4xGTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5jb20xETAPBgNVBAoMCFRlc3QgT3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2yC33VO2kamhtB6i18unclfbsLKgBfKhLzCgGLZRXzZ0j/h3TuwUBPCmcEFsW1rW1kXP/svWH0Du5K9WtwsjCQzBLd4dR4Ogc56737Hi87SpDrRBFduzm8ISbXFRKqStFASIY7BBbwOR/kHnX9JQwNP093FZxsgVKNjVKcAlFioqVEu4ga0x20rlvNmhFcYxVjTI29cGtRbwS50MhZ48ZRd2h8PlLXffdIWSrMVCmsRXdugI+yOYmL76i6GTrUzNVdyJF2QdvKYJ3cL+TIt9x8lc8WzMVsliMkS21uRKHfbzXAzuSBUeMcNjQb3O+x8+v/vWhwuGJ6wPRenDYGm9OQIDAQABo3AwbjAdBgNVHQ4EFgQURRU+BR06yBtA48PMeoWMniKio7IwHwYDVR0jBBgwFoAURRU+BR06yBtA48PMeoWMniKio7IwDwYDVR0TAQH/BAUwAwEB/zAbBgNVHREEFDASghB0ZXN0LmV4YW1wbGUuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQB3AY78EHi1SISfcofvjeAPnhl7SiMGTJd5mZub7MYrjui55qmJfwFDB5MsUYDQ0FtPytKirwrL6WQjiZoMiMIBRp/gdksofdogijyvNcQWAJNYYIZhpTaT4m9/2jseLp2qmpky9sr8g7sM2sg+9dPnhvKu2GB8Z3bvObslSaR+R4D47rIzDxN94ncIp7/4akAblAuG/pO+kTNwSS8USosAmlYQEXUEYK78STjPxT6affswsaeXHDA4ri6mTHh61E6YRur3v8LwB66GdFOCPOTbqmjSSEqsbat32iNpfPJuddQCEYP8M/p+SZ/5bjJ1VeDz5Zoqfe89Uw8VePkMKYxx"
	certDER, _ := base64.StdEncoding.DecodeString(certB64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractJA4X(certDER)
	}
}

func BenchmarkExtractJA4XEmpty(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractJA4X(nil)
	}
}

func BenchmarkExtractJA4XInvalid(b *testing.B) {
	invalidDER := []byte{0x00, 0x01, 0x02, 0x03}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractJA4X(invalidDER)
	}
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
