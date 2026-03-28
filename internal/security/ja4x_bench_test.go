package security

import (
	"encoding/base64"
	"testing"
)

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
