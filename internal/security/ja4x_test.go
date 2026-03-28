package security

import (
	"context"
	"encoding/base64"
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
	parts := splitJA4X(result)
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
	parts := splitJA4X(result)

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

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
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

func splitJA4X(s string) []string {
	var result []string
	var current string
	for _, c := range s {
		if c == '_' {
			result = append(result, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

func TestPipeline_JA4XWhitelistBypass(t *testing.T) {
	cfg := &PipelineConfig{
		ALPNBrowserBypass:   false,
		JA4WhitelistBypass:  true,
		JA4XEnabled:         true,
		JA4XWhitelistBypass: true,
		Whitelist:           map[string]bool{},
	}
	p := NewPipeline(cfg, &mockRedis{dial: 0}, nil)
	p.UpdateJA4XSets(
		map[string]bool{"abc123def456_abc123def456_abc123def456": true},
		map[string]bool{},
	)

	result := p.Process(context.Background(), &ConnectionContext{
		ClientIP: "1.2.3.4",
		JA4X:     "abc123def456_abc123def456_abc123def456",
		ALPN:     "http/1.1",
	})

	if !result.Bypassed {
		t.Error("whitelisted JA4X should bypass")
	}
	if result.BypassReason != "ja4x_whitelist" {
		t.Errorf("bypass reason: got %q, want 'ja4x_whitelist'", result.BypassReason)
	}
}

func TestPipeline_JA4XBlacklistBlock(t *testing.T) {
	cfg := &PipelineConfig{
		ALPNBrowserBypass:   false,
		JA4WhitelistBypass:  true,
		JA4XEnabled:         true,
		JA4XBlacklistBypass: true,
		Whitelist:           map[string]bool{},
	}
	p := NewPipeline(cfg, &mockRedis{dial: 0}, nil)
	p.UpdateJA4XSets(
		map[string]bool{},
		map[string]bool{"blocked_abc_def": true},
	)

	result := p.Process(context.Background(), &ConnectionContext{
		ClientIP: "1.2.3.4",
		JA4X:     "blocked_abc_def",
		ALPN:     "http/1.1",
	})

	if result.Bypassed {
		t.Error("blacklisted JA4X should not set bypassed=true")
	}
	if result.Action != "block" {
		t.Errorf("action: got %q, want 'block'", result.Action)
	}
	if result.BypassReason != "ja4x_blacklist" {
		t.Errorf("block reason: got %q, want 'ja4x_blacklist'", result.BypassReason)
	}
}

func TestPipeline_JA4XBlacklistSignal(t *testing.T) {
	cfg := &PipelineConfig{
		ALPNBrowserBypass:   false,
		JA4WhitelistBypass:  true,
		JA4XEnabled:         true,
		JA4XBlacklistBypass: false,
		Whitelist:           map[string]bool{},
		JA4XBlacklistScore:  80,
	}
	p := NewPipeline(cfg, &mockRedis{dial: 0}, nil)
	p.UpdateJA4XSets(
		map[string]bool{},
		map[string]bool{"signal_abc_def": true},
	)

	result := p.Process(context.Background(), &ConnectionContext{
		ClientIP: "1.2.3.4",
		JA4X:     "signal_abc_def",
		ALPN:     "http/1.1",
	})

	found := false
	for _, s := range result.Signals {
		if s.Name == "ja4x_blacklist" {
			found = true
			if s.Score != 80 {
				t.Errorf("signal score: got %d, want 80", s.Score)
			}
		}
	}
	if !found {
		t.Error("expected ja4x_blacklist signal")
	}
}

func TestPipeline_JA4XExtractionFromCert(t *testing.T) {
	cfg := &PipelineConfig{
		ALPNBrowserBypass:  true,
		JA4WhitelistBypass: true,
		JA4XEnabled:        true,
		Whitelist:          map[string]bool{},
	}
	p := NewPipeline(cfg, &mockRedis{dial: 0}, nil)

	ctx := &ConnectionContext{
		ClientIP:          "1.2.3.4",
		ALPN:              "h2",
		JA4X:              "",
		ClientCertificate: []byte{},
	}

	result := p.Process(context.Background(), ctx)

	if result.BypassReason == "alpn_browser" {
		if ctx.JA4X != "" {
			t.Errorf("JA4X should remain empty when client cert is empty")
		}
	}
}

func TestUpdateJA4XSets(t *testing.T) {
	p := newTestPipeline(0)
	p.UpdateJA4XSets(
		map[string]bool{"whitelist1": true},
		map[string]bool{"blacklist1": true},
	)

	p.mu.RLock()
	if len(p.JA4XWhitelist) != 1 || !p.JA4XWhitelist["whitelist1"] {
		t.Error("whitelist not updated")
	}
	if len(p.JA4XBlacklist) != 1 || !p.JA4XBlacklist["blacklist1"] {
		t.Error("blacklist not updated")
	}
	p.mu.RUnlock()
}
