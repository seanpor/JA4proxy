package security

import (
	"net"
	"context"
	"encoding/base64"
	"testing"
)

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
		ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4",
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
		JA4XBlockingEnabled: true,
		Whitelist:           map[string]bool{},
	}
	p := NewPipeline(cfg, &mockRedis{dial: 0}, nil)
	p.UpdateJA4XSets(
		map[string]bool{},
		map[string]bool{"blocked_abc_def": true},
	)

	result := p.Process(context.Background(), &ConnectionContext{
		ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4",
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
		JA4XBlockingEnabled: false,
		Whitelist:           map[string]bool{},
		JA4XBlacklistScore:  80,
	}
	p := NewPipeline(cfg, &mockRedis{dial: 0}, nil)
	p.UpdateJA4XSets(
		map[string]bool{},
		map[string]bool{"signal_abc_def": true},
	)

	result := p.Process(context.Background(), &ConnectionContext{
		ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4",
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
		ParsedIP: net.ParseIP("1.2.3.4"), ClientIP:          "1.2.3.4",
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

func TestPipeline_JA4XExtractionFromRealCert(t *testing.T) {
	certB64 := "MIIDWTCCAkGgAwIBAgITJOxzb4jON/Jq7qKW5MoNZZ7xnDANBgkqhkiG9w0BAQsFADAuMRkwFwYDVQQDDBB0ZXN0LmV4YW1wbGUuY29tMREwDwYDVQQKDAhUZXN0IE9yZzAeFw0yNjAzMjgxOTM1MDlaFw0yNzAzMjgxOTM1MDlaMC4xGTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5jb20xETAPBgNVBAoMCFRlc3QgT3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2yC33VO2kamhtB6i18unclfbsLKgBfKhLzCgGLZRXzZ0j/h3TuwUBPCmcEFsW1rW1kXP/svWH0Du5K9WtwsjCQzBLd4dR4Ogc56737Hi87SpDrRBFduzm8ISbXFRKqStFASIY7BBbwOR/kHnX9JQwNP093FZxsgVKNjVKcAlFioqVEu4ga0x20rlvNmhFcYxVjTI29cGtRbwS50MhZ48ZRd2h8PlLXffdIWSrMVCmsRXdugI+yOYmL76i6GTrUzNVdyJF2QdvKYJ3cL+TIt9x8lc8WzMVsliMkS21uRKHfbzXAzuSBUeMcNjQb3O+x8+v/vWhwuGJ6wPRenDYGm9OQIDAQABo3AwbjAdBgNVHQ4EFgQURRU+BR06yBtA48PMeoWMniKio7IwHwYDVR0jBBgwFoAURRU+BR06yBtA48PMeoWMniKio7IwDwYDVR0TAQH/BAUwAwEB/zAbBgNVHREEFDASghB0ZXN0LmV4YW1wbGUuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQB3AY78EHi1SISfcofvjeAPnhl7SiMGTJd5mZub7MYrjui55qmJfwFDB5MsUYDQ0FtPytKirwrL6WQjiZoMiMIBRp/gdksofdogijyvNcQWAJNYYIZhpTaT4m9/2jseLp2qmpky9sr8g7sM2sg+9dPnhvKu2GB8Z3bvObslSaR+R4D47rIzDxN94ncIp7/4akAblAuG/pO+kTNwSS8USosAmlYQEXUEYK78STjPxT6affswsaeXHDA4ri6mTHh61E6YRur3v8LwB66GdFOCPOTbqmjSSEqsbat32iNpfPJuddQCEYP8M/p+SZ/5bjJ1VeDz5Zoqfe89Uw8VePkMKYxx"
	certDER, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		t.Fatalf("failed to decode test certificate: %v", err)
	}

	cfg := &PipelineConfig{
		ALPNBrowserBypass:  false,
		JA4WhitelistBypass: false,
		JA4XEnabled:        true,
		Whitelist:          map[string]bool{},
	}
	p := NewPipeline(cfg, &mockRedis{dial: 0}, nil)

	conn := &ConnectionContext{
		ParsedIP: net.ParseIP("1.2.3.4"), ClientIP:          "1.2.3.4",
		ALPN:              "http/1.1",
		JA4X:              "",
		ClientCertificate: certDER,
	}

	p.Process(context.Background(), conn)

	if conn.JA4X == "" {
		t.Error("JA4X should be populated from real cert DER")
	}
	expected := "d4e9368ed7f9_d4e9368ed7f9_4c48f54aa568"
	if conn.JA4X != expected {
		t.Errorf("JA4X from cert: got %q, want %q", conn.JA4X, expected)
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
