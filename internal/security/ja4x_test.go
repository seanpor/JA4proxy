package security

import (
	"context"
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
