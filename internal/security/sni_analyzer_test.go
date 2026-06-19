package security

import "testing"

func newSNIAnalyzer(cfg *SNIAnalyzerConfig) *SNIAnalyzer {
	return NewSNIAnalyzer(cfg, nil)
}

func TestSNIAnalyzer_MissingSNI_SignalFired(t *testing.T) {
	a := newSNIAnalyzer(&SNIAnalyzerConfig{
		MissingSNIEnabled: true,
		MissingSNIScore:   30,
	})
	sigs := a.Analyze("")
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(sigs))
	}
	if sigs[0].Name != "missing_sni" {
		t.Errorf("signal name = %q; want 'missing_sni'", sigs[0].Name)
	}
	if sigs[0].Score != 30 {
		t.Errorf("signal score = %d; want 30", sigs[0].Score)
	}
}

func TestSNIAnalyzer_MissingSNI_DisabledNoSignal(t *testing.T) {
	a := newSNIAnalyzer(&SNIAnalyzerConfig{
		MissingSNIEnabled: false,
	})
	sigs := a.Analyze("")
	if len(sigs) != 0 {
		t.Errorf("disabled missing_sni should produce no signals, got %d", len(sigs))
	}
}

func TestSNIAnalyzer_IPLiteral_IPv4_SignalFired(t *testing.T) {
	a := newSNIAnalyzer(&SNIAnalyzerConfig{
		IPLiteralSNIEnabled: true,
		IPLiteralSNIScore:   25,
	})
	sigs := a.Analyze("1.2.3.4")
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(sigs))
	}
	if sigs[0].Name != "ip_literal_sni" {
		t.Errorf("signal name = %q; want 'ip_literal_sni'", sigs[0].Name)
	}
	if sigs[0].Score != 25 {
		t.Errorf("signal score = %d; want 25", sigs[0].Score)
	}
}

func TestSNIAnalyzer_IPLiteral_IPv6_SignalFired(t *testing.T) {
	a := newSNIAnalyzer(&SNIAnalyzerConfig{
		IPLiteralSNIEnabled: true,
		IPLiteralSNIScore:   25,
	})
	sigs := a.Analyze("2001:db8::1")
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(sigs))
	}
	if sigs[0].Name != "ip_literal_sni" {
		t.Errorf("signal name = %q; want 'ip_literal_sni'", sigs[0].Name)
	}
}

func TestSNIAnalyzer_NormalHostname_NoIPSignal(t *testing.T) {
	a := newSNIAnalyzer(&SNIAnalyzerConfig{
		IPLiteralSNIEnabled: true,
		IPLiteralSNIScore:   25,
	})
	sigs := a.Analyze("example.com")
	for _, s := range sigs {
		if s.Name == "ip_literal_sni" {
			t.Error("normal hostname should not produce ip_literal_sni signal")
		}
	}
}

func TestSNIAnalyzer_DGA_HighEntropy_Scored(t *testing.T) {
	a := newSNIAnalyzer(&SNIAnalyzerConfig{
		DGAEnabled:  true,
		DGAScoreCap: 40,
	})
	// High DGA score: digits, no vowels, high entropy
	sigs := a.Analyze("a8f3bc2d19e74f6a.io")
	found := false
	for _, s := range sigs {
		if s.Name == "dga" {
			found = true
			if s.Score <= 0 {
				t.Errorf("DGA score should be > 0, got %d", s.Score)
			}
		}
	}
	if !found {
		t.Error("high-entropy DGA-like domain should produce 'dga' signal")
	}
}

func TestSNIAnalyzer_DGA_NormalDomain_NotScored(t *testing.T) {
	a := newSNIAnalyzer(&SNIAnalyzerConfig{
		DGAEnabled:  true,
		DGAScoreCap: 40,
	})
	sigs := a.Analyze("google.com")
	for _, s := range sigs {
		if s.Name == "dga" {
			t.Errorf("normal domain 'google.com' should not produce dga signal (score=%d)", s.Score)
		}
	}
}

func TestSNIAnalyzer_UnexpectedSNI_NotInList(t *testing.T) {
	a := newSNIAnalyzer(&SNIAnalyzerConfig{
		UnexpectedSNIEnabled: true,
		UnexpectedSNIScore:   15,
		ExpectedHostnames:    map[string]bool{"myapp.example.com": true},
	})
	sigs := a.Analyze("evil.example.com")
	found := false
	for _, s := range sigs {
		if s.Name == "unexpected_sni" {
			found = true
			if s.Score != 15 {
				t.Errorf("unexpected_sni score = %d; want 15", s.Score)
			}
		}
	}
	if !found {
		t.Error("unexpected SNI should produce signal when not in list")
	}
}

func TestSNIAnalyzer_UnexpectedSNI_InList_NoSignal(t *testing.T) {
	a := newSNIAnalyzer(&SNIAnalyzerConfig{
		UnexpectedSNIEnabled: true,
		UnexpectedSNIScore:   15,
		ExpectedHostnames:    map[string]bool{"myapp.example.com": true},
	})
	sigs := a.Analyze("myapp.example.com")
	for _, s := range sigs {
		if s.Name == "unexpected_sni" {
			t.Error("expected hostname should not produce unexpected_sni signal")
		}
	}
}

func TestSNIAnalyzer_ExpectedHostnames_EmptyList_NoUnexpectedSignal(t *testing.T) {
	a := newSNIAnalyzer(&SNIAnalyzerConfig{
		UnexpectedSNIEnabled: true,
		UnexpectedSNIScore:   15,
		ExpectedHostnames:    map[string]bool{}, // empty — no expected list
	})
	sigs := a.Analyze("anything.example.com")
	for _, s := range sigs {
		if s.Name == "unexpected_sni" {
			t.Error("empty expected list should not produce unexpected_sni signal")
		}
	}
}

// TestRegression_JA4PROXY_2026_0027_CanonicalizeSNIRejectsKeyInjection guards the
// "Redis Key Injection via SNI Hostnames" finding. The deleted Python proxy built
// Redis keys from raw SNI; the Go proxy never does — CanonicalizeSNI rejects
// anything that is not a strict RFC-1123 hostname, so colon/CRLF/glob/NUL
// key-injection payloads are flagged invalid before any value reaches a Redis key.
func TestRegression_JA4PROXY_2026_0027_CanonicalizeSNIRejectsKeyInjection(t *testing.T) {
	injection := []string{
		"evil.com:other:key",      // ':' Redis-key separator smuggling
		"evil.com\r\nSET foo bar", // CRLF command smuggling
		"key\x00inject",           // NUL byte
		"*",                       // glob / KEYS pattern
		"foo bar",                 // whitespace
		"a/b",                     // path separator
	}
	for _, s := range injection {
		if _, ok := CanonicalizeSNI(s); ok {
			t.Errorf("CanonicalizeSNI(%q) accepted; want rejected (key-injection vector)", s)
		}
	}
	if _, ok := CanonicalizeSNI("good.example.com"); !ok {
		t.Error("CanonicalizeSNI(good.example.com) rejected a legitimate hostname")
	}
}
