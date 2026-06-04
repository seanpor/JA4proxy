package security

import (
	"context"
	"net"
	"testing"
)

// mockRedis is a test double for RedisReader.
type mockRedis struct {
	dial int
	data map[string]string
}

func (m *mockRedis) GetDial(_ context.Context) int                             { return m.dial }
func (m *mockRedis) SIsMember(_ context.Context, _ string, _ interface{}) bool { return false }
func (m *mockRedis) SlidingWindowCount(_ context.Context, _ string, _ float64, _ int) int {
	return 0
}
func (m *mockRedis) HGetAll(_ context.Context, _ string) map[string]string { return nil }
func (m *mockRedis) GetString(_ context.Context, key string) string {
	if m.data == nil {
		return ""
	}
	return m.data[key]
}
func (m *mockRedis) SetString(_ context.Context, key, value string, _ int) {
	if m.data == nil {
		m.data = make(map[string]string)
	}
	m.data[key] = value
}
func (m *mockRedis) Exists(_ context.Context, _ string) bool                        { return false }
func (m *mockRedis) Ping(_ context.Context) error                                   { return nil }
func (m *mockRedis) ZAdd(_ context.Context, _ string, _ float64, _ string)          {}
func (m *mockRedis) ZRemRangeByScore(_ context.Context, _ string, _, _ float64)     {}
func (m *mockRedis) ZRange(_ context.Context, _ string, _, _ int64) []string        { return nil }
func (m *mockRedis) ZCard(_ context.Context, _ string) int64                        { return 0 }
func (m *mockRedis) ZRangeScores(_ context.Context, _ string, _, _ int64) []float64 { return nil }

func newTestPipeline(dial int) *Pipeline {
	cfg := &PipelineConfig{
		ALPNBrowserBypass:  true,
		JA4WhitelistBypass: true,
		JA4BlockingEnabled: true,
		MTLSBypass:         true,
		Whitelist:          map[string]bool{"t13d1516h2_8daaf6152771_02713d6af862": true},
		Blacklist:          map[string]bool{"t13d190900_9dc949149365_97f8aa674fd9": true},
	}
	return NewPipeline(cfg, &mockRedis{dial: dial}, nil)
}

func TestPipeline_ALPNBrowserBypass_H2(t *testing.T) {
	p := newTestPipeline(100)
	result := p.Process(context.Background(), &ConnectionContext{
		ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4",
		ALPN: "h2",
	})
	if !result.Bypassed {
		t.Error("h2 ALPN should trigger browser bypass")
	}
	if result.BypassReason != "alpn_browser" {
		t.Errorf("bypass reason: got %q, want 'alpn_browser'", result.BypassReason)
	}
	if result.Action != "allow" {
		t.Errorf("bypassed action: got %q, want 'allow'", result.Action)
	}
}

func TestPipeline_ALPNBrowserBypass_H1(t *testing.T) {
	p := newTestPipeline(100)
	result := p.Process(context.Background(), &ConnectionContext{
		ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4",
		ALPN: "h1",
	})
	if !result.Bypassed {
		t.Error("h1 ALPN should trigger browser bypass")
	}
}

func TestPipeline_JA4Whitelist_Bypass(t *testing.T) {
	p := newTestPipeline(100)
	result := p.Process(context.Background(), &ConnectionContext{
		ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4",
		JA4: "t13d1516h2_8daaf6152771_02713d6af862",
	})
	if !result.Bypassed {
		t.Error("whitelisted JA4 should bypass")
	}
	if result.BypassReason != "ja4_whitelist" {
		t.Errorf("bypass reason: got %q, want 'ja4_whitelist'", result.BypassReason)
	}
}

func TestPipeline_JA4Blacklist_Block(t *testing.T) {
	p := newTestPipeline(100)
	result := p.Process(context.Background(), &ConnectionContext{
		ParsedIP: net.ParseIP("5.6.7.8"), ClientIP: "5.6.7.8",
		JA4: "t13d190900_9dc949149365_97f8aa674fd9",
	})
	if result.Bypassed {
		t.Error("blacklisted JA4 should not set bypassed=true")
	}
	if result.Action != "block" {
		t.Errorf("blacklisted JA4: action=%q, want 'block'", result.Action)
	}
	if result.BypassReason != "ja4_blacklist" {
		t.Errorf("block reason: got %q, want 'ja4_blacklist'", result.BypassReason)
	}
}

func TestPipeline_MTLSBypass(t *testing.T) {
	p := newTestPipeline(100)
	result := p.Process(context.Background(), &ConnectionContext{
		ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4",
		HasValidClientCert: true,
	})
	if !result.Bypassed {
		t.Error("valid mTLS cert should trigger bypass")
	}
	if result.BypassReason != "mtls" {
		t.Errorf("bypass reason: got %q, want 'mtls'", result.BypassReason)
	}
}

func TestPipeline_MonitorMode_AlwaysAllow(t *testing.T) {
	p := newTestPipeline(0) // dial=0 = monitor mode
	result := p.Process(context.Background(), &ConnectionContext{
		ParsedIP: net.ParseIP("5.6.7.8"), ClientIP: "5.6.7.8",
		JA4: "t13d000000_000000000000_000000000000",
	})
	if result.Action != "allow" {
		t.Errorf("dial=0: action=%q, want 'allow'", result.Action)
	}
	if result.Bypassed {
		t.Error("scored connections should not set bypassed=true")
	}
	// Monitor mode should produce counterfactuals
	if len(result.Counterfactuals) == 0 {
		t.Error("monitor mode should produce counterfactuals")
	}
}

func TestPipeline_FullBlocking_ScoreZero_IsAllow(t *testing.T) {
	p := newTestPipeline(100)
	result := p.Process(context.Background(), &ConnectionContext{
		ParsedIP: net.ParseIP("5.6.7.8"), ClientIP: "5.6.7.8",
		JA4: "t13d000000_000000000000_000000000000",
	})
	if result.Action != "allow" {
		t.Errorf("score=0 at dial=100: action=%q, want 'allow'", result.Action)
	}
}

func TestPipeline_NilRedis_FailOpen(t *testing.T) {
	// nil Redis → dial=0 → monitor mode; must not panic
	cfg := &PipelineConfig{
		ALPNBrowserBypass: true,
	}
	p := NewPipeline(cfg, nil, nil)
	result := p.Process(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4"})
	if result == nil {
		t.Fatal("Process returned nil")
	}
	if result.Action != "allow" {
		t.Errorf("nil redis: action=%q, want 'allow'", result.Action)
	}
}

func TestPipeline_ALPNBypassDisabled(t *testing.T) {
	cfg := &PipelineConfig{
		ALPNBrowserBypass: false, // disabled
		Whitelist:         map[string]bool{},
		Blacklist:         map[string]bool{},
	}
	p := NewPipeline(cfg, &mockRedis{dial: 0}, nil)
	result := p.Process(context.Background(), &ConnectionContext{
		ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4",
		ALPN: "h2",
	})
	if result.Bypassed {
		t.Error("h2 ALPN should NOT bypass when alpn_browser_bypass is disabled")
	}
}
