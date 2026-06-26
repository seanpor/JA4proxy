package security

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
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
// phase-248: offense counter operations.
func (m *mockRedis) Incr(_ context.Context, _ string) (int64, error)            { return 0, nil }
func (m *mockRedis) Expire(_ context.Context, _ string, _ time.Duration) error  { return nil }
func (m *mockRedis) CountKeys(_ context.Context, _ string) int                  { return 0 }

func newTestPipeline(dial int) *Pipeline {
	cfg := &PipelineConfig{
		ALPNBrowserBypass:  true,
		JA4WhitelistBypass: true,
		JA4BlockingEnabled: true,
		MTLSBypass:         true,
		Whitelist:          map[string]bool{"t13d1516h2_8daaf6152771_02713d6af862": true},
		Blacklist:          map[string]bool{"t13d190900_9dc949149365_97f8aa674fd9": true},
	}
	p := NewPipeline(cfg, &mockRedis{dial: dial}, nil)
	p.Sync = true
	return p
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
	p.Sync = true
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
	p.Sync = true
	result := p.Process(context.Background(), &ConnectionContext{
		ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4",
		ALPN: "h2",
	})
	if result.Bypassed {
		t.Error("h2 ALPN should NOT bypass when alpn_browser_bypass is disabled")
	}
}

// Regression test for JA4PROXY-2026-0067 — Unbounded fire-and-forget goroutines
// for mesh drift audit. Before the fix, every scored connection spawned an
// unbounded goroutine. The fix uses a bounded auditWorker pool.
func TestPipeline_AuditWorkerBounded(t *testing.T) {
	cfg := &PipelineConfig{
		Whitelist: map[string]bool{},
		Blacklist: map[string]bool{},
	}
	redis := &mockRedis{dial: 0, data: make(map[string]string)}
	p := NewPipeline(cfg, redis, nil)
	p.Sync = true

	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	base := runtime.NumGoroutine()

	// Process many connections with score > 0 to trigger audit jobs.
	var wg sync.WaitGroup
	const iterations = 500
	wg.Add(iterations)
	for i := 0; i < iterations; i++ {
		go func(idx int) {
			defer wg.Done()
			conn := &ConnectionContext{
				ParsedIP: net.ParseIP(fmt.Sprintf("192.168.1.%d", idx%250+1)),
				ClientIP: fmt.Sprintf("192.168.1.%d", idx%250+1),
			}
			p.Process(context.Background(), conn)
		}(i)
	}
	wg.Wait()

	// Allow goroutines to settle.
	for i := 0; i < 10; i++ {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
	}
	after := runtime.NumGoroutine()
	growth := after - base
	// The bounded worker pool should prevent unbounded growth.
	// Pre-fix: 500 goroutines would leak. Post-fix: bounded to 1 audit worker.
	if growth > 20 {
		t.Fatalf("audit worker leaked goroutines: base=%d after=%d growth=%d "+
			"(0067 regression — unbounded goroutine spawn)",
			base, after, growth)
	}
}

// Regression test for JA4PROXY-2026-0069 — processInternal reads
// PipelineConfig fields outside the lock scope. Verifies that config reads
// for JA4X toggles are performed under RLock.
func TestPipeline_ConfigReadUnderLock(t *testing.T) {
	cfg := &PipelineConfig{
		Whitelist:           map[string]bool{},
		Blacklist:           map[string]bool{},
		JA4XEnabled:         true,
		JA4XBlockingEnabled: false,
		JA4XBlacklistScore:  50,
	}
	redis := &mockRedis{dial: 0}
	p := NewPipeline(cfg, redis, nil)
	p.JA4XBlacklist = map[string]bool{"test_ja4x": true}
	p.Sync = true

	// Concurrently process connections and reload config to exercise the lock.
	var wg sync.WaitGroup
	wg.Add(2)

	// Writer: periodically swap config to trigger data race detection.
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			p.mu.Lock()
			newCfg := *p.cfg
			p.cfg = &newCfg
			p.mu.Unlock()
			time.Sleep(time.Microsecond)
		}
	}()

	// Reader: process connections that read JA4X config fields.
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			conn := &ConnectionContext{
				ParsedIP: net.ParseIP("10.0.0.1"),
				ClientIP: "10.0.0.1",
				JA4X:     "test_ja4x",
			}
			p.Process(context.Background(), conn)
		}
	}()

	wg.Wait()
	// Run with -race flag to detect data races.
}
