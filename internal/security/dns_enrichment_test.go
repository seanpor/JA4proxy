package security

import (
	"context"
	"net"
	"testing"
)

// mockRedisRW extends mockRedisKV to implement the full RedisWriter interface.
type mockRedisRW struct {
	mockRedisKV
	setValues map[string]string
}

func newMockRedisRW() *mockRedisRW {
	return &mockRedisRW{
		mockRedisKV: mockRedisKV{
			hashes:  make(map[string]map[string]string),
			strings: make(map[string]string),
		},
		setValues: make(map[string]string),
	}
}

func (m *mockRedisRW) SetString(_ context.Context, key, value string, _ int) {
	m.setValues[key] = value
	m.strings[key] = value
}

func (m *mockRedisRW) Exists(_ context.Context, _ string) bool { return false }
func (m *mockRedisRW) Ping(_ context.Context) error            { return nil }

func defaultDNSEnrichmentCfg() *DNSEnrichmentConfig {
	return &DNSEnrichmentConfig{
		Enabled:           true,
		Workers:           1,
		NoPTRScore:        15,
		FCrDNSFailedScore: 20,
		ResidentialScore:  -10,
		TTL:               3600,
	}
}

func TestDNSEnrichment_Disabled_NoSignal(t *testing.T) {
	cfg := defaultDNSEnrichmentCfg()
	cfg.Enabled = false
	d := NewDNSEnrichment(cfg, newMockRedisRW(), nil)
	sig := d.GetSignal(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4"})
	if sig != nil {
		t.Errorf("disabled: expected nil signal, got %v", sig)
	}
}

func TestDNSEnrichment_CachedNoPTR_Signal(t *testing.T) {
	r := newMockRedisRW()
	r.strings["dns:fcrdns:1.2.3.4"] = "no_ptr"
	d := NewDNSEnrichment(defaultDNSEnrichmentCfg(), r, nil)
	sig := d.GetSignal(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4"})
	if sig == nil {
		t.Fatal("cached no_ptr: expected signal")
	}
	if sig.Name != "no_ptr" {
		t.Errorf("expected 'no_ptr', got %q", sig.Name)
	}
	if sig.Score <= 0 {
		t.Errorf("expected positive score, got %d", sig.Score)
	}
}

func TestDNSEnrichment_CachedFCrDNSFailed_Signal(t *testing.T) {
	r := newMockRedisRW()
	r.strings["dns:fcrdns:1.2.3.4"] = "fcrdns_failed"
	d := NewDNSEnrichment(defaultDNSEnrichmentCfg(), r, nil)
	sig := d.GetSignal(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4"})
	if sig == nil {
		t.Fatal("cached fcrdns_failed: expected signal")
	}
	if sig.Name != "fcrdns_failed" {
		t.Errorf("expected 'fcrdns_failed', got %q", sig.Name)
	}
}

func TestDNSEnrichment_CachedResidential_NegativeSignal(t *testing.T) {
	r := newMockRedisRW()
	r.strings["dns:fcrdns:1.2.3.4"] = "confirmed_residential"
	d := NewDNSEnrichment(defaultDNSEnrichmentCfg(), r, nil)
	sig := d.GetSignal(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4"})
	if sig == nil {
		t.Fatal("confirmed_residential: expected signal")
	}
	if sig.Name != "residential_ptr" {
		t.Errorf("expected 'residential_ptr', got %q", sig.Name)
	}
	if sig.Score >= 0 {
		t.Errorf("expected negative score, got %d", sig.Score)
	}
}

func TestDNSEnrichment_NotCached_NoSignalEnqueues(t *testing.T) {
	r := newMockRedisRW()
	// No cached value — returns "" from GetString
	d := NewDNSEnrichment(defaultDNSEnrichmentCfg(), r, nil)
	sig := d.GetSignal(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4", ALPN: "tls"})
	if sig != nil {
		t.Errorf("not cached: expected nil signal (enqueued), got %v", sig)
	}
	// Verify IP was enqueued
	select {
	case ip := <-d.queue:
		if ip != "1.2.3.4" {
			t.Errorf("enqueued IP = %q, want '1.2.3.4'", ip)
		}
	default:
		t.Error("not cached: expected IP to be enqueued in queue")
	}
}

func TestDNSEnrichment_BrowserALPN_NeverEnqueued(t *testing.T) {
	r := newMockRedisRW()
	d := NewDNSEnrichment(defaultDNSEnrichmentCfg(), r, nil)
	sig := d.GetSignal(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4", ALPN: "h2"})
	if sig != nil {
		t.Errorf("h2 ALPN: expected nil signal, got %v", sig)
	}
	// Verify IP was NOT enqueued
	select {
	case ip := <-d.queue:
		t.Errorf("h2 ALPN: IP %q was enqueued but should not be", ip)
	default:
		// Expected: nothing enqueued
	}
}

func TestDNSEnrichment_RedisDown_FailOpen(t *testing.T) {
	// GetString returns "" (as if Redis is down) → enqueues, returns nil
	r := newMockRedisRW()
	d := NewDNSEnrichment(defaultDNSEnrichmentCfg(), r, nil)
	sig := d.GetSignal(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("10.0.0.1"), ClientIP: "10.0.0.1", ALPN: "tls"})
	if sig != nil {
		t.Errorf("redis down: expected nil signal (fail open), got %v", sig)
	}
}
