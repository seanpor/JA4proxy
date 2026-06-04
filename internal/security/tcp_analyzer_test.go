package security

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

type mockRedisKV struct {
	mockRedis
	hashes  map[string]map[string]string
	strings map[string]string
}

func (m *mockRedisKV) HGetAll(_ context.Context, key string) map[string]string {
	return m.hashes[key]
}

func (m *mockRedisKV) GetString(_ context.Context, key string) string {
	return m.strings[key]
}

func defaultTCPAnalyzerCfg() *TCPAnalyzerConfig {
	return &TCPAnalyzerConfig{
		Enabled:                       true,
		SessionResumptionEnabled:      true,
		MinConnectionsForSessionCheck: 10,
		ShortLifespanEnabled:          true,
		ShortLifespanThresholdMS:      500,
		ConcurrencyEnabled:            true,
		ConcurrencyModerate:           20,
		ConcurrencyHigh:               50,
		ConcurrencySevere:             100,
		ReturnVisitorEnabled:          true,
		ReturnVisitorMinDays:          7,
		ReturnVisitorMinAllowRate:     0.90,
	}
}

func TestTCPAnalyzer_Disabled_NoSignals(t *testing.T) {
	cfg := defaultTCPAnalyzerCfg()
	cfg.Enabled = false
	a := NewTCPAnalyzer(cfg, &mockRedisKV{
		hashes:  map[string]map[string]string{"session:1.2.3.4": {"total": "100", "resumed": "0"}},
		strings: map[string]string{"concurrent:1.2.3.4": "200"},
	}, nil)
	sigs := a.Analyze(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4", ConnectionLifespanMS: 100})
	if len(sigs) != 0 {
		t.Errorf("disabled: expected no signals, got %d", len(sigs))
	}
}

func TestTCPAnalyzer_SessionResumption_LowRate_Signal(t *testing.T) {
	cfg := defaultTCPAnalyzerCfg()
	cfg.ConcurrencyEnabled = false
	cfg.ShortLifespanEnabled = false
	cfg.ReturnVisitorEnabled = false
	a := NewTCPAnalyzer(cfg, &mockRedisKV{
		hashes: map[string]map[string]string{
			"session:1.2.3.4": {"total": "100", "resumed": "0"}, // 0% resumption — fires signal
		},
	}, nil)
	sigs := a.Analyze(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4"})
	if len(sigs) == 0 {
		t.Fatal("expected no_session_resumption signal")
	}
	if sigs[0].Name != "no_session_resumption" {
		t.Errorf("expected 'no_session_resumption', got %q", sigs[0].Name)
	}
}

func TestTCPAnalyzer_SessionResumption_GoodRate_NoSignal(t *testing.T) {
	cfg := defaultTCPAnalyzerCfg()
	cfg.ConcurrencyEnabled = false
	cfg.ShortLifespanEnabled = false
	cfg.ReturnVisitorEnabled = false
	a := NewTCPAnalyzer(cfg, &mockRedisKV{
		hashes: map[string]map[string]string{
			"session:1.2.3.4": {"total": "100", "resumed": "80"}, // 80% resumption — no signal
		},
	}, nil)
	sigs := a.Analyze(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4"})
	if len(sigs) != 0 {
		t.Errorf("good resumption rate: expected no signals, got %d", len(sigs))
	}
}

func TestTCPAnalyzer_ShortLifespan_Signal(t *testing.T) {
	cfg := defaultTCPAnalyzerCfg()
	cfg.SessionResumptionEnabled = false
	cfg.ConcurrencyEnabled = false
	cfg.ReturnVisitorEnabled = false
	a := NewTCPAnalyzer(cfg, &mockRedisKV{}, nil)
	sigs := a.Analyze(context.Background(), &ConnectionContext{
		ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4",
		ConnectionLifespanMS: 100, // below 500ms threshold
	})
	if len(sigs) == 0 {
		t.Fatal("expected short_connection_lifespan signal")
	}
	if sigs[0].Name != "short_connection_lifespan" {
		t.Errorf("expected 'short_connection_lifespan', got %q", sigs[0].Name)
	}
}

func TestTCPAnalyzer_ModerateConcurrency_Signal(t *testing.T) {
	cfg := defaultTCPAnalyzerCfg()
	cfg.SessionResumptionEnabled = false
	cfg.ShortLifespanEnabled = false
	cfg.ReturnVisitorEnabled = false
	a := NewTCPAnalyzer(cfg, &mockRedisKV{
		strings: map[string]string{"concurrent:1.2.3.4": "30"}, // 30 >= moderate(20)
	}, nil)
	sigs := a.Analyze(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4"})
	if len(sigs) == 0 {
		t.Fatal("expected moderate_concurrency signal")
	}
	if sigs[0].Name != "moderate_concurrency" {
		t.Errorf("expected 'moderate_concurrency', got %q", sigs[0].Name)
	}
}

func TestTCPAnalyzer_SevereConcurrency_OnlyHighestFires(t *testing.T) {
	cfg := defaultTCPAnalyzerCfg()
	cfg.SessionResumptionEnabled = false
	cfg.ShortLifespanEnabled = false
	cfg.ReturnVisitorEnabled = false
	a := NewTCPAnalyzer(cfg, &mockRedisKV{
		strings: map[string]string{"concurrent:1.2.3.4": "150"}, // 150 >= severe(100)
	}, nil)
	sigs := a.Analyze(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4"})
	if len(sigs) == 0 {
		t.Fatal("expected severe_concurrency signal")
	}
	// Only the highest tier should fire (else-if logic)
	if len(sigs) != 1 {
		t.Errorf("expected exactly 1 signal (highest tier only), got %d", len(sigs))
	}
	if sigs[0].Name != "severe_concurrency" {
		t.Errorf("expected 'severe_concurrency', got %q", sigs[0].Name)
	}
}

func TestTCPAnalyzer_ReturnVisitor_HighAllowRate_NegativeSignal(t *testing.T) {
	cfg := defaultTCPAnalyzerCfg()
	cfg.SessionResumptionEnabled = false
	cfg.ShortLifespanEnabled = false
	cfg.ConcurrencyEnabled = false

	// first_seen = 30 days ago (well past 7-day minimum)
	firstSeen := time.Now().AddDate(0, 0, -30).Unix()
	a := NewTCPAnalyzer(cfg, &mockRedisKV{
		hashes: map[string]map[string]string{
			"return_visitor:1.2.3.4": {
				"total":      "100",
				"allowed":    "95",
				"first_seen": fmt.Sprintf("%d", firstSeen),
			},
		},
	}, nil)
	sigs := a.Analyze(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4"})
	if len(sigs) == 0 {
		t.Fatal("expected return_visitor_trust signal")
	}
	if sigs[0].Name != "return_visitor_trust" {
		t.Errorf("expected 'return_visitor_trust', got %q", sigs[0].Name)
	}
	if sigs[0].Score >= 0 {
		t.Errorf("expected negative score for trust signal, got %d", sigs[0].Score)
	}
}

func TestTCPAnalyzer_NoRedisData_NoSignal(t *testing.T) {
	// HGetAll returns nil → fail open (no signal)
	cfg := defaultTCPAnalyzerCfg()
	cfg.ShortLifespanEnabled = false
	cfg.ConcurrencyEnabled = false
	a := NewTCPAnalyzer(cfg, &mockRedisKV{
		hashes:  map[string]map[string]string{}, // returns nil for any key
		strings: map[string]string{},
	}, nil)
	sigs := a.Analyze(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4"})
	if len(sigs) != 0 {
		t.Errorf("no redis data: expected no signals, got %d", len(sigs))
	}
}
