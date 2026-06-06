package security

import (
	"context"
	"net"
	"testing"
	"time"
)

// mockRedisBeacon extends mockRedis with ZRangeScores injection.
type mockRedisBeacon struct {
	mockRedis
	scores map[string][]float64
	zadded map[string][]float64
}

func (m *mockRedisBeacon) ZRangeScores(_ context.Context, key string, _, _ int64) []float64 {
	return m.scores[key]
}

func (m *mockRedisBeacon) ZAdd(_ context.Context, key string, score float64, _ string) {
	m.zadded[key] = append(m.zadded[key], score)
}

func defaultBeaconingCfg() *BeaconingConfig {
	return &BeaconingConfig{
		Enabled:         true,
		ScoreCap:        35,
		MinObservations: 5,
		ShortWindowSec:  3600,
		LongWindowSec:   86400,
	}
}

// makeTimestamps creates n evenly spaced timestamps ending now, with spacing intervalSec.
func makeTimestamps(n int, intervalSec float64) []float64 {
	now := float64(time.Now().UnixNano()) / 1e9
	ts := make([]float64, n)
	for i := 0; i < n; i++ {
		ts[i] = now - float64(n-1-i)*intervalSec
	}
	return ts
}

// makeJitteredTimestamps creates n timestamps with high randomness (CV > 0.7).
func makeJitteredTimestamps(n int) []float64 {
	now := float64(time.Now().UnixNano()) / 1e9
	ts := make([]float64, n)
	spacings := []float64{100, 1, 200, 2, 300, 3, 400, 4, 500}
	offset := 0.0
	for i := 0; i < n; i++ {
		ts[i] = now - 3600 + offset
		if i < len(spacings) {
			offset += spacings[i]
		} else {
			offset += 50
		}
	}
	return ts
}

func TestBeaconing_Disabled_NoSignal(t *testing.T) {
	cfg := defaultBeaconingCfg()
	cfg.Enabled = false
	d := NewBeaconingDetector(cfg, &mockRedisBeacon{scores: map[string][]float64{
		"beacon:1.2.3.4:t13d1234": makeTimestamps(20, 60),
	}, zadded: map[string][]float64{}}, nil)
	sig := d.GetSignal(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4", JA4: "t13d1234"})
	if sig != nil {
		t.Errorf("disabled: expected nil, got %v", sig)
	}
}

func TestBeaconing_BrowserALPN_NoSignal(t *testing.T) {
	d := NewBeaconingDetector(defaultBeaconingCfg(), &mockRedisBeacon{
		scores: map[string][]float64{
			"beacon:1.2.3.4:t13d1234": makeTimestamps(20, 60),
		},
		zadded: map[string][]float64{},
	}, nil)
	for _, alpn := range []string{"h2", "h1"} {
		sig := d.GetSignal(context.Background(), &ConnectionContext{
			ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4", JA4: "t13d1234", ALPN: alpn,
		})
		if sig != nil {
			t.Errorf("ALPN=%q: expected nil, got %v", alpn, sig)
		}
	}
}

func TestBeaconing_NotEnoughObservations_NoSignal(t *testing.T) {
	// Only 3 observations, MinObservations=5
	d := NewBeaconingDetector(defaultBeaconingCfg(), &mockRedisBeacon{
		scores: map[string][]float64{
			"beacon:1.2.3.4:t13d1234": makeTimestamps(3, 60),
		},
		zadded: map[string][]float64{},
	}, nil)
	sig := d.GetSignal(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4", JA4: "t13d1234"})
	if sig != nil {
		t.Errorf("not enough observations: expected nil, got %v", sig)
	}
}

func TestBeaconing_RegularPattern_HighScore(t *testing.T) {
	// Very regular 60-second beaconing (CV near 0) → high score
	d := NewBeaconingDetector(defaultBeaconingCfg(), &mockRedisBeacon{
		scores: map[string][]float64{
			"beacon:1.2.3.4:t13d1234": makeTimestamps(20, 60),
		},
		zadded: map[string][]float64{},
	}, nil)
	sig := d.GetSignal(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4", JA4: "t13d1234"})
	if sig == nil {
		t.Fatal("regular beaconing: expected signal")
	}
	if sig.Name != "beaconing" {
		t.Errorf("expected 'beaconing', got %q", sig.Name)
	}
	if sig.Score <= 0 {
		t.Errorf("expected positive score, got %d", sig.Score)
	}
}

func TestBeaconing_HighVariance_NoSignal(t *testing.T) {
	// High jitter (CV > 0.7) → no signal
	d := NewBeaconingDetector(defaultBeaconingCfg(), &mockRedisBeacon{
		scores: map[string][]float64{
			"beacon:1.2.3.4:t13d1234": makeJitteredTimestamps(10),
		},
		zadded: map[string][]float64{},
	}, nil)
	sig := d.GetSignal(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4", JA4: "t13d1234"})
	if sig != nil {
		t.Errorf("high variance: expected nil, got %v (CV might not be >0.7)", sig)
	}
}

func TestBeaconing_MaybeRecord_BlockSkipped(t *testing.T) {
	mock := &mockRedisBeacon{scores: map[string][]float64{}, zadded: map[string][]float64{}}
	d := NewBeaconingDetector(defaultBeaconingCfg(), mock, nil)
	d.MaybeRecord(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4", JA4: "t13d1234"}, "block")
	if len(mock.zadded) != 0 {
		t.Error("block action: MaybeRecord should not record")
	}
}

func TestBeaconing_MaybeRecord_AllowRecords(t *testing.T) {
	mock := &mockRedisBeacon{scores: map[string][]float64{}, zadded: map[string][]float64{}}
	d := NewBeaconingDetector(defaultBeaconingCfg(), mock, nil)
	d.MaybeRecord(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4", JA4: "t13d1234"}, "allow")
	key := "beacon:1.2.3.4:t13d1234"
	if len(mock.zadded[key]) == 0 {
		t.Error("allow action: MaybeRecord should record timestamp")
	}
}

func TestBeaconing_EmptyJA4_NoSignal(t *testing.T) {
	d := NewBeaconingDetector(defaultBeaconingCfg(), &mockRedisBeacon{
		scores: map[string][]float64{},
		zadded: map[string][]float64{},
	}, nil)
	sig := d.GetSignal(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4", JA4: ""})
	if sig != nil {
		t.Errorf("empty JA4: expected nil, got %v", sig)
	}
}

func TestComputeCV_PerfectRegular(t *testing.T) {
	// Regular 1-second intervals → CV should be ~0
	ts := makeTimestamps(10, 1.0)
	cv := computeCV(ts)
	if cv > 0.01 {
		t.Errorf("perfect regular: CV = %.4f, want ~0", cv)
	}
}

func (*mockRedisBeacon) MultiCheck(_ context.Context, _ string) (int, bool, bool) { return 0, false, false }
