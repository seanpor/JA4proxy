package security

import (
	"context"
	"testing"
)

// mockRedisExists extends mockRedis to return true for specific Exists keys.
type mockRedisExists struct {
	mockRedis
	existsKeys map[string]bool
}

func (m *mockRedisExists) Exists(_ context.Context, key string) bool {
	return m.existsKeys[key]
}

func TestAnalyticsSignals_NeitherKey_NoSignal(t *testing.T) {
	r := &mockRedisExists{existsKeys: map[string]bool{}}
	sigs := GetAnalyticsSignals(context.Background(), r, "1.2.3.4", nil)
	if len(sigs) != 0 {
		t.Errorf("neither key: expected no signals, got %d", len(sigs))
	}
}

func TestAnalyticsSignals_CampaignKey_Signal(t *testing.T) {
	r := &mockRedisExists{existsKeys: map[string]bool{
		"analytics:campaign:1.2.3.0/24": true,
	}}
	sigs := GetAnalyticsSignals(context.Background(), r, "1.2.3.4", nil)
	if len(sigs) == 0 {
		t.Fatal("campaign key: expected signal")
	}
	if sigs[0].Name != "analytics_campaign" {
		t.Errorf("expected 'analytics_campaign', got %q", sigs[0].Name)
	}
}

func TestAnalyticsSignals_SlowscanKey_Signal(t *testing.T) {
	r := &mockRedisExists{existsKeys: map[string]bool{
		"analytics:slowscan:1.2.3.0/24": true,
	}}
	sigs := GetAnalyticsSignals(context.Background(), r, "1.2.3.4", nil)
	if len(sigs) == 0 {
		t.Fatal("slowscan key: expected signal")
	}
	if sigs[0].Name != "analytics_slowscan" {
		t.Errorf("expected 'analytics_slowscan', got %q", sigs[0].Name)
	}
}

func TestAnalyticsSignals_BothKeys_TwoSignals(t *testing.T) {
	r := &mockRedisExists{existsKeys: map[string]bool{
		"analytics:campaign:1.2.3.0/24": true,
		"analytics:slowscan:1.2.3.0/24": true,
	}}
	sigs := GetAnalyticsSignals(context.Background(), r, "1.2.3.4", nil)
	if len(sigs) != 2 {
		t.Errorf("both keys: expected 2 signals, got %d", len(sigs))
	}
}

func TestAnalyticsSignals_RedisDown_EmptyNotPanic(t *testing.T) {
	// mockRedis.Exists returns false (simulating Redis down / fail open)
	r := &mockRedis{}
	sigs := GetAnalyticsSignals(context.Background(), r, "1.2.3.4", nil)
	if len(sigs) != 0 {
		t.Errorf("redis down: expected no signals (fail open), got %d", len(sigs))
	}
}
