package security

import (
	"context"
	"testing"
	"time"

	"github.com/seanpor/ja4proxy/internal/config"
)

// offenseRedis is a RedisReader stub for offense counter tests.
// It supports get/set (via mockRedis) plus atomic Incr and CountKeys.
type offenseRedis struct {
	mockRedis
	incrCalls int
	countResp int // CountKeys always returns this value
}

func (o *offenseRedis) Incr(_ context.Context, key string) (int64, error) {
	o.incrCalls++
	if o.data == nil {
		o.data = make(map[string]string)
	}
	cur := int64(0)
	if v, ok := o.data[key]; ok {
		for _, c := range v {
			cur = cur*10 + int64(c-'0')
		}
	}
	cur++
	o.data[key] = itoa(cur)
	return cur, nil
}

func (o *offenseRedis) Expire(_ context.Context, _ string, _ time.Duration) error { return nil }
func (o *offenseRedis) CountKeys(_ context.Context, _ string) int                 { return o.countResp }

// itoa is a minimal int64→string helper (avoids importing fmt/strconv).
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 20)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}

func defaultCfg() *config.AutoEscalateConfig {
	return &config.AutoEscalateConfig{
		Enabled:               true,
		TarpitAtOffense:       1,
		BlockAtOffense:        3,
		BanAtOffense:          5,
		BanHours:              24,
		OffenseTTLHours:       48,
		SharedIPCIDRThreshold: 0, // disabled in most tests
	}
}

func TestOffenseCounter_IncrementFirst(t *testing.T) {
	r := &offenseRedis{}
	oc := NewOffenseCounter(r, defaultCfg(), nil)
	count, err := oc.Increment(context.Background(), "10.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 1 {
		t.Errorf("first Increment: got %d, want 1", count)
	}
}

func TestOffenseCounter_IncrementMultiple(t *testing.T) {
	r := &offenseRedis{}
	oc := NewOffenseCounter(r, defaultCfg(), nil)
	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		count, err := oc.Increment(ctx, "10.0.0.2")
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if count != i {
			t.Errorf("iteration %d: got %d, want %d", i, count, i)
		}
	}
}

func TestOffenseCounter_EscalatedAction_BelowThreshold(t *testing.T) {
	r := &offenseRedis{}
	oc := NewOffenseCounter(r, defaultCfg(), nil)
	// No increments → count=0 < tarpit_at_offense=1
	action, err := oc.EscalatedAction(context.Background(), "10.0.0.3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if action != "" {
		t.Errorf("want empty action below threshold, got %q", action)
	}
}

func TestOffenseCounter_EscalatedAction_Tarpit(t *testing.T) {
	r := &offenseRedis{}
	oc := NewOffenseCounter(r, defaultCfg(), nil)
	ctx := context.Background()
	oc.Increment(ctx, "10.0.0.4") // count=1
	action, _ := oc.EscalatedAction(ctx, "10.0.0.4")
	if action != "tarpit" {
		t.Errorf("at offense 1 want tarpit, got %q", action)
	}
}

func TestOffenseCounter_EscalatedAction_Block(t *testing.T) {
	r := &offenseRedis{}
	oc := NewOffenseCounter(r, defaultCfg(), nil)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		oc.Increment(ctx, "10.0.0.5")
	} // count=3
	action, _ := oc.EscalatedAction(ctx, "10.0.0.5")
	if action != "block" {
		t.Errorf("at offense 3 want block, got %q", action)
	}
}

func TestOffenseCounter_EscalatedAction_Ban(t *testing.T) {
	r := &offenseRedis{}
	oc := NewOffenseCounter(r, defaultCfg(), nil)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		oc.Increment(ctx, "10.0.0.6")
	} // count=5
	action, _ := oc.EscalatedAction(ctx, "10.0.0.6")
	if action != "ban" {
		t.Errorf("at offense 5 want ban, got %q", action)
	}
}

func TestOffenseCounter_EscalatedAction_Disabled(t *testing.T) {
	r := &offenseRedis{}
	cfg := defaultCfg()
	cfg.Enabled = false
	oc := NewOffenseCounter(r, cfg, nil)
	ctx := context.Background()
	// Even if count is high, disabled config returns ""
	for i := 0; i < 10; i++ {
		oc.Increment(ctx, "10.0.0.7")
	}
	action, _ := oc.EscalatedAction(ctx, "10.0.0.7")
	if action != "" {
		t.Errorf("disabled: want empty action, got %q", action)
	}
}

func TestOffenseCounter_SharedIPThreshold_SkipsIncrement(t *testing.T) {
	r := &offenseRedis{countResp: 15} // exceeds threshold=10
	cfg := defaultCfg()
	cfg.SharedIPCIDRThreshold = 10
	oc := NewOffenseCounter(r, cfg, nil)
	count, err := oc.Increment(context.Background(), "203.0.113.42")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("threshold exceeded: want count=0, got %d", count)
	}
	if r.incrCalls != 0 {
		t.Errorf("Incr should not be called when threshold exceeded, got %d calls", r.incrCalls)
	}
}

func TestOffenseCounter_RedisFail_Increment(t *testing.T) {
	// faultyRedis (from pipeline_chaos_test.go) returns error from Incr.
	// Increment should fail open: return 0, not panic.
	fr := newFaultyRedis(1, 0) // failEvery=1 means always fail
	oc := NewOffenseCounter(fr, defaultCfg(), nil)
	count, err := oc.Increment(context.Background(), "1.2.3.4")
	if count != 0 {
		t.Errorf("Redis error: want count=0, got %d", count)
	}
	_ = err // error is expected and acceptable
}
