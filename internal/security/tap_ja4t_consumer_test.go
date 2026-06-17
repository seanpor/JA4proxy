package security

import (
	"context"
	"errors"
	"testing"
	"time"
)

const blocklistedJA4T = "64240_2-1-3-1-1-4_1460_8"

func ja4tConfig() *JA4TConsumerConfig {
	return &JA4TConsumerConfig{
		Enabled:      true,
		SignalScore:  30,
		RedisTimeout: 200 * time.Millisecond,
		CacheTTL:     time.Second,
		Blocklist:    map[string]bool{blocklistedJA4T: true},
	}
}

func TestJA4TConsumer_BlocklistedFires(t *testing.T) {
	r := &fakeRedis{values: map[string]string{"fp:ja4t:ip:203.0.113.9": blocklistedJA4T}}
	c := NewJA4TConsumer(ja4tConfig(), r, nil)

	sig := c.GetSignal(context.Background(), "203.0.113.9")
	if sig == nil {
		t.Fatal("expected tap_ja4t_blocklist signal; got nil")
	}
	if sig.Name != "tap_ja4t_blocklist" {
		t.Errorf("Name = %q; want tap_ja4t_blocklist", sig.Name)
	}
	if sig.Score != 30 {
		t.Errorf("Score = %d; want 30", sig.Score)
	}
	if sig.Weight != 1.0 {
		t.Errorf("Weight = %v; want 1.0", sig.Weight)
	}
}

func TestJA4TConsumer_CleanJA4TNoSignal(t *testing.T) {
	r := &fakeRedis{values: map[string]string{"fp:ja4t:ip:203.0.113.9": "29200_2-4-8-1-3_1460_7"}}
	c := NewJA4TConsumer(ja4tConfig(), r, nil)
	if sig := c.GetSignal(context.Background(), "203.0.113.9"); sig != nil {
		t.Errorf("a JA4T not on the blocklist must not fire; got %+v", sig)
	}
}

func TestJA4TConsumer_MissNoSignal(t *testing.T) {
	r := &fakeRedis{values: map[string]string{}}
	c := NewJA4TConsumer(ja4tConfig(), r, nil)
	if sig := c.GetSignal(context.Background(), "203.0.113.9"); sig != nil {
		t.Errorf("a Redis miss must not fire; got %+v", sig)
	}
}

func TestJA4TConsumer_DisabledFailsOpen(t *testing.T) {
	cfg := ja4tConfig()
	cfg.Enabled = false
	r := &fakeRedis{values: map[string]string{"fp:ja4t:ip:203.0.113.9": blocklistedJA4T}}
	c := NewJA4TConsumer(cfg, r, nil)
	if sig := c.GetSignal(context.Background(), "203.0.113.9"); sig != nil {
		t.Errorf("disabled consumer must not fire; got %+v", sig)
	}
}

func TestJA4TConsumer_EmptyBlocklistNeverLooksUp(t *testing.T) {
	cfg := ja4tConfig()
	cfg.Blocklist = nil
	r := &fakeRedis{values: map[string]string{"fp:ja4t:ip:203.0.113.9": blocklistedJA4T}}
	c := NewJA4TConsumer(cfg, r, nil)
	if sig := c.GetSignal(context.Background(), "203.0.113.9"); sig != nil {
		t.Errorf("empty blocklist must never fire; got %+v", sig)
	}
	if got := r.getCalls; got != 0 {
		t.Errorf("empty blocklist must short-circuit before Redis; got %d Get calls", got)
	}
}

func TestJA4TConsumer_RedisErrorFailsOpen(t *testing.T) {
	r := &fakeRedis{err: errors.New("redis down")}
	c := NewJA4TConsumer(ja4tConfig(), r, nil)
	if sig := c.GetSignal(context.Background(), "203.0.113.9"); sig != nil {
		t.Errorf("Redis error must fail open (no signal); got %+v", sig)
	}
}

func TestJA4TConsumer_TimeoutFailsOpen(t *testing.T) {
	cfg := ja4tConfig()
	cfg.RedisTimeout = 10 * time.Millisecond
	r := &fakeRedis{
		values: map[string]string{"fp:ja4t:ip:203.0.113.9": blocklistedJA4T},
		delay:  200 * time.Millisecond,
	}
	c := NewJA4TConsumer(cfg, r, nil)
	if sig := c.GetSignal(context.Background(), "203.0.113.9"); sig != nil {
		t.Errorf("a slow Redis must fail open within the timeout; got %+v", sig)
	}
}

func TestJA4TConsumer_UnparsableIPNoSignal(t *testing.T) {
	r := &fakeRedis{values: map[string]string{}}
	c := NewJA4TConsumer(ja4tConfig(), r, nil)
	if sig := c.GetSignal(context.Background(), "not-an-ip"); sig != nil {
		t.Errorf("unparsable IP must fail open; got %+v", sig)
	}
}

func TestJA4TConsumer_CanonicalisesIPv6(t *testing.T) {
	// Sensor wrote the canonical form; a consumer lookup with a non-canonical
	// spelling of the same address must still hit.
	r := &fakeRedis{values: map[string]string{"fp:ja4t:ip:2001:db8::1": blocklistedJA4T}}
	c := NewJA4TConsumer(ja4tConfig(), r, nil)
	if sig := c.GetSignal(context.Background(), "2001:DB8:0:0::1"); sig == nil {
		t.Error("expected hit after IPv6 canonicalisation; got nil")
	}
}

func TestJA4TConsumer_CachesLookup(t *testing.T) {
	r := &fakeRedis{values: map[string]string{"fp:ja4t:ip:203.0.113.9": blocklistedJA4T}}
	c := NewJA4TConsumer(ja4tConfig(), r, nil)
	for i := 0; i < 5; i++ {
		c.GetSignal(context.Background(), "203.0.113.9")
	}
	if r.getCalls != 1 {
		t.Errorf("expected 1 Redis Get (rest served from cache); got %d", r.getCalls)
	}
}

func TestJA4TConsumer_NilSafe(t *testing.T) {
	var c *JA4TConsumer
	if sig := c.GetSignal(context.Background(), "203.0.113.9"); sig != nil {
		t.Errorf("nil consumer must return nil; got %+v", sig)
	}
}
