package security

import (
	"context"
	"testing"
	"time"

	"github.com/seanpor/ja4proxy/internal/config"
)

// escalationRedis is a RedisReader that reports a non-zero SlidingWindowCount
// (to trigger the rate limiter) and tracks Incr calls.
type escalationRedis struct {
	mockRedis
	slidingCount int // SlidingWindowCount returns this value
	incrCount    int // tracks INCR calls
	banKey       string
	banValue     string
}

func (e *escalationRedis) SlidingWindowCount(_ context.Context, _ string, _ float64, _ int) int {
	return e.slidingCount
}

func (e *escalationRedis) Incr(_ context.Context, key string) (int64, error) {
	e.incrCount++
	if e.data == nil {
		e.data = make(map[string]string)
	}
	cur := int64(0)
	if v, ok := e.data[key]; ok {
		for _, c := range v {
			cur = cur*10 + int64(c-'0')
		}
	}
	cur++
	e.data[key] = itoa(cur)
	return cur, nil
}

func (e *escalationRedis) Expire(_ context.Context, _ string, _ time.Duration) error { return nil }
func (e *escalationRedis) CountKeys(_ context.Context, _ string) int                 { return 0 }

func (e *escalationRedis) SetString(_ context.Context, key, value string, _ int) {
	if e.data == nil {
		e.data = make(map[string]string)
	}
	e.data[key] = value
	if key == e.banKey {
		e.banValue = value
	}
}

func newEscalationPipeline(redis *escalationRedis, offenseEnabled bool, banAt int) *Pipeline {
	cfg := &PipelineConfig{
		ALPNBrowserBypass:   false,
		JA4WhitelistBypass:  false,
		JA4BlockingEnabled:  false,
		MTLSBypass:          false,
		Whitelist:           map[string]bool{},
		Blacklist:           map[string]bool{},
		RateLimiterEnabled:  true,
		RateLimiterByIP: StrategyConfig{
			Enabled:    true,
			Suspicious: 1,
			Block:      2,
			Ban:        3,
			TTL:        60,
		},
		AutoEscalate: config.AutoEscalateConfig{
			Enabled:               offenseEnabled,
			TarpitAtOffense:       1,
			BlockAtOffense:        3,
			BanAtOffense:          banAt,
			BanHours:              24,
			OffenseTTLHours:       48,
			SharedIPCIDRThreshold: 0,
		},
	}
	p := NewPipeline(cfg, redis, nil)
	return p
}

func TestPipelineEscalation_RateLimitedIncrementsCounter(t *testing.T) {
	r := &escalationRedis{slidingCount: 5} // triggers rate limiter
	p := newEscalationPipeline(r, true, 5)
	conn := &ConnectionContext{ClientIP: "10.0.0.1", JA4: "t13d190900"}
	p.processInternal(context.Background(), conn)
	if r.incrCount == 0 {
		t.Error("offense counter should have been incremented on rate-limit signal")
	}
}

func TestPipelineEscalation_AllowedDoesNotIncrement(t *testing.T) {
	r := &escalationRedis{slidingCount: 0} // rate limiter does not fire
	p := newEscalationPipeline(r, true, 5)
	conn := &ConnectionContext{ClientIP: "10.0.0.2", JA4: "t13d190900"}
	p.processInternal(context.Background(), conn)
	if r.incrCount != 0 {
		t.Errorf("offense counter must not increment when rate limiter did not fire, got %d", r.incrCount)
	}
}

func TestPipelineEscalation_DisabledSkipsCounter(t *testing.T) {
	r := &escalationRedis{slidingCount: 5}
	p := newEscalationPipeline(r, false, 5) // offenseEnabled=false
	conn := &ConnectionContext{ClientIP: "10.0.0.3", JA4: "t13d190900"}
	p.processInternal(context.Background(), conn)
	if r.incrCount != 0 {
		t.Errorf("disabled auto-escalate must not call Incr, got %d calls", r.incrCount)
	}
}

func TestPipelineEscalation_BanKeyWritten(t *testing.T) {
	r := &escalationRedis{slidingCount: 5}
	r.banKey = "ban:10.0.0.4"
	// Set ban_at_offense=1 so first offense triggers ban.
	p := newEscalationPipeline(r, true, 1)
	conn := &ConnectionContext{ClientIP: "10.0.0.4", JA4: "t13d190900"}
	result := p.processInternal(context.Background(), conn)
	if result == nil || result.Action != "ban" {
		t.Errorf("expected ban action, got %v", result)
	}
	if r.banValue == "" {
		t.Error("ban:{ip} key must be written in Redis on auto-ban")
	}
}
