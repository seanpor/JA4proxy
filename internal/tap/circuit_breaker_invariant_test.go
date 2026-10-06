package tap_test

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/seanpor/ja4proxy/internal/tap"
)

type mockRedisSetterGetter struct {
	fail bool
}

func (m *mockRedisSetterGetter) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	if m.fail {
		return errors.New("redis failure")
	}
	return nil
}

func (m *mockRedisSetterGetter) Get(ctx context.Context, key string) (string, error) {
	if m.fail {
		return "", errors.New("redis failure")
	}
	return "ok", nil
}

func TestInvariant_Tap_CircuitBreakerCooldownIsExact(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mock := &mockRedisSetterGetter{fail: true}
		cb := tap.NewRedisCircuitBreaker(mock)
		ctx := context.Background()

		// Trip breaker with 5 consecutive failures
		for i := 0; i < 5; i++ {
			_ = cb.Set(ctx, "k", "v", time.Second)
		}

		// Verify breaker is open
		err := cb.Set(ctx, "k", "v", time.Second)
		if !errors.Is(err, tap.ErrRedisCircuitOpen) {
			t.Fatalf("expected breaker to be open, got %v", err)
		}

		// Advance fake time to 1ns before 10s cooldown expires
		time.Sleep(10*time.Second - time.Nanosecond)
		err = cb.Set(ctx, "k", "v", time.Second)
		if !errors.Is(err, tap.ErrRedisCircuitOpen) {
			t.Fatalf("expected breaker to remain open at cooldown - 1ns, got %v", err)
		}

		// Advance fake time by 1ns to hit exact cooldown boundary
		time.Sleep(time.Nanosecond)
		mock.fail = false // allow probe call to succeed
		err = cb.Set(ctx, "k", "v", time.Second)
		if err != nil {
			t.Fatalf("expected breaker to be closed at exact cooldown boundary, got error: %v", err)
		}
	})
}
