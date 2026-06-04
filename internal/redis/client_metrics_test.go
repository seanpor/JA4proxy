package redis

import (
	"context"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/seanpor/ja4proxy/internal/metrics"
)

// directCounter reads a single counter cell directly from RedisOperationsTotal.
func directCounter(t *testing.T, command, result string) float64 {
	t.Helper()
	c, err := metrics.RedisOperationsTotal.GetMetricWithLabelValues(command, result)
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues: %v", err)
	}
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return m.Counter.GetValue()
}

// TestRedisOps_GetSuccess verifies that a successful Redis Get increments
// ja4proxy_redis_operations_total{command="get",result="ok"}.
func TestRedisOps_GetSuccess(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	ctx := context.Background()
	c.Set(ctx, "k_phase63_ok", "v", 0)

	before := directCounter(t, "get", "ok")
	if _, err := c.Get(ctx, "k_phase63_ok"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	after := directCounter(t, "get", "ok")

	if after <= before {
		t.Errorf("expected get/ok counter to increment: before=%v after=%v", before, after)
	}
}

// TestRedisOps_GetError verifies that a Redis Get against a closed server
// increments ja4proxy_redis_operations_total{command="get",result="error"}.
func TestRedisOps_GetError(t *testing.T) {
	c, mr := newTestClient(t)
	mr.Close() // immediate shutdown so subsequent ops fail

	ctx := context.Background()

	before := directCounter(t, "get", "error")
	_, _ = c.Get(ctx, "k_phase63_err") // fail-open returns nil err
	after := directCounter(t, "get", "error")

	if after <= before {
		t.Errorf("expected get/error counter to increment: before=%v after=%v", before, after)
	}
}

// TestRedisOps_SetSuccess verifies a Set increments command="set", result="ok".
func TestRedisOps_SetSuccess(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	before := directCounter(t, "set", "ok")
	c.Set(context.Background(), "phase63_set", "v", 0)
	after := directCounter(t, "set", "ok")
	if after <= before {
		t.Errorf("expected set/ok counter to increment: before=%v after=%v", before, after)
	}
}
