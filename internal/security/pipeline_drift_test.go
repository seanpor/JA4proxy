package security

import (
	"context"
	"testing"
	// "time"
	// "net"

	"github.com/anomalyco/ja4proxy/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestAuditDecision_DetectsDrift(t *testing.T) {
	mr := &mockRedis{
		data: map[string]string{
			"audit:last_score:1.2.3.4": "30",
		},
	}
	p := NewPipeline(&PipelineConfig{}, mr, nil)

	metricBefore := testutil.ToFloat64(metrics.SignalDriftTotal.WithLabelValues("mesh", "score_divergence"))

	// Current score 60 vs last score 30 = diff 30 (> 20 threshold)
	p.auditDecision(context.Background(), "1.2.3.4", 60)

	metricAfter := testutil.ToFloat64(metrics.SignalDriftTotal.WithLabelValues("mesh", "score_divergence"))
	if metricAfter <= metricBefore {
		t.Errorf("drift not detected: metric did not increment (before: %f, after: %f)", metricBefore, metricAfter)
	}

	// Verify update
	val := mr.GetString(context.Background(), "audit:last_score:1.2.3.4")
	if val != "60" {
		t.Errorf("last_score not updated in Redis: got %q, want %q", val, "60")
	}
}

func TestAuditDecision_NoDriftBelowThreshold(t *testing.T) {
	mr := &mockRedis{
		data: map[string]string{
			"audit:last_score:1.2.3.4": "30",
		},
	}
	p := NewPipeline(&PipelineConfig{}, mr, nil)

	metricBefore := testutil.ToFloat64(metrics.SignalDriftTotal.WithLabelValues("mesh", "score_divergence"))

	// Current score 40 vs last score 30 = diff 10 (<= 20 threshold)
	p.auditDecision(context.Background(), "1.2.3.4", 40)

	metricAfter := testutil.ToFloat64(metrics.SignalDriftTotal.WithLabelValues("mesh", "score_divergence"))
	if metricAfter != metricBefore {
		t.Errorf("unexpected drift detection: metric incremented for small diff")
	}
}
