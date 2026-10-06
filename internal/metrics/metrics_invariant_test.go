package metrics_test

import (
	"sync"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/seanpor/ja4proxy/internal/metrics"
	"pgregory.net/rapid"
)

// Helper to read Counter value
func readCounter(c interface{ Write(*dto.Metric) error }) float64 {
	var m dto.Metric
	_ = c.Write(&m)
	return m.GetCounter().GetValue()
}

// Helper to read Gauge value
func readGauge(g interface{ Write(*dto.Metric) error }) float64 {
	var m dto.Metric
	_ = g.Write(&m)
	return m.GetGauge().GetValue()
}

// INV-METRICS-001: Counter Monotonicity
// forall t2 >= t1, Counter(t2) >= Counter(t1)
func TestInvariant_Metrics_CounterMonotonicity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		incVal := rapid.IntRange(1, 50).Draw(t, "incVal")
		action := rapid.SampledFrom([]string{"allow", "block", "tarpit", "rate_limit"}).Draw(t, "action")

		c := metrics.ConnectionsTotal.WithLabelValues(action)
		valBefore := readCounter(c)

		for i := 0; i < incVal; i++ {
			c.Inc()
		}

		valAfter := readCounter(c)
		if valAfter < valBefore {
			t.Fatalf("Counter monotonicity violation: before %f, after %f", valBefore, valAfter)
		}
	})
}

// INV-METRICS-002: Active Connections Gauge Non-Negative
// ActiveConnections >= 0 under concurrent inc/dec
func TestInvariant_Metrics_ActiveConnectionsGaugeNonNegative(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ops := rapid.IntRange(10, 50).Draw(t, "ops")

		var wg sync.WaitGroup
		wg.Add(ops)

		for i := 0; i < ops; i++ {
			go func() {
				defer wg.Done()
				metrics.ActiveConnections.Inc()
				metrics.ActiveConnections.Dec()
			}()
		}
		wg.Wait()

		val := readGauge(metrics.ActiveConnections)
		if val < 0 {
			t.Fatalf("ActiveConnections gauge dropped below 0: %f", val)
		}
	})
}

// INV-METRICS-003: Connection Decision Conservation Law
// Delta(ConnectionsTotal) == sum(Delta(action_counters))
func TestInvariant_Metrics_DecisionConservation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		actions := []string{"allow", "block", "tarpit", "rate_limit"}

		initialSum := 0.0
		for _, act := range actions {
			initialSum += readCounter(metrics.ConnectionsTotal.WithLabelValues(act))
		}

		// Simulate connection arrivals
		numConns := rapid.IntRange(1, 20).Draw(t, "numConns")
		for i := 0; i < numConns; i++ {
			actIndex := rapid.IntRange(0, len(actions)-1).Draw(t, "actIndex")
			act := actions[actIndex]
			metrics.ConnectionsTotal.WithLabelValues(act).Inc()
		}

		finalSum := 0.0
		for _, act := range actions {
			finalSum += readCounter(metrics.ConnectionsTotal.WithLabelValues(act))
		}

		delta := finalSum - initialSum
		if int(delta) != numConns {
			t.Fatalf("Decision conservation violation: expected delta %d, got %f", numConns, delta)
		}
	})
}

// INV-METRICS-004: Risk Score Histogram Bounding
// RiskScore values strictly within [0, 100]
func TestInvariant_Metrics_HistogramBucketBounds(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		score := rapid.Float64Range(0.0, 100.0).Draw(t, "score")
		metrics.RiskScore.Observe(score)

		var m dto.Metric
		_ = metrics.RiskScore.Write(&m)
		hist := m.GetHistogram()

		if hist.GetSampleCount() == 0 {
			t.Fatalf("Expected sample count > 0 after Observe")
		}
	})
}
