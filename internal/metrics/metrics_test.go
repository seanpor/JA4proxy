package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestMetricNames_ConnectionsTotal(t *testing.T) {
	desc := ConnectionsTotal.WithLabelValues("allow").Desc()
	if !strings.Contains(desc.String(), "ja4proxy_connections_total") {
		t.Errorf("wrong metric name: %s", desc)
	}
}

func TestMetricNames_ActiveConnections(t *testing.T) {
	ch := make(chan *prometheus.Desc, 1)
	ActiveConnections.Describe(ch)
	desc := <-ch
	if !strings.Contains(desc.String(), "ja4proxy_active_connections") {
		t.Errorf("wrong metric name: %s", desc)
	}
}

func TestMetricNames_RiskScoreHistogram(t *testing.T) {
	ch := make(chan *prometheus.Desc, 10)
	RiskScoreHistogram.Describe(ch)
	desc := <-ch
	if !strings.Contains(desc.String(), "ja4proxy_risk_score_distribution") {
		t.Errorf("wrong metric name: %s", desc)
	}
}
