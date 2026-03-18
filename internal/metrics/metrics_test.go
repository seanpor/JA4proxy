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

func TestMetricNames_ConcurrentConnections(t *testing.T) {
	ch := make(chan *prometheus.Desc, 1)
	ConcurrentConnections.Describe(ch)
	desc := <-ch
	if !strings.Contains(desc.String(), "ja4proxy_concurrent_connections") {
		t.Errorf("wrong metric name: %s", desc)
	}
}

func TestMetricNames_RiskScore(t *testing.T) {
	ch := make(chan *prometheus.Desc, 10)
	RiskScore.Describe(ch)
	desc := <-ch
	if !strings.Contains(desc.String(), "ja4proxy_risk_score") {
		t.Errorf("wrong metric name: %s", desc)
	}
}
