package metrics

import (
	"testing"
	"github.com/prometheus/client_golang/prometheus"
)

func TestMetricNames_ActiveConnections(t *testing.T) {
	// Verify that the metric is registered and has the correct FQ name
	m := ActiveConnections
	desc := make(chan *prometheus.Desc, 1)
	m.Describe(desc)
	d := <-desc
	
	// We check the internal representation of the Desc to verify the name
	// This is slightly hacky but effective for ensuring name parity
	if d.String() == "" {
		t.Fatal("metric descriptor is empty")
	}
	
	// Simple string check for the prometheus descriptor
	if !contains(d.String(), "ja4proxy_active_connections") {
		t.Errorf("wrong metric name: %v", d)
	}
}

func contains(s, substr string) bool {
	return (len(s) >= len(substr)) && (s[:len(substr)] == substr || contains(s[1:], substr))
}
