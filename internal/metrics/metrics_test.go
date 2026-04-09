package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func descString(c prometheus.Collector) string {
	ch := make(chan *prometheus.Desc, 1)
	c.Describe(ch)
	d := <-ch
	return d.String()
}

func TestMetricNames_ActiveConnections(t *testing.T) {
	if !strings.Contains(descString(ActiveConnections), "ja4proxy_active_connections") {
		t.Errorf("wrong metric name: %s", descString(ActiveConnections))
	}
}

// Phase 63: SLO metrics must exist with the expected names.

func TestMetricNames_ConnectionErrorsTotal(t *testing.T) {
	s := descString(ConnectionErrorsTotal)
	if !strings.Contains(s, "ja4proxy_connection_errors_total") {
		t.Errorf("missing metric name ja4proxy_connection_errors_total: %s", s)
	}
	if !strings.Contains(s, "error_type") {
		t.Errorf("expected error_type label: %s", s)
	}
}

func TestMetricNames_RedisOperationsTotal(t *testing.T) {
	s := descString(RedisOperationsTotal)
	if !strings.Contains(s, "ja4proxy_redis_operations_total") {
		t.Errorf("missing metric name ja4proxy_redis_operations_total: %s", s)
	}
	if !strings.Contains(s, "command") || !strings.Contains(s, "result") {
		t.Errorf("expected command,result labels: %s", s)
	}
}

func TestMetricNames_TLSCertExpiryTimestampSeconds(t *testing.T) {
	s := descString(TLSCertExpiryTimestampSeconds)
	if !strings.Contains(s, "ja4proxy_tls_cert_expiry_timestamp_seconds") {
		t.Errorf("missing metric name ja4proxy_tls_cert_expiry_timestamp_seconds: %s", s)
	}
}

func TestRegister_IncludesPhase63Metrics(t *testing.T) {
	// Use a fresh registry to verify the three Phase 63 metrics can be registered together.
	reg := prometheus.NewRegistry()
	if err := reg.Register(ConnectionErrorsTotal); err != nil {
		// Already registered globally is fine; we just want it to exist
		if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
			t.Errorf("register ConnectionErrorsTotal: %v", err)
		}
	}
	if err := reg.Register(RedisOperationsTotal); err != nil {
		if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
			t.Errorf("register RedisOperationsTotal: %v", err)
		}
	}
	if err := reg.Register(TLSCertExpiryTimestampSeconds); err != nil {
		if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
			t.Errorf("register TLSCertExpiryTimestampSeconds: %v", err)
		}
	}
}
