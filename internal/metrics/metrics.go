package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// ConnectionsTotal counts total connections by action.
	ConnectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_connections_total", Help: "Total connections by action"},
		[]string{"action"},
	)
	// ConcurrentConnections is the current number of active connections.
	ConcurrentConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "ja4proxy_concurrent_connections", Help: "Current concurrent connections"},
	)
	// RiskScore tracks the distribution of risk scores.
	// Name follows the standard: histograms end in the base unit, never embed _histogram.
	RiskScore = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "ja4proxy_risk_score",
			Help:    "Risk score distribution",
			Buckets: []float64{0, 10, 20, 35, 55, 70, 85, 100},
		},
	)
	// DialCurrent tracks the current dial setting.
	DialCurrent = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "ja4proxy_dial_current", Help: "Current dial value (0-100)"},
	)
	// SecurityEventsTotal counts security events by type.
	SecurityEventsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_security_events_total", Help: "Security events by type"},
		[]string{"event_type"},
	)
	// TarpitConcurrent tracks current tarpit connections.
	TarpitConcurrent = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "ja4proxy_tarpit_concurrent", Help: "Current tarpit connections"},
	)
	// TarpitOverflowTotal counts tarpit overflows by action.
	TarpitOverflowTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_tarpit_overflow_total", Help: "Tarpit overflows by action"},
		[]string{"action"},
	)
	// ConfigReloadsTotal counts total config reloads.
	ConfigReloadsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "ja4proxy_config_reloads_total", Help: "Total config reloads"},
	)
	// BypassTotal counts bypass checks hit by rule name.
	// Name matches docs/OBSERVABILITY_STANDARDS.md: ja4proxy_bypass_total{bypass}
	BypassTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_bypass_total", Help: "Connections handled by each bypass rule"},
		[]string{"bypass"},
	)
	// SignalTotal counts signal firings by name.
	SignalTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_signal_total", Help: "Signal firings by name"},
		[]string{"signal"},
	)
)

// Register registers all metrics with the default Prometheus registry.
// Safe to call from main() only — panics if called twice.
func Register() {
	prometheus.MustRegister(
		ConnectionsTotal, ConcurrentConnections, RiskScore,
		DialCurrent, SecurityEventsTotal, TarpitConcurrent,
		TarpitOverflowTotal, ConfigReloadsTotal, BypassTotal, SignalTotal,
	)
	// Pre-initialise CounterVec label combinations so they appear in /metrics
	// immediately (Prometheus omits label series that have never been observed).
	for _, action := range []string{"allow", "flag", "rate_limit", "tarpit", "block", "ban"} {
		ConnectionsTotal.WithLabelValues(action)
	}
}
