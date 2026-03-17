package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// ConnectionsTotal counts total connections by action.
	ConnectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_connections_total", Help: "Total connections by action"},
		[]string{"action"},
	)
	// ActiveConnections is the current number of active connections.
	ActiveConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "ja4proxy_active_connections", Help: "Current active connections"},
	)
	// RiskScoreHistogram tracks the distribution of risk scores.
	RiskScoreHistogram = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "ja4proxy_risk_score_distribution",
			Help:    "Distribution of risk scores",
			Buckets: []float64{0, 10, 20, 35, 55, 70, 85, 100},
		},
	)
	// DialSetting tracks the current dial setting.
	DialSetting = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "ja4proxy_dial_setting", Help: "Current dial setting (0-100)"},
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
	// BypassHitsTotal counts bypass checks hit by reason.
	BypassHitsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_bypass_hits_total", Help: "Bypass checks hit"},
		[]string{"reason"},
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
		ConnectionsTotal, ActiveConnections, RiskScoreHistogram,
		DialSetting, SecurityEventsTotal, TarpitConcurrent,
		TarpitOverflowTotal, ConfigReloadsTotal, BypassHitsTotal, SignalTotal,
	)
}
