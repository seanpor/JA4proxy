package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	ConnectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_connections_total", Help: "Total connections by action"},
		[]string{"action"},
	)
	ActiveConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "ja4proxy_active_connections", Help: "Current active connections"},
	)
	RiskScore = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "ja4proxy_risk_score",
			Help:    "Risk score distribution (0-100)",
			Buckets: []float64{0, 10, 25, 40, 55, 70, 85, 100},
		},
	)
	DialCurrent = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "ja4proxy_dial_current", Help: "Current dial value (0-100)"},
	)
	DialChangesTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "ja4proxy_dial_changes_total", Help: "Total dial setting changes"},
	)
	SecurityEventsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_security_events_total", Help: "Security events by type"},
		[]string{"type"},
	)
	TarpitConcurrent = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "ja4proxy_tarpit_concurrent", Help: "Current tarpit connections"},
	)
	TarpitOverflowTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_tarpit_overflow_total", Help: "Tarpit overflows by action"},
		[]string{"action"},
	)
	ConfigReloadsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "ja4proxy_config_reloads_total", Help: "Total config reloads"},
	)
	BypassTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_bypass_total", Help: "Connections handled by each bypass rule"},
		[]string{"rule"},
	)
	SignalTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_signal_total", Help: "Signal firings by name"},
		[]string{"name"},
	)
	AbuseIPDBQueueDroppedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "ja4proxy_abuseipdb_queue_dropped_total", Help: "Dropped AbuseIPDB requests"},
	)
	WeakCipherTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "ja4proxy_weak_cipher_total", Help: "Total weak cipher connections"},
	)
	WriteBufferQueueDepth = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "ja4proxy_write_buffer_queue_depth", Help: "Current event buffer depth"},
	)
	WriteBufferDroppedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "ja4proxy_write_buffer_dropped_total", Help: "Total dropped events"},
	)
	TorExitListEntries = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "ja4proxy_tor_exit_list_entries", Help: "Current Tor exit list size"},
	)
	ASNClassificationTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_asn_classification_total", Help: "ASN classification events"},
		[]string{"type"},
	)
	PipelineDurationSeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "ja4proxy_pipeline_duration_seconds",
			Help:    "Pipeline processing time in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)
	BlocklistMatchesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_blocklist_matches_total", Help: "Blocklist match counts"},
		[]string{"list"},
	)
	DNSEnrichmentQueueDepth = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "ja4proxy_dns_enrichment_queue_depth", Help: "DNS enrichment queue depth"},
	)
	RDAPEnrichmentQueueDepth = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "ja4proxy_rdap_enrichment_queue_depth", Help: "RDAP enrichment queue depth"},
	)
	AbuseIPDBEnrichmentQueueDepth = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "ja4proxy_abuseipdb_enrichment_queue_depth", Help: "AbuseIPDB queue depth"},
	)
	DNSEnrichmentTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_dns_enrichment_total", Help: "DNS enrichment results"},
		[]string{"result"},
	)
	DNSPTRErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_dns_ptr_errors_total", Help: "DNS PTR lookup errors"},
		[]string{"error"},
	)
	DNSPTRClassificationTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_dns_ptr_classification_total", Help: "DNS PTR classifications"},
		[]string{"type"},
	)
	DNSResolverErrorsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "ja4proxy_dns_resolver_errors_total", Help: "DNS resolver errors"},
	)
	DNSEnrichmentQueueDropsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "ja4proxy_dns_enrichment_queue_drops_total", Help: "Dropped DNS enrichment requests"},
	)
	SNISignalTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_sni_signal_total", Help: "SNI signal events"},
		[]string{"signal"},
	)
	SNIDGAScore = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "ja4proxy_sni_dga_score",
			Help:    "SNI DGA score distribution",
			Buckets: []float64{0.1, 0.25, 0.5, 0.75, 0.9, 1.0},
		},
	)
	TCPSignalTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_tcp_signal_total", Help: "TCP signal events"},
		[]string{"signal"},
	)
)

func Register() {
	prometheus.MustRegister(
		ConnectionsTotal, ActiveConnections, RiskScore,
		DialCurrent, DialChangesTotal, SecurityEventsTotal, TarpitConcurrent,
		TarpitOverflowTotal, ConfigReloadsTotal, BypassTotal, SignalTotal,
		AbuseIPDBQueueDroppedTotal, WeakCipherTotal, WriteBufferQueueDepth,
		WriteBufferDroppedTotal, TorExitListEntries, ASNClassificationTotal,
		PipelineDurationSeconds, BlocklistMatchesTotal, DNSEnrichmentQueueDepth,
		RDAPEnrichmentQueueDepth, AbuseIPDBEnrichmentQueueDepth,
		DNSEnrichmentTotal, DNSPTRErrorsTotal, DNSPTRClassificationTotal,
		DNSResolverErrorsTotal, DNSEnrichmentQueueDropsTotal,
		SNISignalTotal, SNIDGAScore, TCPSignalTotal,
	)
	for _, action := range []string{"allow", "flag", "rate_limit", "tarpit", "block", "ban"} {
		ConnectionsTotal.WithLabelValues(action)
	}
}
