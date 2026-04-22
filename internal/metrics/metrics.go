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
	AbuseIPDBLookupsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_abuseipdb_lookups_total", Help: "AbuseIPDB lookup results"},
		[]string{"result"}, // hit, miss, error
	)
	WeakCipherTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "ja4proxy_weak_cipher_total", Help: "Total weak cipher connections"},
	)
	// phase-203b: JA4 prefix ↔ negotiated TLS version mismatch counter.
	JA4TLSMismatchTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_ja4_tls_mismatch_total", Help: "JA4-claimed TLS version vs negotiated TLS version mismatches"},
		[]string{"action"},
	)
	// phase-203a: TAP-consumed OS mismatch lookup and signal counters.
	TapLookupsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_tap_lookups_total", Help: "Phase-20 TAP fingerprint lookup results"},
		[]string{"result"}, // hit_match, hit_mismatch, miss, error
	)
	TapSignalTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_tap_signal_total", Help: "TAP-derived OS mismatch signals emitted"},
		[]string{"action"},
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
	SyncClockDriftSeconds = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "ja4proxy_sync_clock_drift_seconds", Help: "NTP clock drift in seconds"},
	)
	SyncPeerSkewSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "ja4proxy_sync_peer_skew_seconds", Help: "Clock skew relative to peer DC"},
		[]string{"peer"},
	)
	SyncWANConnected = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "ja4proxy_sync_wan_connected", Help: "WAN connection status to peers (1=connected, 0=disconnected)"},
		[]string{"peer"},
	)
	SyncReplicationLagSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "ja4proxy_sync_replication_lag_seconds", Help: "Cross-DC state replication lag"},
		[]string{"stream"},
	)
	SyncEventsProcessedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_sync_events_processed_total", Help: "Total sync events applied locally"},
		[]string{"op", "dc"},
	)
	SyncErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ja4proxy_sync_errors_total", Help: "Total sync failures"},
		[]string{"type"},
	)

	// ── Phase 63 — SLO metrics ───────────────────────────────────────────
	// ConnectionErrorsTotal counts unhandled errors in the connection handler
	// before a policy decision was reached. Used as the "bad" term of the
	// availability SLI.
	ConnectionErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ja4proxy_connection_errors_total",
			Help: "Unhandled errors in the connection handler before a policy decision",
		},
		// phase-63 review-fix: source-aware error classification.
		// Values: client_read_timeout, client_read_error, backend_dial_timeout,
		// backend_dial_error, backend_refused, redis_timeout, redis_error,
		// connection_refused, oom, timeout, unknown.
		// (TLS parse failures are NOT counted here — see cmd/proxy/main.go.)
		[]string{"error_type"},
	)
	// RedisOperationsTotal counts every Redis call by command and result.
	// Used as both terms of the Redis correctness SLI.
	RedisOperationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ja4proxy_redis_operations_total",
			Help: "Redis operations performed by the proxy",
		},
		[]string{"command", "result"}, // result: ok | error
	)
	// TLSCertExpiryTimestampSeconds is the listener TLS certificate's NotAfter
	// as a Unix timestamp. Set at startup and on config reload. Phase 64 alerts
	// on this gauge (see slo_recording_rules.yml & PHASE_64).
	TLSCertExpiryTimestampSeconds = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ja4proxy_tls_cert_expiry_timestamp_seconds",
			Help: "Listener TLS certificate NotAfter as a Unix timestamp (phase-63)",
		},
	)

	// phase-201c: see docs/runbooks/go_proxy_operations.md
	// Redis client health gauge. Labels: status=ok|error. 1=current, 0=stale.
	// Wired by internal/redis/client.go HealthCheck() and cmd/proxy/main.go ticker.
	RedisHealth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ja4proxy_redis_health",
			Help: "Redis health status (1=current, 0=stale). Labels: status=ok|error.",
		},
		[]string{"status"},
	)
	// phase-201c: see docs/runbooks/go_proxy_operations.md
	// Count of sliding_window.lua reloads after Redis restart/SCRIPT FLUSH.
	// Labels: result=ok|error. Incremented from HealthCheck() when an empty SHA
	// is detected and loadScripts() is re-invoked.
	RedisScriptReloadsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ja4proxy_redis_script_reloads_total",
			Help: "Count of sliding_window.lua reloads after Redis restart/flush. Labels: result=ok|error.",
		},
		[]string{"result"},
	)
	// StreamEventQueueDepth is the current depth of the bounded XADD event
	// queue used to publish connection decisions to Redis Streams.
	// JA4PROXY-2026-0031 — we replaced the previous unbounded
	// `go func() { p.redis.XAdd(context.Background(), ... ) }()` with a
	// bounded channel drained by a fixed worker pool. This gauge lets us
	// alert when Redis is lagging and the queue is filling up.
	StreamEventQueueDepth = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ja4proxy_stream_event_queue_depth",
			Help: "Current depth of the bounded XADD event queue (JA4PROXY-2026-0031).",
		},
	)
	// StreamEventDropsTotal counts events that were dropped because the
	// bounded queue was full. Every drop corresponds to one connection
	// decision whose ECS event did not reach Redis — the connection itself
	// was still handled correctly, this is a telemetry loss metric only.
	StreamEventDropsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ja4proxy_stream_event_drops_total",
			Help: "XADD events dropped because the bounded queue was full (JA4PROXY-2026-0031).",
		},
	)
	// StreamEventWriteErrorsTotal counts XADD calls that failed from the
	// worker pool, labelled by reason. reason=timeout means Redis did not
	// acknowledge within the per-call deadline; reason=error covers every
	// other backend failure.
	StreamEventWriteErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ja4proxy_stream_event_write_errors_total",
			Help: "XADD worker failures by reason (JA4PROXY-2026-0031).",
		},
		[]string{"reason"},
	)
	// PROXY protocol parser events (JA4PROXY-2026-0001, -0002).
	// Labels:
	//   event=spoof_stripped  — header arrived from an untrusted source and was
	//                           stripped so the backend never sees attacker-
	//                           controlled src/dst IPs. (Finding 0001.)
	//   event=smuggling_blocked — a second PROXY header followed the first and
	//                             the connection was closed. (Finding 0002.)
	ProxyProtocolParserEvents = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ja4proxy_proxy_protocol_parser_events_total",
			Help: "PROXY protocol parser security events. Labels: event=spoof_stripped|smuggling_blocked.",
		},
		[]string{"event"},
	)
)

func Register() {
	prometheus.MustRegister(
		ConnectionsTotal, ActiveConnections, RiskScore,
		DialCurrent, DialChangesTotal, SecurityEventsTotal, TarpitConcurrent,
		TarpitOverflowTotal, ConfigReloadsTotal, BypassTotal, SignalTotal,
		AbuseIPDBQueueDroppedTotal, AbuseIPDBLookupsTotal, WeakCipherTotal, WriteBufferQueueDepth,
		WriteBufferDroppedTotal, TorExitListEntries, ASNClassificationTotal,
		PipelineDurationSeconds, BlocklistMatchesTotal, DNSEnrichmentQueueDepth,
		RDAPEnrichmentQueueDepth, AbuseIPDBEnrichmentQueueDepth,
		DNSEnrichmentTotal, DNSPTRErrorsTotal, DNSPTRClassificationTotal,
		DNSResolverErrorsTotal, DNSEnrichmentQueueDropsTotal,
		SNISignalTotal, SNIDGAScore, TCPSignalTotal, SyncClockDriftSeconds,
		SyncPeerSkewSeconds, SyncWANConnected, SyncReplicationLagSeconds,
		SyncEventsProcessedTotal, SyncErrorsTotal,
		// phase-63
		ConnectionErrorsTotal, RedisOperationsTotal, TLSCertExpiryTimestampSeconds,
		// phase-201c
		RedisHealth, RedisScriptReloadsTotal,
		// phase-203a/b
		JA4TLSMismatchTotal, TapLookupsTotal, TapSignalTotal,
		// JA4PROXY-2026-0001/-0002
		ProxyProtocolParserEvents,
		// JA4PROXY-2026-0031
		StreamEventQueueDepth, StreamEventDropsTotal, StreamEventWriteErrorsTotal,
	)
	for _, action := range []string{"allow", "flag", "rate_limit", "tarpit", "block", "ban"} {
		ConnectionsTotal.WithLabelValues(action)
	}
}
