// Package tap implements the passive TAP/SPAN sensor (Phase 316a): it reads
// mirrored packets, reassembles each TCP connection bidirectionally, and emits
// the ClientHello/ServerHello handshake bytes of every TLS flow. It computes no
// fingerprints and writes nothing to Redis — that is Phase 316b onward.
package tap

import "github.com/prometheus/client_golang/prometheus"

// TAP sensor metrics. These live in the tap package rather than internal/metrics
// because the sensor ships as a standalone binary (cmd/ja4-tap, see PHASE_316a
// §3b) with its own registry — the inline proxy must not link the TAP surface.
//
// Names follow ja4proxy_tap_{metric}_{unit}; note the noun-last
// ja4proxy_tap_active_streams gauge, per OBSERVABILITY_STANDARDS.
var (
	PacketsReceivedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ja4proxy_tap_packets_received_total",
		Help: "Packets read from the capture source (live ring or pcap file).",
	})
	PacketsDroppedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ja4proxy_tap_packets_dropped_total",
		Help: "Packets or stream bytes dropped, by reason.",
	}, []string{"reason"})
	ActiveStreams = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ja4proxy_tap_active_streams",
		Help: "TCP connections currently tracked by the reassembler.",
	})
	HandshakesExtractedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ja4proxy_tap_handshakes_extracted_total",
		Help: "TLS handshake messages extracted, by kind (clienthello|serverhello|connection).",
	}, []string{"kind"})
	RingBufferFillRatio = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ja4proxy_tap_ring_buffer_fill_ratio",
		Help: "Live AF_PACKET ring buffer fill ratio (0-1); shedding rule input.",
	})
	WorkerRestartsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ja4proxy_tap_worker_restarts_total",
		Help: "Sensor worker restarts triggered by the watchdog.",
	})
	FingerprintsWrittenTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ja4proxy_tap_fingerprints_written_total",
		Help: "Passive OS fingerprints, by result (written|skipped_unknown|error).",
	}, []string{"result"})
	JA4TWrittenTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ja4proxy_tap_ja4t_written_total",
		Help: "Passive JA4T TCP fingerprints written to fp:ja4t:ip, by result (written|skipped_unknown|error). skipped_unknown counts SYN-less connections (no JA4T) and nil-backend dry runs.",
	}, []string{"result"})
	// EnforcementActionsTotal counts out-of-band enforcement decisions (Phase
	// 316d). The result="error" label supersedes the outline's separate
	// ja4proxy_tap_enforcement_errors_total — one counter, one taxonomy.
	EnforcementActionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ja4proxy_tap_enforcement_actions_total",
		Help: "TAP out-of-band enforcement decisions, by result (skipped|watchlist|banned|operator_override|error). watchlist = advisory fp:ban_intent recorded (default); banned = enforceable ban:{ip} written (armed only); operator_override = an operator-owned ban:{ip} already existed, so the sensor did not overwrite it (D-001); skipped = no blocklist match / empty blocklist / no JA4T / no backend; error = unparsable IP or Redis write failed (fail-open).",
	}, []string{"result"})
	// EnforcementArmed mirrors the high-risk-bypass arming convention: 1 when
	// the sensor will write enforceable ban:{ip} keys, 0 when advisory-only.
	EnforcementArmed = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ja4proxy_tap_enforcement_armed",
		Help: "1 when the sensor is armed to write enforceable ban:{ip} keys (active blocking); 0 when advisory-only (default).",
	})
	// RedisCircuitBreakerOpenedTotal counts how many times the shared
	// Store/Enforcer circuit breaker tripped open after consecutive Redis
	// write failures (R-002). A healthy deployment stays at 0.
	RedisCircuitBreakerOpenedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ja4proxy_tap_redis_circuit_breaker_opened_total",
		Help: "Times the Redis circuit breaker tripped open after consecutive write failures.",
	})
	// RedisCircuitBreakerSkipsTotal counts writes skipped because the
	// breaker was open, rather than attempted and failed.
	RedisCircuitBreakerSkipsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ja4proxy_tap_redis_circuit_breaker_skips_total",
		Help: "Writes skipped (not attempted) because the Redis circuit breaker was open.",
	})
)

// results for EnforcementActionsTotal (Phase 316d).
const (
	enfSkipped          = "skipped"           // no blocklist match / empty blocklist / no JA4T / nil backend
	enfWatchlist        = "watchlist"         // advisory ban intent recorded; nothing blocks (default)
	enfBanned           = "banned"            // ban:{ip} written; inline proxy enforces on next connection (armed)
	enfOperatorOverride = "operator_override" // an operator ban already existed; sensor did not overwrite it (D-001)
	enfError            = "error"             // unparsable IP or Redis write failed; dropped fail-open
)

// results for FingerprintsWrittenTotal (Phase 316b).
const (
	fpWritten        = "written"         // class persisted to fp:os:ip
	fpSkippedUnknown = "skipped_unknown" // classifier returned Unknown; nothing written (conservative)
	fpError          = "error"           // Redis write failed; dropped fail-open
)

// Collectors returns every TAP collector for registration on a registry.
func Collectors() []prometheus.Collector {
	return []prometheus.Collector{
		PacketsReceivedTotal,
		PacketsDroppedTotal,
		ActiveStreams,
		HandshakesExtractedTotal,
		RingBufferFillRatio,
		WorkerRestartsTotal,
		FingerprintsWrittenTotal,
		JA4TWrittenTotal,
		EnforcementActionsTotal,
		EnforcementArmed,
		RedisCircuitBreakerOpenedTotal,
		RedisCircuitBreakerSkipsTotal,
	}
}

// drop reasons for PacketsDroppedTotal.
const (
	dropDecode      = "decode"       // packet failed Ethernet/IP/TCP decode
	dropNonTCP      = "non_tcp"      // decoded but no TCP layer
	dropCapExceeded = "cap_exceeded" // stream exceeded the per-direction handshake cap
	dropGap         = "gap"          // missing bytes before the handshake; cannot parse
)
