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
	}
}

// drop reasons for PacketsDroppedTotal.
const (
	dropDecode      = "decode"       // packet failed Ethernet/IP/TCP decode
	dropNonTCP      = "non_tcp"      // decoded but no TCP layer
	dropCapExceeded = "cap_exceeded" // stream exceeded the per-direction handshake cap
	dropGap         = "gap"          // missing bytes before the handshake; cannot parse
)
