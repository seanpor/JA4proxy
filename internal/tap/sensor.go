package tap

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"
)

// PacketSource yields raw frames. Both the offline pcap reader and the live
// AF_PACKET handle satisfy it (it matches gopacket.PacketDataSource).
type PacketSource interface {
	ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error)
}

// idleFlushInterval bounds how long a half-open or never-completed connection
// lingers before being flushed and (if a ClientHello was seen) emitted.
const idleFlushInterval = 30 * time.Second

// Sensor reassembles mirrored TCP traffic and emits a HandshakeEvent per TLS
// connection. It is single-goroutine: ProcessPacket and Flush must be called
// from the same goroutine (Run does this).
type Sensor struct {
	decoder *decoder
	pool    *reassembly.StreamPool
	asm     *reassembly.Assembler
	events  chan HandshakeEvent
}

// NewSensor builds a sensor for the given capture link type. eventBuffer sizes
// the emit channel; when full, events are dropped (fail-open — the sensor never
// blocks the capture path).
func NewSensor(linkType layers.LinkType, eventBuffer int) *Sensor {
	s := &Sensor{
		events: make(chan HandshakeEvent, eventBuffer),
	}
	factory := &streamFactory{emit: s.deliver}
	s.pool = reassembly.NewStreamPool(factory)
	s.asm = reassembly.NewAssembler(s.pool)
	s.asm.MaxBufferedPagesTotal = maxBufferedPagesTotal
	s.asm.MaxBufferedPagesPerConnection = maxBufferedPagesPerConn
	s.decoder = newDecoder(linkType)
	return s
}

// Events returns the channel of emitted handshakes.
func (s *Sensor) Events() <-chan HandshakeEvent { return s.events }

func (s *Sensor) deliver(e HandshakeEvent) {
	select {
	case s.events <- e:
	default:
		// Downstream is slower than capture — drop rather than stall the sensor.
		PacketsDroppedTotal.WithLabelValues("event_overflow").Inc()
	}
}

// ProcessPacket decodes one frame and feeds it to the reassembler.
func (s *Sensor) ProcessPacket(data []byte, ci gopacket.CaptureInfo) {
	PacketsReceivedTotal.Inc()
	netFlow, tcp, ttl, ok := s.decoder.decode(data)
	if !ok {
		PacketsDroppedTotal.WithLabelValues(dropNonTCP).Inc()
		return
	}
	s.asm.AssembleWithContext(netFlow, tcp, &assemblerCtx{ci: ci, ttl: ttl})
}

// Flush closes and emits all in-flight connections (call at shutdown / EOF).
func (s *Sensor) Flush() { s.asm.FlushAll() }

// Run pumps packets from src until the source reports EOF, ctx is cancelled, or
// a non-recoverable read error occurs. It closes the events channel on return.
func (s *Sensor) Run(ctx context.Context, src PacketSource) error {
	defer close(s.events)
	lastFlush := time.Time{}
	for {
		select {
		case <-ctx.Done():
			s.Flush()
			return ctx.Err()
		default:
		}

		data, ci, err := src.ReadPacketData()
		switch {
		case err == nil:
			s.ProcessPacket(data, ci)
			if !ci.Timestamp.IsZero() {
				if lastFlush.IsZero() {
					lastFlush = ci.Timestamp
				} else if ci.Timestamp.Sub(lastFlush) >= idleFlushInterval {
					s.asm.FlushCloseOlderThan(ci.Timestamp.Add(-idleFlushInterval))
					lastFlush = ci.Timestamp
				}
			}
		case errors.Is(err, io.EOF):
			s.Flush()
			return nil
		default:
			// Transient read errors (e.g. live poll timeouts) are non-fatal.
			continue
		}
	}
}

// assemblerCtx carries per-packet info the reassembler callbacks need. The TTL
// is included because reassembly never exposes the IP layer, yet the SYN's TTL
// is a primary passive-OS-fingerprint feature (316b).
type assemblerCtx struct {
	ci  gopacket.CaptureInfo
	ttl uint8
}

func (c *assemblerCtx) GetCaptureInfo() gopacket.CaptureInfo { return c.ci }
