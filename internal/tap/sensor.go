package tap

import (
	"context"
	"errors"
	"fmt"
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

// ErrPollTimeout is returned by a PacketSource to signal a benign, expected
// read timeout (e.g. an idle live-capture interface polled with no traffic —
// see capture_linux.go's afpacket.OptPollTimeout wiring for R-001) rather than
// a genuine error. Run does not apply backoff or count these toward the
// persistent-error threshold (F-014); it is a plain package-level sentinel,
// not an afpacket type, so this platform-independent file never needs to
// import the Linux-only afpacket package.
var ErrPollTimeout = errors.New("tap: packet source poll timeout")

// idleFlushInterval bounds how long a half-open or never-completed connection
// lingers before being flushed and (if a ClientHello was seen) emitted.
const idleFlushInterval = 30 * time.Second

// Backoff/threshold tuning for the genuine-read-error path (F-014). Package-
// level vars, not consts, so tests can shrink them and exercise the
// threshold-exceeded path without a real multi-second wait.
var (
	// readErrorBackoffBase is the initial backoff delay after a genuine
	// (non-timeout) PacketSource read error.
	readErrorBackoffBase = 10 * time.Millisecond
	// readErrorBackoffCap bounds the exponential backoff so a persistent
	// error never waits longer than this between retries.
	readErrorBackoffCap = time.Second
	// maxConsecutiveReadErrors is the number of consecutive genuine read
	// errors Run tolerates before giving up and returning an error. The
	// caller's Watchdog (watchdog.go) restarts the sensor with a fresh
	// source on a non-nil Run error, so this composes with the existing
	// crash-loop protection rather than needing its own.
	maxConsecutiveReadErrors = 20
)

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

// LinkType returns the capture link type this sensor was built for.
func (s *Sensor) LinkType() layers.LinkType { return s.decoder.linkType }

func (s *Sensor) deliver(e HandshakeEvent) {
	select {
	case s.events <- e:
	default:
		// Downstream is slower than capture — drop rather than stall the sensor.
		PacketsDroppedTotal.WithLabelValues(dropEventOverflow).Inc()
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
	var consecutiveErrors int
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
			consecutiveErrors = 0
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
		case errors.Is(err, ErrPollTimeout):
			// Benign, expected on an idle live interface (R-001) -- not a
			// failure. Reset the error counter and loop back to re-check
			// ctx.Done() without backing off.
			consecutiveErrors = 0
		default:
			// Genuine, persistent read error (F-014). Previously this was
			// treated identically to a benign poll timeout -- a busyloop
			// with no backoff and no upper bound. Back off exponentially
			// (capped) and fail safe past a threshold instead: the caller's
			// Watchdog restarts the sensor with a fresh source on a non-nil
			// Run error, composing with its existing crash-loop protection.
			consecutiveErrors++
			PacketsDroppedTotal.WithLabelValues(dropReadError).Inc()
			if consecutiveErrors >= maxConsecutiveReadErrors {
				s.Flush()
				return fmt.Errorf("tap: %d consecutive read errors, last: %w", consecutiveErrors, err)
			}
			// Doubling via a bounded loop rather than a bit-shift-then-convert
			// avoids a gosec G115 (potential int64 overflow) finding entirely;
			// the loop always terminates in <=~7 iterations in practice since
			// it stops as soon as backoff reaches the cap.
			backoff := readErrorBackoffBase
			for i := 1; i < consecutiveErrors && backoff < readErrorBackoffCap; i++ {
				backoff *= 2
			}
			if backoff > readErrorBackoffCap {
				backoff = readErrorBackoffCap
			}
			select {
			case <-ctx.Done():
				s.Flush()
				return ctx.Err()
			case <-time.After(backoff):
			}
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
