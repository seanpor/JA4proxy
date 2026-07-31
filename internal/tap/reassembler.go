package tap

import (
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"
	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

// Global reassembly memory ceiling (PHASE_316a §5). These bound the page cache
// shared across all tracked connections, on top of the per-direction
// maxHandshakeBytes cap each stream enforces itself. A page is ~1900 bytes;
// 4096 pages ≈ 8 MB, ample for handshake-only buffering and a hard stop against
// a SPAN-port flood turning the sensor into an OOM.
//
// maxBufferedPagesPerConn is a security control, not a tuning knob (F-026):
// gopacket's reassembly.Assembler.MaxBufferedPagesPerConnection defaults much
// higher, and reassembler.go's maybeEmit path calls sg.Fetch(length) with
// length taken directly from gopacket's own accounting of buffered bytes for
// that connection — i.e. an attacker-influenced allocation size bounded only
// by this constant. Raising it (e.g. to accommodate a larger handshake)
// directly raises the per-connection Fetch allocation ceiling; see
// TestMaxBufferedPagesPerConnStaysLow, which pins the current value so a
// change here doesn't pass silently.
const (
	maxBufferedPagesTotal   = 4096
	maxBufferedPagesPerConn = 8
)

type emitFunc func(HandshakeEvent)

// streamFactory builds one tlsStream per TCP connection. reassembly invokes
// New once per bidirectional connection; the resulting Stream receives both
// directions, tagged via ScatterGather.Info().
type streamFactory struct {
	emit emitFunc
}

func (f *streamFactory) New(netFlow, tcpFlow gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	ActiveStreams.Inc()
	return &tlsStream{
		emit:       f.emit,
		clientIP:   netFlow.Src().String(),
		serverIP:   netFlow.Dst().String(),
		clientPort: uint16(tcp.SrcPort),
		serverPort: uint16(tcp.DstPort),
		firstSeen:  ac.GetCaptureInfo().Timestamp,
		stack:      synFeatures(tcp, ttlFromContext(ac)),
	}
}

// ttlFromContext recovers the IP TTL the sensor stashed on the assembler context
// (reassembly never exposes the IP layer). Returns 0 if the context is not ours.
func ttlFromContext(ac reassembly.AssemblerContext) uint8 {
	if c, ok := ac.(*assemblerCtx); ok {
		return c.ttl
	}
	return 0
}

// synFeatures extracts the passive TCP/IP-stack signature from the connection's
// first observed packet. It records features only for a genuine client SYN
// (SYN set, ACK clear); for anything else (mid-stream capture, SYN-ACK seen
// first) it returns HasSYN=false so 316b classifies the OS as Unknown and writes
// nothing. It never panics on malformed options — gopacket has already validated
// option framing by the time we see the slice.
func synFeatures(tcp *layers.TCP, ttl uint8) StackFeatures {
	if tcp == nil || !tcp.SYN || tcp.ACK {
		return StackFeatures{}
	}
	sf := StackFeatures{
		HasSYN:      true,
		TTL:         ttl,
		SYNWindow:   tcp.Window,
		OptionOrder: make([]layers.TCPOptionKind, 0, len(tcp.Options)),
	}
	for _, opt := range tcp.Options {
		sf.OptionOrder = append(sf.OptionOrder, opt.OptionType)
		switch opt.OptionType {
		case layers.TCPOptionKindMSS:
			if len(opt.OptionData) == 2 {
				sf.MSS = uint16(opt.OptionData[0])<<8 | uint16(opt.OptionData[1])
			}
		case layers.TCPOptionKindWindowScale:
			sf.WSOptPresent = true
			if len(opt.OptionData) == 1 {
				sf.WindowScale = opt.OptionData[0]
			}
		}
	}
	return sf
}

// tlsStream tracks one connection's two half-streams, extracting the ClientHello
// (client→server) and ServerHello (server→client) handshake messages. It buffers
// at most maxHandshakeBytes per direction and stops as soon as each direction is
// resolved (handshake found, not-TLS, or cap hit), so a long-lived data
// connection consumes no further memory.
type tlsStream struct {
	emit emitFunc

	clientIP, serverIP     string
	clientPort, serverPort uint16
	firstSeen              time.Time
	stack                  StackFeatures

	clientBuf  []byte
	serverBuf  []byte
	clientDone bool
	serverDone bool

	clientHello []byte
	serverHello []byte
	emitted     bool
}

// Accept admits every in-window segment; the handshake lives at the very start
// of each direction, so we never need to reject mid-stream data.
func (s *tlsStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	return true
}

// ReassembledSG receives ordered, reassembled bytes for one direction.
func (s *tlsStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	length, _ := sg.Lengths()
	dir, _, end, skip := sg.Info()
	isClient := dir == reassembly.TCPDirClientToServer

	switch {
	case skip > 0:
		// Bytes were lost before this segment; we can't trust handshake framing.
		s.markGap(isClient)
	case length > 0:
		s.append(isClient, sg.Fetch(length))
	}

	if end {
		s.maybeEmit(true)
	}
}

// ReassemblyComplete fires when the connection closes or is flushed. Emit a
// final event if we captured a ClientHello but never reached the both-sides
// condition (e.g. server side never mirrored, or RST after ClientHello).
func (s *tlsStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	s.maybeEmit(true)
	ActiveStreams.Dec()
	return true // remove the connection from the pool
}

func (s *tlsStream) markGap(isClient bool) {
	if isClient && !s.clientDone {
		s.clientDone = true
		PacketsDroppedTotal.WithLabelValues(dropGap).Inc()
		logger.Debugf("reassembly: gap detected in client→server stream, abandoning (conn=%s:%d→%s:%d)",
			s.clientIP, s.clientPort, s.serverIP, s.serverPort)
	} else if !isClient && !s.serverDone {
		s.serverDone = true
		PacketsDroppedTotal.WithLabelValues(dropGap).Inc()
		logger.Debugf("reassembly: gap detected in server→client stream, abandoning (conn=%s:%d→%s:%d)",
			s.clientIP, s.clientPort, s.serverIP, s.serverPort)
	}
}

func (s *tlsStream) append(isClient bool, data []byte) {
	if isClient {
		s.appendDir(&s.clientBuf, &s.clientDone, &s.clientHello, data, isClient)
	} else {
		s.appendDir(&s.serverBuf, &s.serverDone, &s.serverHello, data, isClient)
	}
}

func (s *tlsStream) appendDir(buf *[]byte, done *bool, hello *[]byte, data []byte, isClient bool) {
	if *done {
		return
	}
	room := maxHandshakeBytes - len(*buf)
	if room <= 0 {
		*done = true
		PacketsDroppedTotal.WithLabelValues(dropCapExceeded).Inc()
		logger.Debugf("reassembly: buffer full, purging direction (conn=%s:%d→%s:%d, client=%v)",
			s.clientIP, s.clientPort, s.serverIP, s.serverPort, isClient)
		return
	}
	if len(data) > room {
		data = data[:room]
	}
	*buf = append(*buf, data...)

	want := byte(handshakeClientHello)
	kind := "clienthello"
	if !isClient {
		want = handshakeServerHello
		kind = "serverhello"
	}

	res := extractFirstHandshake(*buf, want)
	switch {
	case res.fatal:
		*done = true
	case res.complete:
		// extractFirstHandshake only ever returns complete=true for msgType
		// == want (T-001) — a HelloRetryRequest/HelloRequest ahead of the
		// real message is skipped internally, not surfaced here.
		*done = true
		msg := make([]byte, len(res.message))
		copy(msg, res.message)
		*hello = msg
		HandshakesExtractedTotal.WithLabelValues(kind).Inc()
		s.maybeEmit(false)
	case len(*buf) >= maxHandshakeBytes:
		*done = true
		PacketsDroppedTotal.WithLabelValues(dropCapExceeded).Inc()
		logger.Debugf("reassembly: buffer exceeded max handshake bytes, purging direction (conn=%s:%d→%s:%d, client=%v)",
			s.clientIP, s.clientPort, s.serverIP, s.serverPort, isClient)
	}
}

// maybeEmit emits exactly one HandshakeEvent per connection. Without force it
// waits for both ClientHello and ServerHello; with force (FIN/RST/flush) it
// emits as long as a ClientHello was captured.
func (s *tlsStream) maybeEmit(force bool) {
	if s.emitted || s.clientHello == nil {
		return
	}
	if !force && s.serverHello == nil {
		return
	}
	s.emitted = true
	HandshakesExtractedTotal.WithLabelValues("connection").Inc()

	// Deep-copy OptionOrder so the emitted event shares no backing array with
	// s.stack (G-001) — consistent with the ClientHello/ServerHello deep-copy
	// pattern above; s.emitted guards against a live race today, but a shared
	// slice header is a latent one waiting for a future reader/writer of
	// s.stack after emit.
	stack := s.stack
	stack.OptionOrder = append([]layers.TCPOptionKind(nil), s.stack.OptionOrder...)

	s.emit(HandshakeEvent{
		ClientIP:    s.clientIP,
		ServerIP:    s.serverIP,
		ClientPort:  s.clientPort,
		ServerPort:  s.serverPort,
		ClientHello: s.clientHello,
		ServerHello: s.serverHello,
		FirstSeen:   s.firstSeen,
		Stack:       stack,
	})
}
