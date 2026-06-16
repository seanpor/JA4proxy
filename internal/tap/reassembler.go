package tap

import (
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"
)

// Global reassembly memory ceiling (PHASE_316a §5). These bound the page cache
// shared across all tracked connections, on top of the per-direction
// maxHandshakeBytes cap each stream enforces itself. A page is ~1900 bytes;
// 4096 pages ≈ 8 MB, ample for handshake-only buffering and a hard stop against
// a SPAN-port flood turning the sensor into an OOM.
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
	}
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
	} else if !isClient && !s.serverDone {
		s.serverDone = true
		PacketsDroppedTotal.WithLabelValues(dropGap).Inc()
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
		return
	}
	if len(data) > room {
		data = data[:room]
	}
	*buf = append(*buf, data...)

	res := extractFirstHandshake(*buf)
	switch {
	case res.fatal:
		*done = true
	case res.complete:
		*done = true
		want := byte(handshakeClientHello)
		kind := "clienthello"
		if !isClient {
			want = handshakeServerHello
			kind = "serverhello"
		}
		if res.msgType == want {
			msg := make([]byte, len(res.message))
			copy(msg, res.message)
			*hello = msg
			HandshakesExtractedTotal.WithLabelValues(kind).Inc()
		}
		s.maybeEmit(false)
	case len(*buf) >= maxHandshakeBytes:
		*done = true
		PacketsDroppedTotal.WithLabelValues(dropCapExceeded).Inc()
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
	s.emit(HandshakeEvent{
		ClientIP:    s.clientIP,
		ServerIP:    s.serverIP,
		ClientPort:  s.clientPort,
		ServerPort:  s.serverPort,
		ClientHello: s.clientHello,
		ServerHello: s.serverHello,
		FirstSeen:   s.firstSeen,
	})
}
