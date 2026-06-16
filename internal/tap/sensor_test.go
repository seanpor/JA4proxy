package tap

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

var baseTime = time.Unix(1_700_000_000, 0).UTC()

// flow synthesises the two directions of one TCP connection. Sequence numbers
// are tracked per direction so multi-segment / out-of-order cases are exact.
type flow struct {
	cMAC, sMAC net.HardwareAddr
	cIP, sIP   net.IP
	cPort      layers.TCPPort
	sPort      layers.TCPPort
	ipv6       bool
}

func newFlow(ipv6 bool) *flow {
	f := &flow{
		cMAC:  net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01},
		sMAC:  net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02},
		cPort: 51000,
		sPort: 443,
		ipv6:  ipv6,
	}
	if ipv6 {
		f.cIP = net.ParseIP("2001:db8::1")
		f.sIP = net.ParseIP("2001:db8::2")
	} else {
		f.cIP = net.ParseIP("10.0.0.1")
		f.sIP = net.ParseIP("10.0.0.2")
	}
	return f
}

// seg serialises one TCP segment in the requested direction.
func (f *flow) seg(t *testing.T, fromClient bool, seq uint32, syn, ack, fin bool, payload []byte) []byte {
	t.Helper()
	eth := layers.Ethernet{}
	if fromClient {
		eth.SrcMAC, eth.DstMAC = f.cMAC, f.sMAC
	} else {
		eth.SrcMAC, eth.DstMAC = f.sMAC, f.cMAC
	}

	tcp := layers.TCP{SYN: syn, ACK: ack, FIN: fin, Seq: seq, Window: 65535}
	if fromClient {
		tcp.SrcPort, tcp.DstPort = f.cPort, f.sPort
	} else {
		tcp.SrcPort, tcp.DstPort = f.sPort, f.cPort
	}

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	buf := gopacket.NewSerializeBuffer()

	var netLayer gopacket.SerializableLayer
	if f.ipv6 {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolTCP}
		if fromClient {
			ip.SrcIP, ip.DstIP = f.cIP, f.sIP
		} else {
			ip.SrcIP, ip.DstIP = f.sIP, f.cIP
		}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		netLayer = ip
	} else {
		eth.EthernetType = layers.EthernetTypeIPv4
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
		if fromClient {
			ip.SrcIP, ip.DstIP = f.cIP, f.sIP
		} else {
			ip.SrcIP, ip.DstIP = f.sIP, f.cIP
		}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		netLayer = ip
	}

	if err := gopacket.SerializeLayers(buf, opts, &eth, netLayer, &tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out
}

// memSource replays a fixed list of frames as a PacketSource.
type memSource struct {
	frames [][]byte
	i      int
}

func (m *memSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if m.i >= len(m.frames) {
		return nil, gopacket.CaptureInfo{}, io.EOF
	}
	f := m.frames[m.i]
	m.i++
	return f, gopacket.CaptureInfo{Timestamp: baseTime, CaptureLength: len(f), Length: len(f)}, nil
}

// runSensor feeds frames through a sensor and returns every emitted event.
func runSensor(t *testing.T, frames [][]byte) []HandshakeEvent {
	t.Helper()
	s := NewSensor(layers.LinkTypeEthernet, 64)
	var got []HandshakeEvent
	done := make(chan struct{})
	go func() {
		for e := range s.Events() {
			got = append(got, e)
		}
		close(done)
	}()
	if err := s.Run(context.Background(), &memSource{frames: frames}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	<-done
	return got
}

const (
	cISN = 1000
	sISN = 5000
)

func TestSensorExtractsClientAndServerHello(t *testing.T) {
	f := newFlow(false)
	ch := clientHelloMessage(60)
	sh := handshakeMsg(handshakeServerHello, bytes.Repeat([]byte{0xCD}, 30))

	frames := [][]byte{
		f.seg(t, true, cISN, true, false, false, nil),                                                  // SYN
		f.seg(t, false, sISN, true, true, false, nil),                                                  // SYN-ACK
		f.seg(t, true, cISN+1, false, true, false, tlsRecord(tlsContentHandshake, ch)),                 // ClientHello
		f.seg(t, false, sISN+1, false, true, false, tlsRecord(tlsContentHandshake, sh)),                // ServerHello
		f.seg(t, true, cISN+1+uint32(len(tlsRecord(tlsContentHandshake, ch))), false, true, true, nil), // FIN
	}

	events := runSensor(t, frames)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	e := events[0]
	if e.ClientIP != "10.0.0.1" || e.ServerIP != "10.0.0.2" {
		t.Errorf("IPs = %s -> %s, want 10.0.0.1 -> 10.0.0.2", e.ClientIP, e.ServerIP)
	}
	if e.ClientPort != 51000 || e.ServerPort != 443 {
		t.Errorf("ports = %d -> %d, want 51000 -> 443", e.ClientPort, e.ServerPort)
	}
	if !bytes.Equal(e.ClientHello, ch) {
		t.Error("ClientHello bytes mismatch")
	}
	if !bytes.Equal(e.ServerHello, sh) {
		t.Error("ServerHello bytes mismatch")
	}
}

func TestSensorClientHelloAcrossSegments(t *testing.T) {
	f := newFlow(false)
	ch := clientHelloMessage(200)
	record := tlsRecord(tlsContentHandshake, ch)
	half := len(record) / 2

	frames := [][]byte{
		f.seg(t, true, cISN, true, false, false, nil),
		f.seg(t, false, sISN, true, true, false, nil),
		f.seg(t, true, cISN+1, false, true, false, record[:half]),              // first half
		f.seg(t, true, cISN+1+uint32(half), false, true, false, record[half:]), // second half
		f.seg(t, false, sISN+1, false, true, false, tlsRecord(tlsContentHandshake, handshakeMsg(handshakeServerHello, []byte{0x01, 0x02}))),
	}

	events := runSensor(t, frames)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if !bytes.Equal(events[0].ClientHello, ch) {
		t.Error("ClientHello reassembled from two segments does not match")
	}
}

func TestSensorReassemblesOutOfOrderClientHello(t *testing.T) {
	f := newFlow(false)
	ch := clientHelloMessage(200)
	record := tlsRecord(tlsContentHandshake, ch)
	half := len(record) / 2

	// Deliver the SECOND half before the first; reassembly must reorder by seq.
	frames := [][]byte{
		f.seg(t, true, cISN, true, false, false, nil),
		f.seg(t, true, cISN+1+uint32(half), false, true, false, record[half:]), // out of order
		f.seg(t, true, cISN+1, false, true, false, record[:half]),              // fills the gap
		f.seg(t, true, cISN+1+uint32(len(record)), false, true, true, nil),     // FIN
	}

	events := runSensor(t, frames)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if !bytes.Equal(events[0].ClientHello, ch) {
		t.Error("out-of-order ClientHello did not reassemble correctly")
	}
}

func TestSensorIPv6(t *testing.T) {
	f := newFlow(true)
	ch := clientHelloMessage(48)
	frames := [][]byte{
		f.seg(t, true, cISN, true, false, false, nil),
		f.seg(t, true, cISN+1, false, true, false, tlsRecord(tlsContentHandshake, ch)),
		f.seg(t, true, cISN+1+uint32(len(tlsRecord(tlsContentHandshake, ch))), false, true, true, nil),
	}
	events := runSensor(t, frames)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].ClientIP != "2001:db8::1" || events[0].ServerIP != "2001:db8::2" {
		t.Errorf("IPv6 endpoints = %s -> %s", events[0].ClientIP, events[0].ServerIP)
	}
	if !bytes.Equal(events[0].ClientHello, ch) {
		t.Error("IPv6 ClientHello mismatch")
	}
}

func TestSensorNonTLSEmitsNothing(t *testing.T) {
	f := newFlow(false)
	frames := [][]byte{
		f.seg(t, true, cISN, true, false, false, nil),
		f.seg(t, true, cISN+1, false, true, false, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")),
		f.seg(t, true, cISN+1+27, false, true, true, nil),
	}
	if events := runSensor(t, frames); len(events) != 0 {
		t.Fatalf("expected no events for plaintext HTTP, got %d", len(events))
	}
}

func TestSensorCapExceededEmitsNothing(t *testing.T) {
	f := newFlow(false)
	before := testutil.ToFloat64(PacketsDroppedTotal.WithLabelValues(dropCapExceeded))

	// A handshake header declaring a body far larger than the 16KB cap (100000
	// bytes), streamed as TLS records that never complete it. The sensor must
	// give up at the cap, not buffer unboundedly.
	hsStream := append([]byte{handshakeClientHello, 0x01, 0x86, 0xA0}, bytes.Repeat([]byte{0xAB}, 24000)...)
	frames := [][]byte{f.seg(t, true, cISN, true, false, false, nil)}
	seq := uint32(cISN + 1)
	for off := 0; off < len(hsStream); off += 4000 {
		end := min(off+4000, len(hsStream))
		rec := tlsRecord(tlsContentHandshake, hsStream[off:end])
		frames = append(frames, f.seg(t, true, seq, false, true, false, rec))
		seq += uint32(len(rec))
	}
	frames = append(frames, f.seg(t, true, seq, false, true, true, nil))

	if events := runSensor(t, frames); len(events) != 0 {
		t.Fatalf("expected no event when handshake exceeds cap, got %d", len(events))
	}
	after := testutil.ToFloat64(PacketsDroppedTotal.WithLabelValues(dropCapExceeded))
	if after <= before {
		t.Errorf("expected cap_exceeded drop metric to increase (%v -> %v)", before, after)
	}
}
