package tap

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// TestOpenPcapFileRoundTrip writes a synthetic handshake to a real .pcap on disk,
// then replays it through OpenPcapFile + the sensor — exercising the offline
// capture path end to end (PHASE_316a acceptance: exact extraction from a .pcap).
func TestOpenPcapFileRoundTrip(t *testing.T) {
	f := newFlow(false)
	ch := clientHelloMessage(72)
	sh := handshakeMsg(handshakeServerHello, bytes.Repeat([]byte{0xEE}, 24))
	chRec := tlsRecord(tlsContentHandshake, ch)

	frames := [][]byte{
		f.seg(t, true, cISN, true, false, false, nil),
		f.seg(t, false, sISN, true, true, false, nil),
		f.seg(t, true, cISN+1, false, true, false, chRec),
		f.seg(t, false, sISN+1, false, true, false, tlsRecord(tlsContentHandshake, sh)),
		f.seg(t, true, cISN+1+uint32(len(chRec)), false, true, true, nil),
	}

	path := filepath.Join(t.TempDir(), "handshake.pcap")
	writePcap(t, path, frames)

	src, lt, closeFn, err := OpenPcapFile(path)
	if err != nil {
		t.Fatalf("OpenPcapFile: %v", err)
	}
	defer closeFn()
	if lt != layers.LinkTypeEthernet {
		t.Fatalf("link type = %v, want Ethernet", lt)
	}

	s := NewSensor(lt, 16)
	var got []HandshakeEvent
	done := make(chan struct{})
	go func() {
		for e := range s.Events() {
			got = append(got, e)
		}
		close(done)
	}()
	if err := s.Run(context.Background(), src); err != nil {
		t.Fatalf("Run: %v", err)
	}
	<-done

	if len(got) != 1 {
		t.Fatalf("expected 1 event from pcap, got %d", len(got))
	}
	if !bytes.Equal(got[0].ClientHello, ch) || !bytes.Equal(got[0].ServerHello, sh) {
		t.Error("handshake bytes from pcap replay do not match originals")
	}
}

func writePcap(t *testing.T, path string, frames [][]byte) {
	t.Helper()
	out, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}
	defer out.Close()
	w := pcapgo.NewWriter(out)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}
	for _, fr := range frames {
		ci := gopacket.CaptureInfo{Timestamp: baseTime, CaptureLength: len(fr), Length: len(fr)}
		if err := w.WritePacket(ci, fr); err != nil {
			t.Fatalf("write pcap packet: %v", err)
		}
	}
}

// TestSensorRunContextCancel ensures Run returns promptly when the context is
// cancelled, flushing in-flight state without emitting a partial connection.
func TestSensorRunContextCancel(t *testing.T) {
	s := NewSensor(layers.LinkTypeEthernet, 4)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before Run starts

	done := make(chan struct{})
	go func() {
		for range s.Events() {
		}
		close(done)
	}()
	err := s.Run(ctx, &memSource{})
	if err != context.Canceled {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}
	<-done
}
