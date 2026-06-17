package tap

import (
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// synFrame builds a client SYN with the given TTL, window and TCP options, in the
// same Ethernet/IPv4 shape the other sensor tests use. It lets the Step-0 capture
// path be exercised end to end (decode → reassembly New → StackFeatures).
func synFrame(t *testing.T, f *flow, ttl uint8, win uint16, opts []layers.TCPOption) []byte {
	t.Helper()
	eth := layers.Ethernet{SrcMAC: f.cMAC, DstMAC: f.sMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: ttl, Protocol: layers.IPProtocolTCP, SrcIP: f.cIP, DstIP: f.sIP}
	tcp := layers.TCP{SrcPort: f.cPort, DstPort: f.sPort, Seq: cISN, SYN: true, Window: win, Options: opts}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	so := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, so, &eth, ip, &tcp); err != nil {
		t.Fatalf("serialize SYN: %v", err)
	}
	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out
}

func opt(kind layers.TCPOptionKind, length uint8, data []byte) layers.TCPOption {
	return layers.TCPOption{OptionType: kind, OptionLength: length, OptionData: data}
}

// linuxSYNOptions mirrors a modern Linux default SYN: MSS, SACK, TS, NOP, WS.
func linuxSYNOptions() []layers.TCPOption {
	return []layers.TCPOption{
		opt(layers.TCPOptionKindMSS, 4, []byte{0x05, 0xb4}),
		opt(layers.TCPOptionKindSACKPermitted, 2, nil),
		opt(layers.TCPOptionKindTimestamps, 10, []byte{1, 2, 3, 4, 0, 0, 0, 0}),
		opt(layers.TCPOptionKindNop, 1, nil),
		opt(layers.TCPOptionKindWindowScale, 3, []byte{7}),
	}
}

func TestSensorCapturesSYNFeatures(t *testing.T) {
	f := newFlow(false)
	ch := clientHelloMessage(48)
	chRec := tlsRecord(tlsContentHandshake, ch)

	frames := [][]byte{
		synFrame(t, f, 56, 64240, linuxSYNOptions()),
		f.seg(t, true, cISN+1, false, true, false, chRec),
		f.seg(t, true, cISN+1+uint32(len(chRec)), false, true, true, nil), // FIN forces emit
	}

	events := runSensor(t, frames)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	sf := events[0].Stack
	if !sf.HasSYN {
		t.Fatal("StackFeatures.HasSYN = false; SYN features were not captured")
	}
	if sf.TTL != 56 {
		t.Errorf("TTL = %d; want 56", sf.TTL)
	}
	if sf.SYNWindow != 64240 {
		t.Errorf("SYNWindow = %d; want 64240", sf.SYNWindow)
	}
	if sf.MSS != 1460 {
		t.Errorf("MSS = %d; want 1460", sf.MSS)
	}
	if !sf.WSOptPresent || sf.WindowScale != 7 {
		t.Errorf("WindowScale present=%v val=%d; want present=true val=7", sf.WSOptPresent, sf.WindowScale)
	}
	// The classifier should map this exact Linux profile to linux.
	if got := Classify(sf).String(); got != "linux" {
		t.Errorf("Classify(captured) = %q; want linux", got)
	}
}

func TestSensorMidStreamHasNoSYNFeatures(t *testing.T) {
	// Capture that starts mid-connection: first observed packet is a data segment,
	// not a SYN. HasSYN must be false so the OS is classified Unknown (no write).
	f := newFlow(false)
	ch := clientHelloMessage(48)
	chRec := tlsRecord(tlsContentHandshake, ch)
	frames := [][]byte{
		f.seg(t, true, cISN+1, false, true, false, chRec),
		f.seg(t, true, cISN+1+uint32(len(chRec)), false, true, true, nil),
	}
	events := runSensor(t, frames)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Stack.HasSYN {
		t.Error("mid-stream capture must yield HasSYN=false")
	}
	if got := Classify(events[0].Stack); got.IsKnown() {
		t.Errorf("mid-stream classify = %v; want Unknown", got)
	}
}
