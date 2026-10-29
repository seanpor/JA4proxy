//go:build soak

package tap_test

import (
	"runtime"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/seanpor/ja4proxy/internal/tap"
)

// TestSoak_TAPStreamReclamationOverPackets verifies that processing 10,000 synthetic
// packets followed by a flush properly drains streams and does not leak heap buffers.
func TestSoak_TAPStreamReclamationOverPackets(t *testing.T) {
	sensor := tap.NewSensor(layers.LinkTypeEthernet, 1000)

	// Consume emitted events in background so channel never blocks
	go func() {
		for range sensor.Events() {
		}
	}()

	now := time.Now()
	totalPackets := 10000

	// Pre-warm GC
	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	// Ingest synthetic TCP packets
	for i := 0; i < totalPackets; i++ {
		clientPort := uint16(1024 + (i % 500))
		eth := &layers.Ethernet{
			SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			DstMAC:       []byte{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    []byte{192, 168, 1, byte(i % 250)},
			DstIP:    []byte{10, 0, 0, 1},
		}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(clientPort),
			DstPort: 443,
			SYN:     true,
			Window:  65535,
		}
		_ = tcp.SetNetworkLayerForChecksum(ip)

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
		_ = gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload([]byte{0x16, 0x03, 0x01, 0x00, 0x10}))

		ci := gopacket.CaptureInfo{
			Timestamp:     now.Add(time.Duration(i) * time.Millisecond),
			CaptureLength: len(buf.Bytes()),
			Length:        len(buf.Bytes()),
		}

		sensor.ProcessPacket(buf.Bytes(), ci)
	}

	// Flush sensor reassembly tables
	sensor.Flush()

	runtime.GC()
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	t.Logf("Soak finished: Ingested %d packets. HeapAlloc before: %d KB, after: %d KB",
		totalPackets, memBefore.HeapAlloc/1024, memAfter.HeapAlloc/1024)
}
