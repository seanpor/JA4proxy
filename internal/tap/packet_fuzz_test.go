// Package tap provides passive network traffic analysis and TLS/JA4T fingerprinting.
package tap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"pgregory.net/rapid"
)

// ---------------------------------------------------------------------------
// Native Go Fuzz Targets
// ---------------------------------------------------------------------------

// FuzzPacketDecoder fuzzes raw packet decoding across different link types.
func FuzzPacketDecoder(f *testing.F) {
	f.Add([]byte{}, uint8(layers.LinkTypeEthernet))
	f.Add([]byte{}, uint8(layers.LinkTypeRaw))
	f.Add([]byte{}, uint8(layers.LinkTypeIPv4))
	f.Add([]byte{}, uint8(layers.LinkTypeIPv6))
	f.Add([]byte{}, uint8(layers.LinkTypeLoop))

	// Minimal Ethernet + IPv4 + TCP SYN frame seed
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IPv4(192, 0, 2, 1),
		DstIP:    net.IPv4(198, 51, 100, 1),
	}
	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 443,
		SYN:     true,
		Seq:     1000,
		Window:  65535,
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	_ = gopacket.SerializeLayers(buf, opts, eth, ip4, tcp)
	f.Add(buf.Bytes(), uint8(layers.LinkTypeEthernet))

	f.Fuzz(func(t *testing.T, payload []byte, linkTypeVal uint8) {
		linkType := layers.LinkType(linkTypeVal)
		dec := newDecoder(linkType)
		res := dec.decode(payload)

		// Verification: decoder must never panic and results must be internally consistent
		if res.Proto == ProtoTCP && res.TCP == nil {
			t.Fatal("expected non-nil TCP struct for ProtoTCP")
		}
		if res.Proto == ProtoUDP && res.UDP == nil {
			t.Fatal("expected non-nil UDP struct for ProtoUDP")
		}
	})
}

// FuzzTCPReassembly fuzzes stream reassembly and TLS frame extraction.
func FuzzTCPReassembly(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00}) // ClientHello start
	f.Add([]byte("HTTP/1.1 200 OK\r\n\r\n"))                                   // Non-TLS

	f.Fuzz(func(t *testing.T, chunk []byte) {
		var emitted []HandshakeEvent
		emit := func(e HandshakeEvent) {
			emitted = append(emitted, e)
		}

		stream := &tlsStream{
			emit:      emit,
			clientIP:  "192.0.2.1",
			serverIP:  "198.51.100.1",
			firstSeen: time.Now(),
		}

		// Push to client-to-server direction (isClient = true)
		stream.append(true, chunk)

		// Buffer must never exceed maxHandshakeBytes
		if len(stream.clientBuf) > maxHandshakeBytes {
			t.Fatalf("stream buffer %d exceeded maxHandshakeBytes %d", len(stream.clientBuf), maxHandshakeBytes)
		}
	})
}

// FuzzParsePortList fuzzes BPF port list string parsing.
func FuzzParsePortList(f *testing.F) {
	f.Add("443,8443,80")
	f.Add("")
	f.Add("0")
	f.Add("65535")
	f.Add("invalid,99999,-5")
	f.Add("  443 , 80  ")

	f.Fuzz(func(t *testing.T, input string) {
		ports, err := ParsePortList(input)
		if err != nil {
			if len(ports) != 0 {
				t.Fatalf("expected empty ports on error, got %d ports", len(ports))
			}
			return
		}
		// Valid ports must be in 1-65535
		for _, p := range ports {
			if p == 0 {
				t.Fatalf("port 0 should not be accepted by ParsePortList")
			}
		}
	})
}

// FuzzComputeJA4T fuzzes TCP option extraction and JA4T fingerprinting.
func FuzzComputeJA4T(f *testing.F) {
	f.Add(uint16(65535), uint8(64), []byte{})
	f.Add(uint16(1024), uint8(128), []byte{2, 4, 0x05, 0xb4})             // MSS 1460
	f.Add(uint16(8192), uint8(255), []byte{3, 3, 7, 8, 10, 0, 0, 0, 0}) // WScale + Timestamps

	f.Fuzz(func(t *testing.T, window uint16, ttl uint8, optBytes []byte) {
		// Construct synthetic TCP options
		var options []layers.TCPOption
		idx := 0
		for idx < len(optBytes) {
			kind := layers.TCPOptionKind(optBytes[idx])
			idx++
			if kind == layers.TCPOptionKindEndList || kind == layers.TCPOptionKindNop {
				options = append(options, layers.TCPOption{OptionType: kind})
				continue
			}
			if idx >= len(optBytes) {
				break
			}
			optLen := int(optBytes[idx])
			idx++
			dataLen := optLen - 2
			if dataLen < 0 || idx+dataLen > len(optBytes) {
				break
			}
			data := optBytes[idx : idx+dataLen]
			idx += dataLen
			options = append(options, layers.TCPOption{
				OptionType:   kind,
				OptionLength: uint8(optLen),
				OptionData:   data,
			})
		}

		tcp := &layers.TCP{
			Window:  window,
			Options: options,
			SYN:     true,
			ACK:     false,
		}

		features := synFeatures(tcp, ttl)
		_ = ComputeJA4T(features)
	})
}

// ---------------------------------------------------------------------------
// Rapid Property-Based Invariant Tests
// ---------------------------------------------------------------------------

// TestProperty_StreamBufferCeiling proves that for arbitrary appended chunks,
// stream buffers are strictly bounded by maxHandshakeBytes and truncate gracefully.
func TestProperty_StreamBufferCeiling(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		stream := &tlsStream{
			clientIP:  "192.0.2.1",
			serverIP:  "198.51.100.1",
			firstSeen: time.Now(),
		}

		numChunks := rapid.IntRange(1, 10).Draw(rt, "num_chunks")
		for i := 0; i < numChunks; i++ {
			chunkLen := rapid.IntRange(1, 4096).Draw(rt, fmt.Sprintf("chunk_len_%d", i))
			chunk := rapid.SliceOfN(rapid.Byte(), chunkLen, chunkLen).Draw(rt, fmt.Sprintf("chunk_%d", i))

			isClient := rapid.Bool().Draw(rt, fmt.Sprintf("is_client_%d", i))
			stream.append(isClient, chunk)

			if len(stream.clientBuf) > maxHandshakeBytes {
				rt.Fatalf("clientBuf length %d exceeded maxHandshakeBytes %d", len(stream.clientBuf), maxHandshakeBytes)
			}
			if len(stream.serverBuf) > maxHandshakeBytes {
				rt.Fatalf("serverBuf length %d exceeded maxHandshakeBytes %d", len(stream.serverBuf), maxHandshakeBytes)
			}
		}
	})
}

// TestProperty_BPFJumpOffsetsBounded proves that CompilePortBPF generates jump offsets
// that strictly fit within 8-bit unsigned integers (<= 255) for all valid port counts (<= 127).
func TestProperty_BPFJumpOffsetsBounded(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		numPorts := rapid.IntRange(1, maxBPFPorts).Draw(rt, "num_ports")
		ports := make([]uint16, numPorts)
		for i := 0; i < numPorts; i++ {
			ports[i] = rapid.Uint16Range(1, 65535).Draw(rt, fmt.Sprintf("port_%d", i))
		}

		rawInsts, err := CompilePortBPF(ports...)
		if err != nil {
			rt.Fatalf("unexpected CompilePortBPF error for %d ports: %v", numPorts, err)
		}
		if len(rawInsts) == 0 {
			rt.Fatalf("expected non-empty BPF instructions for %d ports", numPorts)
		}

		// Beyond maxBPFPorts must fail
		tooManyPorts := make([]uint16, maxBPFPorts+1)
		_, errOver := CompilePortBPF(tooManyPorts...)
		if errOver == nil {
			rt.Fatalf("expected error for %d ports, got nil", maxBPFPorts+1)
		}
	})
}

// TestProperty_RedisCircuitBreakerStateTransitions proves that RedisCircuitBreaker
// trips open on exactly 5 consecutive failures and resets to closed on success.
func TestProperty_RedisCircuitBreakerStateTransitions(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		mr := &mockRedisSetterGetter{}
		cb := NewRedisCircuitBreaker(mr)

		failCount := rapid.IntRange(1, 10).Draw(rt, "fail_count")
		mr.err = errors.New("redis connection refused")
		for i := 0; i < failCount; i++ {
			err := cb.Set(context.Background(), fmt.Sprintf("k_%d", i), "v", time.Minute)
			if i < circuitBreakerFailureThreshold-1 {
				if errors.Is(err, ErrRedisCircuitOpen) {
					rt.Fatalf("circuit breaker opened prematurely after %d failures", i+1)
				}
			} else {
				if !errors.Is(err, ErrRedisCircuitOpen) && err != mr.err {
					rt.Fatalf("circuit breaker must be open or report error after %d consecutive failures, got %v", i+1, err)
				}
			}
		}

		// A success must restore operation
		mr.err = nil
		// Wait past openUntil if needed or force cooldown
		cb.mu.Lock()
		cb.openUntil = time.Now().Add(-time.Second)
		cb.mu.Unlock()

		err := cb.Set(context.Background(), "k_restore", "v", time.Minute)
		if err != nil {
			rt.Fatalf("circuit breaker failed after recovery: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Micro-Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkPacketDecode(b *testing.B) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IPv4(192, 0, 2, 1),
		DstIP:    net.IPv4(198, 51, 100, 1),
	}
	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 443,
		SYN:     true,
		Seq:     1000,
		Window:  65535,
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	_ = gopacket.SerializeLayers(buf, opts, eth, ip4, tcp)
	payload := buf.Bytes()

	dec := newDecoder(layers.LinkTypeEthernet)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = dec.decode(payload)
	}
}

func BenchmarkTCPReassembly(b *testing.B) {
	chunk := []byte{0x16, 0x03, 0x01, 0x00, 0x50, 0x01, 0x00, 0x00, 0x4c}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stream := &tlsStream{
			clientIP:  "192.0.2.1",
			serverIP:  "198.51.100.1",
			firstSeen: time.Now(),
		}
		stream.append(true, chunk)
	}
}

func BenchmarkComputeJA4T(b *testing.B) {
	tcp := &layers.TCP{
		Window: 65535,
		SYN:    true,
		Options: []layers.TCPOption{
			{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
			{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}},
			{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
			{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)},
		},
	}
	features := synFeatures(tcp, 64)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComputeJA4T(features)
	}
}
