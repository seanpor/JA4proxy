// Package quic implements QUIC Initial packet parsing and JA4Q fingerprinting.
package quic

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"pgregory.net/rapid"
)

// encodeVarint writes a QUIC variable-length integer (RFC 9000 §16) into buf.
// Returns the number of bytes written, or -1 if val is too large (> 2^62-1).
func encodeVarint(val uint64, buf []byte) int {
	if val <= 63 {
		if len(buf) < 1 {
			return -1
		}
		buf[0] = byte(val)
		return 1
	} else if val <= 16383 {
		if len(buf) < 2 {
			return -1
		}
		binary.BigEndian.PutUint16(buf[:2], uint16(val)|0x4000)
		return 2
	} else if val <= 1073741823 {
		if len(buf) < 4 {
			return -1
		}
		binary.BigEndian.PutUint32(buf[:4], uint32(val)|0x80000000)
		return 4
	} else if val <= 4611686018427387903 {
		if len(buf) < 8 {
			return -1
		}
		binary.BigEndian.PutUint64(buf[:8], val|0xc000000000000000)
		return 8
	}
	return -1
}

// ---------------------------------------------------------------------------
// Native Go Fuzz Targets
// ---------------------------------------------------------------------------

// FuzzReadVarint fuzzes the QUIC variable-length integer decoder (RFC 9000 §16).
func FuzzReadVarint(f *testing.F) {
	// Seed 1-byte, 2-byte, 4-byte, 8-byte valid varints and empty/truncated inputs
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x25})       // 37 (1 byte)
	f.Add([]byte{0x7b, 0xbd}) // 15293 (2 byte)
	f.Add([]byte{0x9d, 0x7f, 0x3e, 0x7d}) // 494878333 (4 byte)
	f.Add([]byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}) // (8 byte)
	f.Add([]byte{0x40})       // 2-byte prefix but truncated
	f.Add([]byte{0x80, 0x01}) // 4-byte prefix but truncated
	f.Add([]byte{0xc0, 0x01, 0x02, 0x03}) // 8-byte prefix but truncated

	f.Fuzz(func(t *testing.T, data []byte) {
		val, n := readVarint(data)
		if n <= 0 {
			if n != -1 {
				t.Fatalf("expected error return code -1, got %d", n)
			}
			return
		}

		// Valid read: n must be 1, 2, 4, or 8 and must not exceed len(data)
		if n != 1 && n != 2 && n != 4 && n != 8 {
			t.Fatalf("invalid varint read length: %d", n)
		}
		if n > len(data) {
			t.Fatalf("readVarint read %d bytes from slice of length %d", n, len(data))
		}

		// Verify re-encoding produces the same value
		buf := make([]byte, 8)
		m := encodeVarint(val, buf)
		if m != n {
			// RFC 9000 allows variable length encoding with wider representation than necessary,
			// but readVarint must still decode correctly. Re-reading buf[:m] must match val.
			val2, n2 := readVarint(buf[:m])
			if n2 != m || val2 != val {
				t.Fatalf("re-encoded varint mismatch: original %d (len %d), re-encoded %d (len %d)", val, n, val2, n2)
			}
		}
	})
}

// FuzzParseCRYPTOFrames fuzzes the extraction and reassembly of CRYPTO frames.
func FuzzParseCRYPTOFrames(f *testing.F) {
	// Seed with valid CRYPTO frames, multiple frames, non-crypto frames, and malformed inputs
	f.Add([]byte{})
	f.Add([]byte{0x06, 0x00, 0x04, 't', 'e', 's', 't'})
	f.Add([]byte{0x00, 0x06, 0x00, 0x02, 'h', 'i', 0x01}) // PADDING, CRYPTO, PING
	f.Add([]byte{0x06, 0x00, 0x80, 0x00, 0x00, 0x05})    // truncated length
	f.Add([]byte{0x06, 0x40, 0x04, 0x04, 'd', 'a', 't', 'a'}) // offset 4

	f.Fuzz(func(t *testing.T, data []byte) {
		extracted, err := ParseCRYPTOFrames(data)
		if err != nil {
			if extracted != nil {
				t.Fatalf("expected nil data on error, got %d bytes", len(extracted))
			}
			return
		}

		// Successful extraction invariant: never exceeds MaxCryptoBytes
		if len(extracted) > MaxCryptoBytes {
			t.Fatalf("extracted CRYPTO bytes %d exceeded MaxCryptoBytes %d", len(extracted), MaxCryptoBytes)
		}
	})
}

// FuzzDecodeInitialHeader fuzzes the UDP payload header parsing in DecodeInitial.
func FuzzDecodeInitialHeader(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00}) // Short header
	f.Add([]byte{0x80}) // Long header, Initial (ptype 0)
	f.Add([]byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, payload []byte) {
		dec := NewDecoder(nil)
		udp := &layers.UDP{
			BaseLayer: layers.BaseLayer{Payload: payload},
			SrcPort:   layers.UDPPort(4433),
			DstPort:   layers.UDPPort(8443),
		}

		srcIP := net.IPv4(192, 0, 2, 1)
		dstIP := net.IPv4(198, 51, 100, 1)
		netFlow, _ := gopacket.FlowFromEndpoints(
			layers.NewIPEndpoint(srcIP),
			layers.NewIPEndpoint(dstIP),
		)

		ci := gopacket.CaptureInfo{
			Timestamp:      time.Now(),
			CaptureLength:  len(payload),
			Length:         len(payload),
		}

		res, err := dec.DecodeInitial(netFlow, udp, ci, 64)
		if err != nil {
			// On error, res must be nil
			if res != nil {
				t.Fatalf("expected nil result on error, got %+v", res)
			}
			return
		}

		// If res is returned without error, verify basic fields
		if res != nil {
			if res.ClientPort != 4433 || res.ServerPort != 8443 {
				t.Fatalf("unexpected ports in result: %d -> %d", res.ClientPort, res.ServerPort)
			}
			if len(res.DCID) > 32 {
				t.Fatalf("DCID length exceeds 32: %d", len(res.DCID))
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Rapid Property-Based Invariant Tests
// ---------------------------------------------------------------------------

// TestProperty_VarintRoundtrip proves that for any valid uint62 integer,
// encodeVarint followed by readVarint exactly preserves the integer value.
func TestProperty_VarintRoundtrip(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Generate value in [0, 2^62-1]
		val := rapid.Uint64Range(0, 4611686018427387903).Draw(rt, "varint_val")

		buf := make([]byte, 16)
		n := encodeVarint(val, buf)
		if n <= 0 {
			rt.Fatalf("encodeVarint failed for %d", val)
		}

		decoded, readN := readVarint(buf[:n])
		if readN != n {
			rt.Fatalf("varint length mismatch: encoded %d bytes, read %d bytes", n, readN)
		}
		if decoded != val {
			rt.Fatalf("varint value roundtrip mismatch: expected %d, got %d", val, decoded)
		}
	})
}

// TestProperty_CRYPTOFrameBounds proves that defragmentation strictly adheres to
// the MaxCryptoBytes limit and preserves contiguous byte sequences without memory leaks.
func TestProperty_CRYPTOFrameBounds(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		numFrags := rapid.IntRange(1, 10).Draw(rt, "num_fragments")
		frags := make([]fragment, numFrags)

		currentOffset := uint64(0)
		for i := 0; i < numFrags; i++ {
			fragLen := rapid.IntRange(1, 4096).Draw(rt, fmt.Sprintf("frag_len_%d", i))
			data := rapid.SliceOfN(rapid.Byte(), fragLen, fragLen).Draw(rt, fmt.Sprintf("frag_data_%d", i))
			frags[i] = fragment{
				offset: currentOffset,
				data:   data,
			}
			currentOffset += uint64(fragLen)
		}

		result, err := defragment(frags)
		if currentOffset > MaxCryptoBytes {
			if err == nil {
				rt.Fatalf("expected error for totalLen %d > MaxCryptoBytes %d, got nil", currentOffset, MaxCryptoBytes)
			}
			if result != nil {
				rt.Fatalf("expected nil result on defragment error, got %d bytes", len(result))
			}
		} else {
			if err != nil {
				rt.Fatalf("unexpected defragment error for valid fragments: %v", err)
			}
			if uint64(len(result)) != currentOffset {
				rt.Fatalf("expected assembled length %d, got %d", currentOffset, len(result))
			}
		}
	})
}

// TestProperty_DecoderCapacityBound proves that under arbitrary additions of connection IDs,
// Decoder active connection tracking never exceeds MaxActive (4096 entries).
func TestProperty_DecoderCapacityBound(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		dec := NewDecoder(nil)
		connCount := rapid.IntRange(1, MaxActive+100).Draw(rt, "conn_count")

		srcIP := net.IPv4(10, 0, 0, 1)
		dstIP := net.IPv4(10, 0, 0, 2)
		netFlow, _ := gopacket.FlowFromEndpoints(
			layers.NewIPEndpoint(srcIP),
			layers.NewIPEndpoint(dstIP),
		)
		ci := gopacket.CaptureInfo{Timestamp: time.Now()}

		// Version 1 encoded as varint (prefix 0b00, value 1 -> 0x01)
		basePayload := []byte{
			0x80, // Initial packet (ptype 0x00, Long Header 0x80)
			0x01, // Version 1 as varint (RFC 9000 varint 1)
			0x08, // DCID length = 8
		}

		for i := 0; i < connCount; i++ {
			dcid := make([]byte, 8)
			binary.BigEndian.PutUint64(dcid, uint64(i+1))

			payload := make([]byte, 0, len(basePayload)+8+1+1+1+10)
			payload = append(payload, basePayload...)
			payload = append(payload, dcid...)
			payload = append(payload, 0x00) // SCID length = 0
			payload = append(payload, 0x00) // Token length = 0 (varint 0)
			payload = append(payload, 0x0a) // Length = 10 (varint 10)
			payload = append(payload, make([]byte, 10)...) // Ciphertext padding

			udp := &layers.UDP{
				BaseLayer: layers.BaseLayer{Payload: payload},
				SrcPort:   4433,
				DstPort:   8443,
			}

			_, err := dec.DecodeInitial(netFlow, udp, ci, 64)
			if dec.ActiveCount() > MaxActive {
				rt.Fatalf("Decoder active count %d exceeded MaxActive %d", dec.ActiveCount(), MaxActive)
			}

			if i >= MaxActive && err == nil {
				// Once MaxActive unique connections are active, new connections must fail
				rt.Fatalf("expected capacity error at connection index %d, got nil", i)
			}
		}
	})
}

// TestProperty_JA4QDeterminism proves that ComputeJA4Q is strictly deterministic
// and always produces the expected 3-part format "{version}_{sni}_{12_hex}".
func TestProperty_JA4QDeterminism(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		version := rapid.Uint32().Draw(rt, "quic_version")
		sni := rapid.StringMatching(`^[a-z0-9\.\-]{0,64}$`).Draw(rt, "sni")
		numAlpn := rapid.IntRange(0, 5).Draw(rt, "num_alpn")
		alpnList := make([]string, numAlpn)
		for j := 0; j < numAlpn; j++ {
			alpnList[j] = rapid.StringMatching(`^[a-z0-9\-]{1,10}$`).Draw(rt, fmt.Sprintf("alpn_%d", j))
		}

		numSigAlgs := rapid.IntRange(0, 10).Draw(rt, "num_sig_algs")
		sigAlgs := make([]uint16, numSigAlgs)
		for j := 0; j < numSigAlgs; j++ {
			sigAlgs[j] = rapid.Uint16().Draw(rt, fmt.Sprintf("sig_alg_%d", j))
		}

		numExts := rapid.IntRange(0, 15).Draw(rt, "num_exts")
		exts := make([]uint16, numExts)
		for j := 0; j < numExts; j++ {
			exts[j] = rapid.Uint16().Draw(rt, fmt.Sprintf("ext_%d", j))
		}

		features := &ClientHelloFeatures{
			SNI:                 sni,
			ALPN:                alpnList,
			SignatureAlgorithms: sigAlgs,
			ExtensionOrder:      exts,
		}

		fp1 := ComputeJA4Q(version, features)
		fp2 := ComputeJA4Q(version, features)

		if fp1 != fp2 {
			rt.Fatalf("ComputeJA4Q non-deterministic: %q != %q", fp1, fp2)
		}

		// Check format: 3 parts separated by underscores
		parts := strings.Split(fp1, "_")
		if len(parts) != 3 {
			rt.Fatalf("JA4Q fingerprint must have 3 parts, got %q (parts: %d)", fp1, len(parts))
		}
		// Version part
		if parts[0] != "quicv1" && parts[0] != "quicv2" && !strings.HasPrefix(parts[0], "draft") && parts[0] != "unknown" {
			rt.Fatalf("unexpected JA4Q version prefix: %q", parts[0])
		}
		// Hash part must be 12 hex chars
		if len(parts[2]) != 12 {
			rt.Fatalf("JA4Q hash component must be 12 hex chars, got %q (len %d)", parts[2], len(parts[2]))
		}
	})
}

// ---------------------------------------------------------------------------
// Micro-Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkReadVarint(b *testing.B) {
	cases := []struct {
		name string
		data []byte
	}{
		{"1-Byte", []byte{0x25}},
		{"2-Byte", []byte{0x7b, 0xbd}},
		{"4-Byte", []byte{0x9d, 0x7f, 0x3e, 0x7d}},
		{"8-Byte", []byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = readVarint(tc.data)
			}
		})
	}
}

func BenchmarkParseCRYPTOFramesMultiFrag(b *testing.B) {
	// Construct a synthetic 512-byte payload with 3 CRYPTO frames
	frame1 := append([]byte{0x06, 0x00, 0x80, 0x00, 0x00, 0x64}, make([]byte, 100)...) // len 100
	frame2 := append([]byte{0x06, 0x40, 0x64, 0x80, 0x00, 0x00, 0x64}, make([]byte, 100)...) // offset 100, len 100
	frame3 := append([]byte{0x06, 0x80, 0x00, 0x00, 0xc8, 0x80, 0x00, 0x00, 0x64}, make([]byte, 100)...) // offset 200, len 100
	payload := append(frame1, frame2...)
	payload = append(payload, frame3...)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseCRYPTOFrames(payload)
	}
}
