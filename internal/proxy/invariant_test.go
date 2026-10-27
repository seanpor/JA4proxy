package proxy_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"

	"pgregory.net/rapid"
	"github.com/seanpor/ja4proxy/internal/proxy"
)

// proxyV2Signature is the 12-byte PROXY protocol v2 magic preamble.
var proxyV2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// TestInvariant_ProxyV1_TotalityAndBounds verifies that arbitrary byte sequences
// never cause ReadProxyProtocol to panic or hang.
func TestInvariant_ProxyV1_TotalityAndBounds(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		data := rapid.SliceOf(rapid.Byte()).Draw(t, "data")
		clientIP, ok := proxy.ReadProxyProtocol(data)

		// Invariant: If ok is true, clientIP must be a valid non-empty IP string.
		if ok {
			if clientIP == "" {
				t.Fatalf("ReadProxyProtocol returned ok=true with empty clientIP")
			}
			parsed := net.ParseIP(clientIP)
			if parsed == nil {
				t.Fatalf("ReadProxyProtocol returned ok=true with invalid IP %q", clientIP)
			}
			// Invariant: Header line must contain CRLF and be <= 107 bytes.
			idx := bytes.Index(data, []byte("\r\n"))
			if idx < 0 || idx > 107 {
				t.Fatalf("ReadProxyProtocol returned ok=true for line length %d", idx)
			}
		}
	})
}

// TestInvariant_ProxyV2_TotalityAndBounds verifies that arbitrary byte sequences
// never cause ReadProxyProtocolV2 or ReadProxyProtocolV2WithLength to panic or hang.
func TestInvariant_ProxyV2_TotalityAndBounds(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		data := rapid.SliceOf(rapid.Byte()).Draw(t, "data")
		clientIP, ok, hdrLen := proxy.ReadProxyProtocolV2WithLength(data)

		// Invariant: If ok is true, headerLen must be bounded within len(data).
		if ok {
			if hdrLen <= 0 || hdrLen > len(data) {
				t.Fatalf("ReadProxyProtocolV2WithLength returned invalid headerLen %d for input len %d", hdrLen, len(data))
			}
			if len(data) < 16 {
				t.Fatalf("ReadProxyProtocolV2WithLength returned ok=true on buffer < 16 bytes: %d", len(data))
			}
			if !bytes.HasPrefix(data, proxyV2Signature) {
				t.Fatalf("ReadProxyProtocolV2WithLength returned ok=true without v2 signature prefix")
			}
			if clientIP != "" {
				parsed := net.ParseIP(clientIP)
				if parsed == nil {
					t.Fatalf("ReadProxyProtocolV2WithLength returned invalid IP %q", clientIP)
				}
			}
		} else {
			if hdrLen != 0 {
				t.Fatalf("ReadProxyProtocolV2WithLength returned ok=false but non-zero hdrLen %d", hdrLen)
			}
		}
	})
}

// TestInvariant_ProxyV2_LocalCommandSemantics verifies JA4PROXY-2026-0113:
// LOCAL command (cmd=0x00) MUST return ok=true with clientIP="" and correct headerLen.
func TestInvariant_ProxyV2_LocalCommandSemantics(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Version 2 (high nibble = 2) | command LOCAL (0x00) -> 0x20
		cmdVer := byte(0x20)
		family := rapid.Byte().Draw(t, "family")
		addrLen := rapid.Uint16Range(0, 1024).Draw(t, "addrLen")
		extraPayload := rapid.SliceOfN(rapid.Byte(), int(addrLen), int(addrLen)).Draw(t, "payload")

		var buf bytes.Buffer
		buf.Write(proxyV2Signature)
		buf.WriteByte(cmdVer)
		buf.WriteByte(family)
		_ = binary.Write(&buf, binary.BigEndian, addrLen)
		buf.Write(extraPayload)

		// Trailing data representing TLS ClientHello or payload
		trailing := rapid.SliceOf(rapid.Byte()).Draw(t, "trailing")
		buf.Write(trailing)

		clientIP, ok, hdrLen := proxy.ReadProxyProtocolV2WithLength(buf.Bytes())

		expectedHdrLen := 16 + int(addrLen)
		if !ok {
			t.Fatalf("LOCAL command was rejected: ok=false")
		}
		if clientIP != "" {
			t.Fatalf("LOCAL command must return empty clientIP (discard header and use socket IP), got %q", clientIP)
		}
		if hdrLen != expectedHdrLen {
			t.Fatalf("LOCAL command hdrLen mismatch: got %d, want %d", hdrLen, expectedHdrLen)
		}
	})
}

// TestInvariant_Proxy_AntiSmuggling verifies JA4PROXY-2026-0002 & JA4PROXY-2026-0110:
// Chained / double headers cannot smuggle spoofed IPs across boundaries.
func TestInvariant_Proxy_AntiSmuggling(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate valid primary v2 header
		srcIPv4 := net.IPv4(
			rapid.ByteRange(1, 254).Draw(t, "ip1"),
			rapid.Byte().Draw(t, "ip2"),
			rapid.Byte().Draw(t, "ip3"),
			rapid.ByteRange(1, 254).Draw(t, "ip4"),
		)
		dstIPv4 := net.IPv4(127, 0, 0, 1)
		srcPort := rapid.IntRange(1024, 65535).Draw(t, "srcPort")
		dstPort := 443

		v2Primary := proxy.BuildBackendProxyHeader(2, srcIPv4, srcPort, dstIPv4, dstPort)

		// Attacker attempts to smuggle secondary v1 or v2 header in the trailing payload
		smuggledIP := net.IPv4(10, 0, 0, rapid.ByteRange(1, 254).Draw(t, "smuggleLast"))
		v1Smuggled := fmt.Sprintf("PROXY TCP4 %s 127.0.0.1 5555 443\r\n", smuggledIP.String())

		// Combine primary + smuggled payload
		combined := append([]byte(nil), v2Primary...)
		combined = append(combined, []byte(v1Smuggled)...)

		// Read primary header
		extractedIP, ok, hdrLen := proxy.ReadProxyProtocolV2WithLength(combined)
		if !ok {
			t.Fatalf("Valid v2 header was rejected when followed by smuggled bytes")
		}
		if extractedIP != srcIPv4.String() {
			t.Fatalf("Extracted IP was mutated: got %q, want %q", extractedIP, srcIPv4.String())
		}
		if hdrLen != len(v2Primary) {
			t.Fatalf("Header length did not match primary header length: got %d, want %d", hdrLen, len(v2Primary))
		}

		// The remainder of the payload must begin exactly with the smuggled payload,
		// allowing downstream anti-smuggling / TLS lockdown checks to inspect the slice.
		remainder := combined[hdrLen:]
		if !strings.HasPrefix(string(remainder), "PROXY ") {
			t.Fatalf("Smuggled header was not preserved at boundary: %q", string(remainder))
		}
	})
}
