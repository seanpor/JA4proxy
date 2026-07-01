package main

import (
	"net"
	"testing"

	"github.com/sirupsen/logrus"
)

// minimalProxyForReassembly builds just enough proxy to call reassembleClientHello.
func minimalProxyForReassembly() *proxy {
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	return &proxy{log: log}
}

// TestReassembleClientHello_ShortData verifies data shorter than 5 bytes is
// returned unchanged without touching clientConn.
func TestReassembleClientHello_ShortData(t *testing.T) {
	p := minimalProxyForReassembly()
	buf := make([]byte, 65536)

	for _, n := range []int{0, 1, 4} {
		data := make([]byte, n)
		// conn is nil — function must not dereference it for short data.
		result := p.reassembleClientHello(nil, data, buf)
		if len(result) != n {
			t.Errorf("n=%d: expected unchanged data of len %d, got %d", n, n, len(result))
		}
	}
}

// TestReassembleClientHello_OversizedRecordCap verifies the firstRecordCap
// branch: a TLS record header claiming more than 64 KB is capped.
// Uses a pipe whose server end is immediately closed so the read returns EOF.
func TestReassembleClientHello_OversizedRecordCap(t *testing.T) {
	p := minimalProxyForReassembly()
	buf := make([]byte, 65536)

	// Construct a 5-byte TLS header where recordLen = 0xFFFF (65535),
	// so want = 5 + 65535 = 65540 > firstRecordCap (65536).
	data := make([]byte, 5)
	data[0] = 0x16 // TLS Handshake record type
	data[1] = 0x03
	data[2] = 0x03
	data[3] = 0xFF // recordLen high byte
	data[4] = 0xFF // recordLen low byte  → 0xFFFF = 65535

	copy(buf, data)

	clientEnd, serverEnd := net.Pipe()
	serverEnd.Close() // reads on clientEnd will return EOF immediately

	// Should return without panic — firstRecordCap branch is exercised.
	result := p.reassembleClientHello(clientEnd, buf[:5], buf)
	clientEnd.Close()

	if len(result) < 5 {
		t.Errorf("expected at least 5 bytes back, got %d", len(result))
	}
}

// TestReassembleClientHello_SmallBufCap verifies the `offset >= cap(buf)` break:
// when the buffer is already full the loop exits without reading from conn.
func TestReassembleClientHello_SmallBufCap(t *testing.T) {
	p := minimalProxyForReassembly()

	// A 5-byte header claiming 10 more bytes (recordLen = 10, want = 15).
	rawHeader := [5]byte{0x16, 0x03, 0x03, 0x00, 0x0A}

	// buf capacity exactly 5 — same as the current data length.
	// The loop sees offset = 5 = cap(buf) and breaks immediately.
	buf := make([]byte, 5) // len=cap=5; loop hits offset >= cap(buf) and breaks
	copy(buf, rawHeader[:])

	clientEnd, serverEnd := net.Pipe()
	defer serverEnd.Close()
	defer clientEnd.Close()

	result := p.reassembleClientHello(clientEnd, buf, buf)
	if len(result) < 5 {
		t.Errorf("expected at least 5 bytes, got %d", len(result))
	}
}

// TestReassembleClientHello_NonHandshakeFragment verifies that a non-0x16
// content-type record encountered during fragment reassembly causes an
// immediate break (no infinite read loop).
func TestReassembleClientHello_NonHandshakeFragment(t *testing.T) {
	p := minimalProxyForReassembly()

	// Build a minimal ClientHello header (9 bytes) that claims a large
	// handshake body so the fragmentation loop is entered.
	// data[0:5] = TLS record header (4-byte record body)
	// data[5]   = 0x01 (ClientHello)
	// data[6:9] = handshake length 0x000064 = 100 bytes
	initial := []byte{
		0x16, 0x03, 0x03, 0x00, 0x04, // TLS record header, record len=4
		0x01,       // ClientHello type
		0x00, 0x00, 0x64, // handshake length = 100
	}

	buf := make([]byte, 65536)
	copy(buf, initial)

	clientEnd, serverEnd := net.Pipe()

	// The server sends one record with a non-handshake content type (0x15 = Alert).
	// The worker function will read the 5-byte header, detect it's not 0x16, and break.
	go func() {
		defer serverEnd.Close()
		// 5-byte TLS record header for Alert
		serverEnd.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02})
		// 2-byte alert body
		serverEnd.Write([]byte{0x02, 0x00})
	}()

	result := p.reassembleClientHello(clientEnd, buf[:len(initial)], buf)
	clientEnd.Close()

	if len(result) < len(initial) {
		t.Errorf("result shorter than initial data: got %d, want >= %d", len(result), len(initial))
	}
}
