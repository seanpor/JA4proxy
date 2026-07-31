package tap

import (
	"bytes"
	"testing"
)

// TestSensor_PayloadPrivacy_NoApplicationDataRetained guards F-021 (the
// PHASE_316a plan's own Test Plan §10 requirement: "assert no payload bytes
// beyond the handshake are retained"). Sends a complete handshake followed by
// post-handshake application-data payload on both directions (simulating a
// real HTTP request/response after the TLS handshake finishes) and asserts
// the emitted HandshakeEvent's ClientHello/ServerHello contain exactly the
// handshake bytes and nothing from the trailing payload.
func TestSensor_PayloadPrivacy_NoApplicationDataRetained(t *testing.T) {
	f := newFlow(false)
	ch := clientHelloMessage(60)
	sh := handshakeMsg(handshakeServerHello, bytes.Repeat([]byte{0xCD}, 30))
	chRec := tlsRecord(tlsContentHandshake, ch)
	shRec := tlsRecord(tlsContentHandshake, sh)

	// Payload bytes that must never appear in the emitted event or in
	// anything a downstream writer would persist — a distinctive marker
	// makes an accidental leak trivially greppable in test failure output.
	clientPayload := []byte("GET /secret-path?token=abc123 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	serverPayload := []byte("HTTP/1.1 200 OK\r\nSet-Cookie: session=deadbeef\r\n\r\n<html>private</html>")
	clientAppData := tlsRecord(23 /* application_data */, clientPayload)
	serverAppData := tlsRecord(23, serverPayload)

	frames := [][]byte{
		f.seg(t, true, cISN, true, false, false, nil),                                                // SYN
		f.seg(t, false, sISN, true, true, false, nil),                                                // SYN-ACK
		f.seg(t, true, cISN+1, false, true, false, chRec),                                            // ClientHello
		f.seg(t, false, sISN+1, false, true, false, shRec),                                           // ServerHello -- completes the handshake, triggers emit
		f.seg(t, true, cISN+1+uint32(len(chRec)), false, true, false, clientAppData),                 // post-handshake request (must be ignored)
		f.seg(t, false, sISN+1+uint32(len(shRec)), false, true, false, serverAppData),                // post-handshake response (must be ignored)
		f.seg(t, true, cISN+1+uint32(len(chRec))+uint32(len(clientAppData)), false, true, true, nil), // FIN
	}

	events := runSensor(t, frames)
	if len(events) != 1 {
		t.Fatalf("expected exactly 1 event, got %d", len(events))
	}
	e := events[0]

	if !bytes.Equal(e.ClientHello, ch) {
		t.Errorf("ClientHello = %d bytes, want exactly the %d-byte handshake message (payload may have leaked in)", len(e.ClientHello), len(ch))
	}
	if !bytes.Equal(e.ServerHello, sh) {
		t.Errorf("ServerHello = %d bytes, want exactly the %d-byte handshake message (payload may have leaked in)", len(e.ServerHello), len(sh))
	}
	if bytes.Contains(e.ClientHello, clientPayload) || bytes.Contains(e.ServerHello, clientPayload) {
		t.Error("client application-data payload leaked into the emitted HandshakeEvent")
	}
	if bytes.Contains(e.ClientHello, serverPayload) || bytes.Contains(e.ServerHello, serverPayload) {
		t.Error("server application-data payload leaked into the emitted HandshakeEvent")
	}
}
