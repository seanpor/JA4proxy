package tap

import (
	"bytes"
	"testing"
)

// handshakeMsg builds a TLS handshake message: type(1) + length(3) + body.
func handshakeMsg(msgType byte, body []byte) []byte {
	m := make([]byte, handshakeHeaderLen+len(body))
	m[0] = msgType
	m[1] = byte(len(body) >> 16)
	m[2] = byte(len(body) >> 8)
	m[3] = byte(len(body))
	copy(m[handshakeHeaderLen:], body)
	return m
}

// tlsRecord wraps payload in a TLS record header (content type + version 3.1 +
// length).
func tlsRecord(contentType byte, payload []byte) []byte {
	r := make([]byte, tlsRecordHeaderLen+len(payload))
	r[0] = contentType
	r[1] = 0x03
	r[2] = 0x01
	r[3] = byte(len(payload) >> 8)
	r[4] = byte(len(payload))
	copy(r[tlsRecordHeaderLen:], payload)
	return r
}

func clientHelloMessage(bodyLen int) []byte {
	body := bytes.Repeat([]byte{0xAB}, bodyLen)
	return handshakeMsg(handshakeClientHello, body)
}

func TestExtractFirstHandshake(t *testing.T) {
	ch := clientHelloMessage(40)
	sh := handshakeMsg(handshakeServerHello, bytes.Repeat([]byte{0xCD}, 20))

	t.Run("complete ClientHello in one record", func(t *testing.T) {
		res := extractFirstHandshake(tlsRecord(tlsContentHandshake, ch), handshakeClientHello)
		if !res.complete || res.fatal {
			t.Fatalf("expected complete non-fatal, got %+v", res)
		}
		if res.msgType != handshakeClientHello {
			t.Errorf("msgType = %d, want %d", res.msgType, handshakeClientHello)
		}
		if !bytes.Equal(res.message, ch) {
			t.Errorf("message mismatch: got %d bytes, want %d", len(res.message), len(ch))
		}
	})

	t.Run("ServerHello", func(t *testing.T) {
		res := extractFirstHandshake(tlsRecord(tlsContentHandshake, sh), handshakeServerHello)
		if !res.complete || res.msgType != handshakeServerHello {
			t.Fatalf("expected complete ServerHello, got %+v", res)
		}
	})

	t.Run("handshake fragmented across two records", func(t *testing.T) {
		half := len(ch) / 2
		var buf []byte
		buf = append(buf, tlsRecord(tlsContentHandshake, ch[:half])...)
		buf = append(buf, tlsRecord(tlsContentHandshake, ch[half:])...)
		res := extractFirstHandshake(buf, handshakeClientHello)
		if !res.complete {
			t.Fatalf("expected complete across records, got %+v", res)
		}
		if !bytes.Equal(res.message, ch) {
			t.Error("defragmented message does not match original ClientHello")
		}
	})

	t.Run("incomplete — waits for more", func(t *testing.T) {
		full := tlsRecord(tlsContentHandshake, ch)
		res := extractFirstHandshake(full[:len(full)-10], handshakeClientHello) // truncated record
		if res.complete || res.fatal {
			t.Fatalf("expected incomplete non-fatal, got %+v", res)
		}
	})

	t.Run("non-handshake first record is fatal", func(t *testing.T) {
		// content type 23 = application data, or plaintext HTTP.
		res := extractFirstHandshake([]byte("GET / HTTP/1.1\r\n\r\n"), handshakeClientHello)
		if !res.fatal {
			t.Fatalf("expected fatal for non-TLS, got %+v", res)
		}
	})

	t.Run("empty buffer", func(t *testing.T) {
		res := extractFirstHandshake(nil, handshakeClientHello)
		if res.complete || res.fatal {
			t.Fatalf("expected neither complete nor fatal, got %+v", res)
		}
	})
}

// TestExtractFirstHandshake_SkipsNonMatchingType guards T-001: a complete
// handshake message of a type other than what the caller wants (e.g. a TLS
// 1.3 HelloRetryRequest, type 6, or a TLS 1.2 HelloRequest, type 0, ahead of
// the real ServerHello) must be skipped rather than treated as the terminal
// message for the direction — otherwise the real ServerHello is silently
// lost.
func TestExtractFirstHandshake_SkipsNonMatchingType(t *testing.T) {
	const handshakeHelloRetryRequest = 6
	hrr := handshakeMsg(handshakeHelloRetryRequest, bytes.Repeat([]byte{0x11}, 8))
	sh := handshakeMsg(handshakeServerHello, bytes.Repeat([]byte{0xCD}, 20))

	t.Run("HelloRetryRequest then ServerHello in one buffer", func(t *testing.T) {
		var buf []byte
		buf = append(buf, tlsRecord(tlsContentHandshake, hrr)...)
		buf = append(buf, tlsRecord(tlsContentHandshake, sh)...)

		res := extractFirstHandshake(buf, handshakeServerHello)
		if !res.complete || res.fatal {
			t.Fatalf("expected complete non-fatal ServerHello past the HRR, got %+v", res)
		}
		if res.msgType != handshakeServerHello {
			t.Errorf("msgType = %d, want ServerHello (%d)", res.msgType, handshakeServerHello)
		}
		if !bytes.Equal(res.message, sh) {
			t.Error("message does not match the real ServerHello — HRR bytes leaked in, or ServerHello truncated")
		}
	})

	t.Run("HelloRetryRequest alone waits for the real ServerHello", func(t *testing.T) {
		buf := tlsRecord(tlsContentHandshake, hrr)
		res := extractFirstHandshake(buf, handshakeServerHello)
		if res.complete || res.fatal {
			t.Fatalf("expected incomplete (still waiting past the HRR), got %+v", res)
		}
	})
}

// TestRoundTrip_HelloRetryRequestDoesNotDropServerHello is the end-to-end
// version of T-001: a full sensor Run() over a synthetic connection where the
// server sends a HelloRetryRequest before its real ServerHello must still
// emit both the ClientHello and the real ServerHello bytes.
func TestRoundTrip_HelloRetryRequestDoesNotDropServerHello(t *testing.T) {
	const handshakeHelloRetryRequest = 6
	f := newFlow(false)
	ch := clientHelloMessage(48)
	chRec := tlsRecord(tlsContentHandshake, ch)
	hrr := handshakeMsg(handshakeHelloRetryRequest, bytes.Repeat([]byte{0x11}, 8))
	sh := handshakeMsg(handshakeServerHello, bytes.Repeat([]byte{0xCD}, 24))

	frames := [][]byte{
		f.seg(t, true, cISN, true, false, false, nil),
		f.seg(t, false, sISN, true, true, false, nil),
		f.seg(t, true, cISN+1, false, true, false, chRec),
		f.seg(t, false, sISN+1, false, true, false, tlsRecord(tlsContentHandshake, hrr)),
		f.seg(t, false, sISN+1+uint32(len(tlsRecord(tlsContentHandshake, hrr))), false, true, false, tlsRecord(tlsContentHandshake, sh)),
		f.seg(t, true, cISN+1+uint32(len(chRec)), false, true, true, nil),
	}

	events := runSensor(t, frames)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if !bytes.Equal(events[0].ClientHello, ch) {
		t.Error("ClientHello bytes do not match original")
	}
	if !bytes.Equal(events[0].ServerHello, sh) {
		t.Errorf("ServerHello bytes lost or wrong (got %d bytes, want %d) — HelloRetryRequest incorrectly terminated the server direction",
			len(events[0].ServerHello), len(sh))
	}
}
