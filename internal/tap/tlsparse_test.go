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
		res := extractFirstHandshake(tlsRecord(tlsContentHandshake, ch))
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
		res := extractFirstHandshake(tlsRecord(tlsContentHandshake, sh))
		if !res.complete || res.msgType != handshakeServerHello {
			t.Fatalf("expected complete ServerHello, got %+v", res)
		}
	})

	t.Run("handshake fragmented across two records", func(t *testing.T) {
		half := len(ch) / 2
		var buf []byte
		buf = append(buf, tlsRecord(tlsContentHandshake, ch[:half])...)
		buf = append(buf, tlsRecord(tlsContentHandshake, ch[half:])...)
		res := extractFirstHandshake(buf)
		if !res.complete {
			t.Fatalf("expected complete across records, got %+v", res)
		}
		if !bytes.Equal(res.message, ch) {
			t.Error("defragmented message does not match original ClientHello")
		}
	})

	t.Run("incomplete — waits for more", func(t *testing.T) {
		full := tlsRecord(tlsContentHandshake, ch)
		res := extractFirstHandshake(full[:len(full)-10]) // truncated record
		if res.complete || res.fatal {
			t.Fatalf("expected incomplete non-fatal, got %+v", res)
		}
	})

	t.Run("non-handshake first record is fatal", func(t *testing.T) {
		// content type 23 = application data, or plaintext HTTP.
		res := extractFirstHandshake([]byte("GET / HTTP/1.1\r\n\r\n"))
		if !res.fatal {
			t.Fatalf("expected fatal for non-TLS, got %+v", res)
		}
	})

	t.Run("empty buffer", func(t *testing.T) {
		res := extractFirstHandshake(nil)
		if res.complete || res.fatal {
			t.Fatalf("expected neither complete nor fatal, got %+v", res)
		}
	})
}
