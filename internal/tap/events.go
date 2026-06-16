package tap

import "time"

// HandshakeEvent is the sole output of the 316a sensor: the raw, plaintext
// ClientHello (and ServerHello, when observed) bytes of one TLS connection,
// plus its 5-tuple. Fingerprint computation is deliberately out of scope here —
// a downstream phase (316b) consumes these bytes.
//
// ClientHello/ServerHello are the full TLS handshake messages
// (handshake-record-defragmented): a 4-byte handshake header
// (type + uint24 length) followed by the message body. They are never logged or
// persisted by the sensor.
type HandshakeEvent struct {
	ClientIP   string
	ServerIP   string
	ClientPort uint16
	ServerPort uint16

	// ClientHello is always set on an emitted event. ServerHello may be nil if
	// the server side was not observed (e.g. one-directional mirror, or the
	// connection reset before the ServerHello).
	ClientHello []byte
	ServerHello []byte

	// FirstSeen is the capture timestamp of the first packet of the connection.
	FirstSeen time.Time
}

// HasServerHello reports whether the server side of the handshake was captured.
func (e *HandshakeEvent) HasServerHello() bool { return len(e.ServerHello) > 0 }
