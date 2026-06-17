package tap

import (
	"time"

	"github.com/gopacket/gopacket/layers"
)

// StackFeatures holds the passive TCP/IP-stack features needed for OS
// classification (the inputs JA4T uses), captured from the connection's SYN
// packet. They are recorded once, at stream creation, from the first observed
// packet of the connection.
//
// HasSYN is false when the first observed packet was not a client SYN — for
// example a capture that started mid-connection on a SPAN port. In that case the
// other fields are zero and 316b must classify the OS as Unknown (write nothing):
// we never guess a class without the SYN.
type StackFeatures struct {
	HasSYN bool

	// TTL is the IP TTL (IPv4) or hop-limit (IPv6) observed on the SYN — the
	// post-hop value; the classifier infers the initial TTL (64/128/255).
	TTL uint8

	// SYNWindow is the advertised TCP window on the SYN (pre-window-scale).
	SYNWindow uint16

	// MSS is the value of the SYN's MSS option, or 0 if absent.
	MSS uint16

	// WindowScale is the shift count from the SYN's window-scale option; 0 if
	// the option is absent (WSOptPresent distinguishes "absent" from "shift 0").
	WindowScale  uint8
	WSOptPresent bool

	// OptionOrder is the ordered list of TCP option kinds on the SYN (including
	// NOPs), which differs by OS stack and is part of the passive signature.
	OptionOrder []layers.TCPOptionKind
}

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

	// Stack carries the passive TCP/IP-stack features from the SYN. Stack.HasSYN
	// is false when no client SYN was observed (mid-stream capture).
	Stack StackFeatures
}

// HasServerHello reports whether the server side of the handshake was captured.
func (e *HandshakeEvent) HasServerHello() bool { return len(e.ServerHello) > 0 }
