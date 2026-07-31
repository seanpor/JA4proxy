package tap

// TLS record / handshake constants.
const (
	tlsContentHandshake = 22 // TLS record content type for handshake messages

	handshakeClientHello = 1 // handshake message type
	handshakeServerHello = 2

	tlsRecordHeaderLen  = 5       // content(1) + version(2) + length(2)
	handshakeHeaderLen  = 4       // type(1) + length(3)
	maxTLSRecordPayload = 1 << 14 // 16384 — RFC 8446 max TLSPlaintext fragment
	maxHandshakeBytes   = 16384   // per-direction reassembly cap (PHASE_316a §5)
)

// handshakeResult reports the outcome of scanning a reassembled byte stream for
// the first TLS handshake message.
type handshakeResult struct {
	msgType  byte   // 1 = ClientHello, 2 = ServerHello (only when complete)
	message  []byte // full handshake message (header + body) when complete
	complete bool   // a whole handshake message was recovered
	fatal    bool   // the stream is definitely not a TLS handshake — stop trying
}

// extractFirstHandshake walks the TLS record layer in buf, concatenating the
// payloads of consecutive handshake (type 22) records, and returns the first
// complete handshake message of type want. A handshake message may be
// fragmented across several TLS records, so payloads are defragmented before
// length-checking.
//
// Complete handshake messages of a type other than want (e.g. a TLS 1.3
// HelloRetryRequest or a TLS 1.2 HelloRequest arriving before the real
// ServerHello — T-001) are skipped rather than treated as the terminal
// message for this direction: the caller only cares about ClientHello in the
// client direction and ServerHello in the server direction, so anything else
// on the wire must not stop the scan.
//
// It never panics on malformed input: every offset and length is bounds-checked
// against buf. When the data so far is a valid-but-incomplete handshake it
// returns complete=false (wait for more bytes); when the first record is plainly
// not a handshake it returns fatal=true (give up on this direction).
func extractFirstHandshake(buf []byte, want byte) handshakeResult {
	var hs []byte // defragmented handshake-record payload
	i := 0
	for i+tlsRecordHeaderLen <= len(buf) {
		contentType := buf[i]
		recLen := int(buf[i+3])<<8 | int(buf[i+4])

		if contentType != tlsContentHandshake {
			// The very first TLS record of a client/server stream must be a
			// handshake. Anything else (alert, app-data, plaintext HTTP) means
			// this is not a TLS handshake we can fingerprint.
			if len(hs) == 0 {
				return handshakeResult{fatal: true}
			}
			break
		}
		if recLen == 0 || recLen > maxTLSRecordPayload {
			return handshakeResult{fatal: true}
		}

		recEnd := i + tlsRecordHeaderLen + recLen
		if recEnd > len(buf) {
			break // record truncated — wait for more bytes
		}
		hs = append(hs, buf[i+tlsRecordHeaderLen:recEnd]...)
		i = recEnd
	}

	if r, done := firstMatchingHandshakeMessage(hs, want); done {
		return r
	}
	return handshakeResult{}
}

// firstMatchingHandshakeMessage scans the defragmented handshake payload for
// the first complete message whose type equals want, skipping over any
// complete-but-non-matching messages that precede it (T-001) rather than
// stopping at the first complete message of any type.
func firstMatchingHandshakeMessage(hs []byte, want byte) (handshakeResult, bool) {
	off := 0
	for len(hs)-off >= handshakeHeaderLen {
		msgLen := int(hs[off+1])<<16 | int(hs[off+2])<<8 | int(hs[off+3])
		total := handshakeHeaderLen + msgLen
		if len(hs)-off < total {
			return handshakeResult{}, false // incomplete — wait for more bytes
		}
		if hs[off] == want {
			return handshakeResult{
				msgType:  hs[off],
				message:  hs[off : off+total],
				complete: true,
			}, true
		}
		off += total // not our type (e.g. HelloRetryRequest/HelloRequest) — skip it
	}
	return handshakeResult{}, false
}
