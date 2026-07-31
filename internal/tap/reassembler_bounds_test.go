package tap

import "testing"

// TestMaxBufferedPagesPerConnStaysLow pins maxBufferedPagesPerConn (F-026):
// it is a security control bounding the size of an attacker-influenced
// sg.Fetch() allocation in maybeEmit, not a tuning knob. A future change that
// raises it (e.g. "to fit a larger handshake") should have to update this
// test deliberately rather than passing silently — see the doc comment on
// the const block in reassembler.go for the full rationale.
func TestMaxBufferedPagesPerConnStaysLow(t *testing.T) {
	const maxSafe = 16 // ~1900 bytes/page * 16 ~= 30KB per connection; still bounded
	if maxBufferedPagesPerConn > maxSafe {
		t.Fatalf("maxBufferedPagesPerConn = %d exceeds the reviewed safe ceiling of %d — "+
			"this directly raises the attacker-influenced sg.Fetch() allocation size in "+
			"maybeEmit (F-026); if this increase is intentional, update maxSafe here after "+
			"re-reviewing the Fetch() call site, don't just bump this test",
			maxBufferedPagesPerConn, maxSafe)
	}
}
