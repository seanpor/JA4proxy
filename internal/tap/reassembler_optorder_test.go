package tap

import (
	"testing"

	"github.com/gopacket/gopacket/layers"
)

// TestMaybeEmitDeepCopiesOptionOrder guards G-001: the emitted event's
// Stack.OptionOrder must not share a backing array with the tlsStream's own
// s.stack.OptionOrder, so mutating one after emit can never affect the other.
func TestMaybeEmitDeepCopiesOptionOrder(t *testing.T) {
	var got HandshakeEvent
	s := &tlsStream{
		emit: func(e HandshakeEvent) { got = e },
		stack: StackFeatures{
			HasSYN:      true,
			OptionOrder: []layers.TCPOptionKind{layers.TCPOptionKindMSS, layers.TCPOptionKindWindowScale},
		},
		clientHello: []byte("ch"),
		serverHello: []byte("sh"),
	}

	s.maybeEmit(false)

	if len(got.Stack.OptionOrder) != 2 {
		t.Fatalf("emitted OptionOrder len = %d, want 2", len(got.Stack.OptionOrder))
	}

	// Mutate the stream's own copy after emit — the emitted event must be unaffected.
	s.stack.OptionOrder[0] = layers.TCPOptionKindTimestamps

	if got.Stack.OptionOrder[0] != layers.TCPOptionKindMSS {
		t.Errorf("emitted OptionOrder[0] = %v after mutating s.stack; want unchanged %v (slice is aliased, not deep-copied)",
			got.Stack.OptionOrder[0], layers.TCPOptionKindMSS)
	}
}
