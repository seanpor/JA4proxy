package tap

import (
	"testing"

	"github.com/gopacket/gopacket/layers"
)

func TestComputeJA4T(t *testing.T) {
	const (
		mss  = layers.TCPOptionKindMSS           // 2
		nop  = layers.TCPOptionKindNop           // 1
		ws   = layers.TCPOptionKindWindowScale   // 3
		sack = layers.TCPOptionKindSACKPermitted // 4
		ts   = layers.TCPOptionKindTimestamps    // 8
		eol  = layers.TCPOptionKindEndList       // 0
	)

	cases := []struct {
		name string
		f    StackFeatures
		want string
	}{
		{
			name: "no SYN observed yields empty",
			f:    StackFeatures{HasSYN: false, SYNWindow: 64240, MSS: 1460},
			want: "",
		},
		{
			name: "windows-style SYN",
			f: StackFeatures{
				HasSYN: true, SYNWindow: 64240, MSS: 1460, WindowScale: 8, WSOptPresent: true,
				OptionOrder: []layers.TCPOptionKind{mss, nop, ws, nop, nop, sack},
			},
			want: "64240_2-1-3-1-1-4_1460_8",
		},
		{
			name: "linux-style SYN",
			f: StackFeatures{
				HasSYN: true, SYNWindow: 29200, MSS: 1460, WindowScale: 7, WSOptPresent: true,
				OptionOrder: []layers.TCPOptionKind{mss, sack, ts, nop, ws},
			},
			want: "29200_2-4-8-1-3_1460_7",
		},
		{
			name: "absent window scale renders 00, distinct from a present shift of 0",
			f: StackFeatures{
				HasSYN: true, SYNWindow: 65535, MSS: 1460, WindowScale: 0, WSOptPresent: false,
				OptionOrder: []layers.TCPOptionKind{mss, sack},
			},
			want: "65535_2-4_1460_00",
		},
		{
			name: "present window scale of 0 renders 0",
			f: StackFeatures{
				HasSYN: true, SYNWindow: 65535, MSS: 1460, WindowScale: 0, WSOptPresent: true,
				OptionOrder: []layers.TCPOptionKind{mss, sack, ws},
			},
			want: "65535_2-4-3_1460_0",
		},
		{
			name: "end-of-option-list terminator is dropped, NOPs are kept",
			f: StackFeatures{
				HasSYN: true, SYNWindow: 1024, MSS: 536, WindowScale: 0, WSOptPresent: true,
				OptionOrder: []layers.TCPOptionKind{mss, nop, eol},
			},
			want: "1024_2-1_536_0",
		},
		{
			name: "absent MSS renders 0",
			f: StackFeatures{
				HasSYN: true, SYNWindow: 8192, MSS: 0, WindowScale: 6, WSOptPresent: true,
				OptionOrder: []layers.TCPOptionKind{sack, ts},
			},
			want: "8192_4-8_0_6",
		},
		{
			name: "no options at all",
			f: StackFeatures{
				HasSYN: true, SYNWindow: 512, MSS: 0, WindowScale: 0, WSOptPresent: false,
				OptionOrder: nil,
			},
			want: "512__0_00",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ComputeJA4T(c.f); got != c.want {
				t.Errorf("ComputeJA4T() = %q; want %q", got, c.want)
			}
		})
	}
}

// TestComputeJA4T_Deterministic guards against any accidental non-determinism
// (e.g. map iteration creeping into the option join): the same input must always
// produce the same string.
func TestComputeJA4T_Deterministic(t *testing.T) {
	f := StackFeatures{
		HasSYN: true, SYNWindow: 64240, MSS: 1460, WindowScale: 8, WSOptPresent: true,
		OptionOrder: []layers.TCPOptionKind{
			layers.TCPOptionKindMSS, layers.TCPOptionKindNop, layers.TCPOptionKindWindowScale,
			layers.TCPOptionKindNop, layers.TCPOptionKindNop, layers.TCPOptionKindSACKPermitted,
		},
	}
	first := ComputeJA4T(f)
	for i := 0; i < 100; i++ {
		if got := ComputeJA4T(f); got != first {
			t.Fatalf("non-deterministic: iteration %d = %q; first = %q", i, got, first)
		}
	}
}
