package tap

import (
	"testing"

	"github.com/gopacket/gopacket/layers"
	"github.com/seanpor/ja4proxy/internal/fingerprint"
)

// Canonical default SYN option layouts (with NOP/EOL padding, as on the wire).
var (
	winOpts = []layers.TCPOptionKind{
		layers.TCPOptionKindMSS, layers.TCPOptionKindNop,
		layers.TCPOptionKindWindowScale, layers.TCPOptionKindNop,
		layers.TCPOptionKindNop, layers.TCPOptionKindSACKPermitted,
	}
	linuxOpts = []layers.TCPOptionKind{
		layers.TCPOptionKindMSS, layers.TCPOptionKindSACKPermitted,
		layers.TCPOptionKindTimestamps, layers.TCPOptionKindNop,
		layers.TCPOptionKindWindowScale,
	}
	darwinOpts = []layers.TCPOptionKind{
		layers.TCPOptionKindMSS, layers.TCPOptionKindNop,
		layers.TCPOptionKindWindowScale, layers.TCPOptionKindNop,
		layers.TCPOptionKindNop, layers.TCPOptionKindTimestamps,
		layers.TCPOptionKindSACKPermitted, layers.TCPOptionKindEndList,
	}
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		f    StackFeatures
		want fingerprint.OSClass
	}{
		{
			name: "windows default SYN (TTL 128, no timestamps)",
			f:    StackFeatures{HasSYN: true, TTL: 120, SYNWindow: 64240, MSS: 1460, WSOptPresent: true, OptionOrder: winOpts},
			want: fingerprint.OSWindows,
		},
		{
			name: "linux default SYN (TTL 64, SACK before TS)",
			f:    StackFeatures{HasSYN: true, TTL: 56, SYNWindow: 64240, MSS: 1460, WSOptPresent: true, OptionOrder: linuxOpts},
			want: fingerprint.OSLinux,
		},
		{
			name: "darwin (macOS/iOS) is intentionally Unknown — not separable",
			f:    StackFeatures{HasSYN: true, TTL: 60, SYNWindow: 65535, MSS: 1460, WSOptPresent: true, OptionOrder: darwinOpts},
			want: fingerprint.OSUnknown,
		},
		{
			name: "no SYN observed (mid-stream capture) → Unknown",
			f:    StackFeatures{HasSYN: false},
			want: fingerprint.OSUnknown,
		},
		{
			name: "middlebox-normalised: TTL 64 but no timestamps → Unknown",
			f:    StackFeatures{HasSYN: true, TTL: 64, WSOptPresent: true, OptionOrder: []layers.TCPOptionKind{layers.TCPOptionKindMSS, layers.TCPOptionKindSACKPermitted, layers.TCPOptionKindWindowScale}},
			want: fingerprint.OSUnknown,
		},
		{
			name: "TTL rewritten to network-gear range (255) → Unknown",
			f:    StackFeatures{HasSYN: true, TTL: 250, WSOptPresent: true, OptionOrder: winOpts},
			want: fingerprint.OSUnknown,
		},
		{
			name: "windows layout but with timestamps (atypical/VPN) → Unknown",
			f:    StackFeatures{HasSYN: true, TTL: 120, WSOptPresent: true, OptionOrder: []layers.TCPOptionKind{layers.TCPOptionKindMSS, layers.TCPOptionKindWindowScale, layers.TCPOptionKindSACKPermitted, layers.TCPOptionKindTimestamps}},
			want: fingerprint.OSUnknown,
		},
		{
			name: "zero TTL → Unknown",
			f:    StackFeatures{HasSYN: true, TTL: 0, WSOptPresent: true, OptionOrder: linuxOpts},
			want: fingerprint.OSUnknown,
		},
		{
			name: "linux options but window-scale option absent → Unknown",
			f:    StackFeatures{HasSYN: true, TTL: 56, WSOptPresent: true, OptionOrder: []layers.TCPOptionKind{layers.TCPOptionKindMSS, layers.TCPOptionKindSACKPermitted, layers.TCPOptionKindTimestamps}},
			want: fingerprint.OSUnknown,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Classify(c.f); got != c.want {
				t.Errorf("Classify(%s) = %v; want %v", c.name, got, c.want)
			}
		})
	}
}

func TestInferInitialTTL(t *testing.T) {
	cases := []struct {
		ttl  uint8
		want int
	}{
		{0, 0}, {1, 64}, {56, 64}, {64, 64}, {65, 128}, {120, 128}, {128, 128}, {200, 255}, {255, 255},
	}
	for _, c := range cases {
		if got := inferInitialTTL(c.ttl); got != c.want {
			t.Errorf("inferInitialTTL(%d) = %d; want %d", c.ttl, got, c.want)
		}
	}
}

func TestStripPadding(t *testing.T) {
	in := []layers.TCPOptionKind{
		layers.TCPOptionKindMSS, layers.TCPOptionKindNop,
		layers.TCPOptionKindWindowScale, layers.TCPOptionKindEndList,
	}
	got := stripPadding(in)
	want := []layers.TCPOptionKind{layers.TCPOptionKindMSS, layers.TCPOptionKindWindowScale}
	if !kindsEqual(got, want) {
		t.Errorf("stripPadding = %v; want %v", got, want)
	}
}
