package tap

import (
	"github.com/gopacket/gopacket/layers"
	"github.com/seanpor/ja4proxy/internal/fingerprint"
)

// Classify maps the passive TCP/IP-stack features of a connection's SYN to a
// canonical OS class, or fingerprint.OSUnknown when it cannot be sure.
//
// The classifier is deliberately conservative — it returns a concrete class only
// for an *exact* match of a well-known stack signature, and OSUnknown for
// everything else (no SYN observed, an ambiguous stack, a NAT/middlebox-normalised
// stack, or a stack we cannot safely disambiguate). This is the whole point: a
// false OS class produces a false OS-mismatch, and a false mismatch on a real
// browser is the expensive error (the core asymmetry). When unsure, write nothing.
//
// Scope of the MVP (316b): only Windows and Linux are emitted.
//
//   - Windows is reliably separable: initial TTL 128 and, distinctively, modern
//     Windows does NOT send TCP timestamps.
//   - Linux is separable from Apple/Darwin at initial TTL 64 by its SYN option
//     ordering (SACK before Timestamps, window-scale last).
//   - macOS and iOS share the Darwin TCP stack and are passively
//     indistinguishable from each other, so emitting either risks labelling a
//     real iOS Safari user "macos" (or vice-versa) → a false mismatch. We
//     therefore classify Darwin stacks as OSUnknown and never emit macos/ios from
//     the passive path. (The JA4 side still distinguishes them; the consumer only
//     fires when both sides are concrete, so Darwin → Unknown → no signal.)
//   - ChromeOS and Android both use the Linux TCP stack (same TTL 64 +
//     SYN option order as desktop Linux) and are passively indistinguishable
//     from it, so they classify as OSLinux too (T-005). This is the same
//     asymmetry as Darwin above, but resolved the other way: unlike
//     macOS/iOS, there is no separate "chromeos"/"android" OSClass to
//     conflate with, and the browser fingerprint on these platforms (Chrome)
//     doesn't claim a specific desktop OS the way Safari implies macOS/iOS —
//     so a ChromeOS/Android user classifying as OSLinux is *correct*, not a
//     conflation. The residual risk this doc calls out for T-005: if the JA4
//     side is ever extended to claim a browser-implied OS other than "linux"
//     for Chrome-on-ChromeOS/Android traffic, that would produce a false
//     tap_os_mismatch for these users — worth checking before extending the
//     JA4 OS-claim table, not a reason to change the passive side today.
func Classify(f StackFeatures) fingerprint.OSClass {
	if !f.HasSYN {
		return fingerprint.OSUnknown
	}

	initTTL := inferInitialTTL(f.TTL)
	kinds := stripPadding(f.OptionOrder)
	hasTS := containsKind(kinds, layers.TCPOptionKindTimestamps)
	hasSACK := containsKind(kinds, layers.TCPOptionKindSACKPermitted)

	switch initTTL {
	case 128:
		// Windows 10/11: SYN options (NOPs/EOL stripped) = MSS, WindowScale,
		// SACKPermitted, and crucially NO Timestamps.
		if !hasTS && f.WSOptPresent && hasSACK &&
			kindsEqual(kinds, windowsOptionOrder) {
			return fingerprint.OSWindows
		}
	case 64:
		// Modern Linux and Darwin both send Timestamps; absence at TTL 64 is
		// unusual (or a normaliser) → don't guess.
		if hasTS && kindsEqual(kinds, linuxOptionOrder) {
			return fingerprint.OSLinux
		}
		// Apple/Darwin and anything else at TTL 64 → Unknown (see doc comment).
	}
	return fingerprint.OSUnknown
}

// Canonical SYN option signatures (TCP NOP/EndOfList padding removed), as sent
// by each stack's default initial SYN. Matching is exact and order-sensitive.
var (
	// Windows 10/11: MSS, NOP, WS, NOP, NOP, SACK  →  MSS, WS, SACK
	windowsOptionOrder = []layers.TCPOptionKind{
		layers.TCPOptionKindMSS,
		layers.TCPOptionKindWindowScale,
		layers.TCPOptionKindSACKPermitted,
	}
	// Linux: MSS, SACK, TS, NOP, WS  →  MSS, SACK, TS, WS
	linuxOptionOrder = []layers.TCPOptionKind{
		layers.TCPOptionKindMSS,
		layers.TCPOptionKindSACKPermitted,
		layers.TCPOptionKindTimestamps,
		layers.TCPOptionKindWindowScale,
	}
)

// inferInitialTTL rounds an observed (post-hop) TTL up to the nearest common
// initial value. Internet paths are well under 64 hops, so the mapping is
// unambiguous in practice. Returns 0 (unknown) for a zero or out-of-range TTL.
// inferInitialTTL maps an observed TTL to the initial TTL a sender likely
// started with, by rounding up to the nearest common OS default (64, 128,
// 255). This is inherently a boundary heuristic, not an exact inverse (T-004):
// observed 128 could mean initial 128 (0 hops) or initial 255 (127 hops), and
// observed 64 could mean initial 64 (0 hops) or initial 255 (191 hops) --
// there's no way to recover hop count from a single observed TTL. In
// practice this ambiguity has no exploitation path: no mainstream OS uses
// initial TTL 255 for ordinary client traffic, and no real internet path is
// anywhere near 127 hops (typical paths are well under 40) -- so the
// boundary cases this function can't disambiguate don't occur with genuine
// traffic. Classify's own conservative design (concrete class only on an
// exact stack-signature match, Unknown otherwise) is the actual safety net,
// not this function.
func inferInitialTTL(ttl uint8) int {
	switch {
	case ttl == 0:
		return 0
	case ttl <= 64:
		return 64
	case ttl <= 128:
		return 128
	default:
		return 255
	}
}

// stripPadding removes NOP and EndOfList options, which are alignment padding and
// not part of the discriminating signature.
func stripPadding(in []layers.TCPOptionKind) []layers.TCPOptionKind {
	out := make([]layers.TCPOptionKind, 0, len(in))
	for _, k := range in {
		if k == layers.TCPOptionKindNop || k == layers.TCPOptionKindEndList {
			continue
		}
		out = append(out, k)
	}
	return out
}

func containsKind(ks []layers.TCPOptionKind, want layers.TCPOptionKind) bool {
	for _, k := range ks {
		if k == want {
			return true
		}
	}
	return false
}

func kindsEqual(a, b []layers.TCPOptionKind) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
