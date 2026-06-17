package tap

import (
	"strconv"
	"strings"

	"github.com/gopacket/gopacket/layers"
)

// ComputeJA4T returns the canonical JA4T TCP fingerprint for a connection's SYN,
// or "" when no client SYN was observed (StackFeatures.HasSYN false) — we never
// fingerprint a stack we did not see open the connection.
//
// Format (FoxIO JA4+ canonical, interoperable with foxio/ja4 tooling):
//
//	{SYN window size}_{TCP option kinds}_{MSS}_{window scale}
//
// e.g. "65535_2-1-3-1-1-8-4_1460_7". The option-kinds field lists every TCP
// option on the SYN, in wire order, as decimal kind numbers joined by "-",
// including NOP (1) padding because alignment differs by stack — only the
// end-of-option-list terminator (0) is dropped, as it is pure padding. The
// window-scale field is the shift count, or "00" when the option is absent
// (distinct from a present shift of 0), matching the JA4T convention.
//
// This is deliberately NOT the letter-coded variant the archived Python sensor
// emitted; the numeric canonical form is what current JA4+ tooling and threat
// feeds use, so the values are portable.
func ComputeJA4T(f StackFeatures) string {
	if !f.HasSYN {
		return ""
	}

	var b strings.Builder
	b.WriteString(strconv.FormatUint(uint64(f.SYNWindow), 10))
	b.WriteByte('_')
	b.WriteString(joinOptionKinds(f.OptionOrder))
	b.WriteByte('_')
	b.WriteString(strconv.FormatUint(uint64(f.MSS), 10))
	b.WriteByte('_')
	if f.WSOptPresent {
		b.WriteString(strconv.FormatUint(uint64(f.WindowScale), 10))
	} else {
		b.WriteString("00")
	}
	return b.String()
}

// joinOptionKinds renders TCP option kinds as hyphen-joined decimals in wire
// order, dropping only the end-of-option-list terminator (kind 0). NOPs (kind 1)
// are preserved because their placement is part of the stack signature.
func joinOptionKinds(kinds []layers.TCPOptionKind) string {
	parts := make([]string, 0, len(kinds))
	for _, k := range kinds {
		if k == layers.TCPOptionKindEndList {
			continue
		}
		parts = append(parts, strconv.FormatUint(uint64(k), 10))
	}
	return strings.Join(parts, "-")
}
