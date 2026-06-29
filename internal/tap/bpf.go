package tap

import (
	"errors"
	"math"
	"strconv"
	"strings"

	"golang.org/x/net/bpf"
)

// maxBPFPorts is the maximum number of ports that can be compiled into a
// single BPF filter.  Beyond this limit the jump-offset uint8 fields in
// JumpIf overflow silently.  gopacket's BPF instruction limit (4096) is not
// the binding constraint.
const maxBPFPorts = 127

// CompilePortBPF builds a kernel BPF filter that keeps only TCP packets whose
// destination port matches one of the given ports, on standard Ethernet + IPv4
// links.  Packets that do not match (non-IP, non-TCP, wrong port) are dropped
// in the kernel before reaching userspace.
//
// For a three-port example (443, 8443, 80) the generated filter is:
//
//	ld  [12]               A = EtherType
//	jeq #0x0800, 0, DROP   not IPv4 ? -> DROP
//	ld  [23]               A = IP protocol
//	jeq #6,      0, DROP   not TCP ?   -> DROP
//	ld  [36]               A = TCP dst port (Eth 14 + IP 20 + dst 2)
//	jeq #443,     4, 0     port==443 ? jump to KEEP, else fall through
//	ld  [36]
//	jeq #8443,    2, 0     port==8443 ? jump to KEEP, else fall through
//	ld  [36]
//	jeq #80,      0, 1     port==80  ? fall through to KEEP, else DROP
//
// KEEP:
//
//	ret #0xFFFFFFFF
//
// DROP:
//
//	ret #0
//
// VLAN and IPv6 are silently dropped by this filter.
//
// An empty port list returns (nil, nil), which disables kernel BPF filtering
// and falls back to userspace filtering in ProcessPacket.
func CompilePortBPF(ports ...uint16) ([]bpf.RawInstruction, error) {
	if len(ports) == 0 {
		return nil, nil
	}
	if len(ports) > maxBPFPorts {
		return nil, errors.New("tap: too many BPF filter ports (max 127)")
	}

	insts := make([]bpf.Instruction, 0, 2+2+2*len(ports)+2)

	// EtherType check — jump to DROP on non-IPv4.
	// Instructions after this JumpIf: IP check (1 LD + 1 JEQ = 2) + port checks (2*N) + KEEP (1) + DROP (1)
	// The three uint8 casts below are safe: maxBPFPorts=127 caps len(ports),
	// so the largest offset is 2+2*127+1 = 257 — but the maxBPFPorts check above
	// rejects len(ports)>127, keeping all offsets within [0,255].
	insts = append(insts,
		bpf.LoadAbsolute{Off: 12, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipTrue: 0, SkipFalse: uint8(2 + 2*len(ports) + 1)}) //nolint:gosec // bounds guaranteed by maxBPFPorts guard above

	// IP protocol check — jump to DROP on non-TCP.
	// Instructions after this JumpIf: port checks (2*N) + KEEP (1) + before DROP (1)
	insts = append(insts,
		bpf.LoadAbsolute{Off: 23, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipTrue: 0, SkipFalse: uint8(2*len(ports) + 1)}) //nolint:gosec // bounds guaranteed by maxBPFPorts guard above

	for i, p := range ports {
		remaining := len(ports) - i - 1
		// jt: match → skip remaining port checks to land on KEEP.
		jt := uint8(remaining * 2) //nolint:gosec // bounds guaranteed by maxBPFPorts guard above
		// jf: non-match → fall through to next check, or skip KEEP on last.
		jf := uint8(0)
		if remaining == 0 {
			jf = 1
		}
		insts = append(insts,
			bpf.LoadAbsolute{Off: 36, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(p), SkipTrue: jt, SkipFalse: jf},
		)
	}

	insts = append(insts,
		bpf.RetConstant{Val: math.MaxUint32}, // KEEP
		bpf.RetConstant{Val: 0},              // DROP
	)
	return bpf.Assemble(insts)
}

// ParsePortList parses a comma-separated string of port numbers.  Empty input
// returns (nil, nil) — meaning "no ports, no filter".  Invalid entries produce
// an error.
func ParsePortList(s string) ([]uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	out := make([]uint16, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, err
		}
		out = append(out, uint16(v))
	}
	return out, nil
}
