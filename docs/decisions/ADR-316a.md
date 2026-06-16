# ADR-316a: Go capture stack for the TAP/SPAN sensor — gopacket fork + AF_PACKET, no cgo

**Status:** Accepted
**Date:** 2026-06-16
**Phase:** 316 (Go TAP/SPAN passive sensor — sub-phase 316a)

---

## Context

Phase 316a rebuilds the passive TAP/SPAN sensor in Go (the Python sensor was
archived in `5afeba26`; the Go proxy ships only a *consumer* of `fp:*` keys that
nothing currently writes). The sensor must read mirrored traffic, reassemble
both directions of every TCP connection, and extract the TLS ClientHello /
ServerHello — at SPAN-port volumes, in a container, without ever dropping or
delaying real traffic (it is out of band).

ADR-020 already chose **AF_PACKET** over libpcap/Scapy/PF_RING/DPDK for the
*Python* sensor, on the grounds that AF_PACKET with an in-kernel BPF filter and
mmap ring buffer is the right capture primitive for our throughput and
data-minimisation needs. That conclusion still holds. What ADR-020 does **not**
settle is the **Go** realisation: which Go library provides AF_PACKET, decoders,
and TCP reassembly, and whether we accept cgo. That is this ADR.

A second, easy-to-get-wrong sub-decision: the canonical gopacket import path.
`github.com/google/gopacket` was **archived (read-only) in 2023**; the maintained
community fork is `github.com/gopacket/gopacket`.

## Options Considered

| Option | Capture | Decode | Reassembly | cgo |
|---|---|---|---|---|
| **A. `gopacket/gopacket` fork: afpacket + layers + reassembly (chosen)** | `afpacket` (pure-Go AF_PACKET/TPACKETv3) | `layers` + `DecodingLayerParser` | `reassembly` | **No** |
| B. gopacket fork with `pcap` | libpcap | `layers` | `reassembly` | **Yes** |
| C. archived `google/gopacket` | afpacket | layers | tcpassembly | No |
| D. hand-rolled AF_PACKET + custom reassembler | raw syscalls | custom | custom | No |

## Decision

**Option A.** Use the maintained **`github.com/gopacket/gopacket`** fork with:

- **`afpacket`** for live capture — pure-Go AF_PACKET (TPACKETv3), no cgo, so the
  container build stays a static binary with no libpcap to link or CVE-track.
- **`pcapgo`** for offline `--pcap-file` replay — also pure-Go; powers CI
  fixtures and local dev without raw-socket privileges.
- **`gopacket.DecodingLayerParser`** with pre-allocated, reused layer structs for
  zero-allocation Ethernet/IP/TCP decoding on the hot path.
- **`reassembly`** (the current bidirectional API) for TCP stream reassembly —
  **not** the deprecated `tcpassembly`. `reassembly` invokes `StreamFactory.New`
  once per *connection* and tags each delivery with direction, so one `Stream`
  owns both the ClientHello and ServerHello halves; and its
  `AssemblerOptions.MaxBufferedPagesTotal / PerConnection` give a library-level
  hard memory ceiling that, with our per-direction 16 KB cap, satisfies the
  PHASE_316a §5 overload model.

### Why not the alternatives

- **B (libpcap/pcap):** cgo reintroduces the exact static-build and
  supply-chain pain AF_PACKET lets us avoid; no decoder benefit that matters here.
- **C (archived `google/gopacket`):** unmaintained; `tcpassembly` is deprecated.
  Taking a new, load-bearing dependency on read-only code is an unforced risk.
- **D (hand-rolled):** re-implementing TPACKETv3 ring handling *and* a correct,
  out-of-order/retransmit-tolerant TCP reassembler is the single largest source
  of subtle bugs in a sensor. `reassembly` is battle-tested; we should not
  rewrite it to save one dependency.

## Consequences

- **New dependency:** `github.com/gopacket/gopacket` (+ transitive
  `golang.org/x/net/bpf` via `afpacket`). Must pass the `govulncheck` CI gate.
- **Linux-only live capture.** `afpacket` is Linux-only — acceptable, we ship
  Linux. Off-Linux builds compile (offline pcap works) but `NewLiveSource`
  returns an error (`capture_other.go`).
- **Kernel BPF deferred.** `afpacket.SetBPF` wants pre-assembled BPF; compiling
  `tcp port 443` without cgo needs hand-assembled instructions. Increment 1 ships
  userspace filtering (non-TCP frames dropped in `ProcessPacket`); kernel BPF is
  tracked for 316a increment 2 (along with capability-drop + seccomp).
- **Standalone binary** (`cmd/ja4-tap`, see PHASE_316a §3b): the proxy never
  links this capture stack or carries `CAP_NET_RAW`.

## References

- ADR-020 — AF_PACKET vs pcap/Scapy/PF_RING/DPDK (Phase-20, capture primitive).
- `docs/phases/PHASE_316a.md` §3, §5.
