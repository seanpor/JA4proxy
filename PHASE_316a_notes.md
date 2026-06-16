# Phase 316a — implementation notes

Sub-phase 1 of the Go TAP/SPAN sensor series. This branch delivers **increment 1:
the capture + reassembly + handshake-extraction foundation**, proven end to end
against synthetic packets and a real `.pcap`. No fingerprints, no Redis, no
enforcement (those are 316b+).

## What landed

| Area | File(s) |
|---|---|
| Capture-library decision | `docs/decisions/ADR-316a.md` (+ INDEX entry) |
| TLS handshake extraction (record-defrag, never panics) | `internal/tap/tlsparse.go` |
| Zero-alloc Ethernet/IP/TCP decode (`DecodingLayerParser`) | `internal/tap/decode.go` |
| Bidirectional TCP reassembly, 16 KB/direction cap, emit policy | `internal/tap/reassembler.go` |
| Sensor wiring (decode→assemble→`HandshakeEvent`) + idle flush | `internal/tap/sensor.go`, `internal/tap/events.go` |
| Offline pcap source (pure-Go) | `internal/tap/capture.go` |
| Live AF_PACKET source (Linux) / stub (other) | `internal/tap/capture_linux.go`, `capture_other.go` |
| Prometheus metrics (own registry) | `internal/tap/metrics.go` |
| Standalone binary | `cmd/ja4-tap/main.go` |
| Tests (extraction, multi-segment, out-of-order, IPv6, non-TLS, cap-exceeded, pcap round-trip, ctx-cancel) | `internal/tap/*_test.go` |

## Key decisions / facts

- **Standalone binary** `cmd/ja4-tap`, not a `ja4pd` subcommand (PHASE_316a §3b,
  maintainer-confirmed): the proxy must never carry `CAP_NET_RAW`.
- **`reassembly` (not `tcpassembly`)**: `StreamFactory.New` is called once per
  *connection*; one `tlsStream` owns both directions via `ScatterGather.Info()`.
  No cross-stream correlation needed.
- **Emit policy:** one `HandshakeEvent` per connection — when both
  ClientHello+ServerHello are captured, or forced on FIN/RST/flush with at least a
  ClientHello. Fail-open: a full event channel drops, never blocks capture.
- **Memory:** per-direction 16 KB cap (`maxHandshakeBytes`) + global page ceiling
  (`AssemblerOptions.MaxBufferedPages*`). Cap hit → direction abandoned, drop
  metric incremented.
- **Metrics live in `internal/tap`, not `internal/metrics`** — the standalone
  binary owns its registry; the proxy must not link the TAP surface. (Deviation
  from the plan's "add to internal/metrics", justified by the binary split.)

## Deferred to 316a increment 2 (live-capture hardening)

These are intentionally NOT in this branch; `cmd/ja4-tap` logs a WARN on live
capture so it is not mistaken for hardened:

- Kernel BPF filter (`tcp port 443`) — needs hand-assembled BPF (no cgo).
- Post-bind capability drop to non-root + seccomp profile (`config/seccomp_tap.json`).
- Watchdog with rapid-crash detection (`internal/tap/watchdog.go`).
- `config/proxy.yml` `tap:` block + hot-reload semantics, and a `/health` entry.
- Runbook Go section (`docs/runbooks/tap_mode.md`), IPv4 fragment reassembly,
  performance/throughput benchmark.

## Status

`manifest.yaml` 316a stays **not COMPLETE** — this is the foundation increment.
The 316/316a summaries still say "`ja4pd sensor` subcommand" and must be
corrected to the standalone binary (tracked in PHASE_316a Files-to-Modify).
