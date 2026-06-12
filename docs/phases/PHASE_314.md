# PHASE 314 — Go TAP / SPAN Passive Sensor

> **STATUS: DRAFT — awaiting user sign-off. No code until this plan is approved.**
> Large phase — split into three work packages (WP-1..WP-3) that can land and be
> reviewed independently.

## Goal

Port the **passive TAP/SPAN sensor** to Go so the production runtime can ingest a
mirror/SPAN feed, compute the full JA4 fingerprint family, persist fingerprints
to the Redis `fp:*` schema, and (out-of-band) act on them — without ever sitting
inline. The Go proxy today has only the **consumer** half (`internal/security/tap_consumer.go`
reads `fp:os:ip:{ip}` etc. that *something else* must write); the **sensor** that
writes them was the Python prototype (Phase 20), archived in `5afeba26`. This
phase rebuilds the sensor natively in Go.

## Background — what exists vs what's missing

| Piece | State today |
|---|---|
| TAP consumer (inline proxy reads TAP fingerprints) | ✅ `internal/security/tap_consumer.go` (Phase 203a) — reads `fp:*` from Redis. **The clean seam: this phase just needs to *write* what it already reads.** |
| JA4 family computation | ✅ Partial in Go (`internal/tls` computes JA4 for the inline path). Reuse/extend for JA4S/JA4T/JA4H/JA4X from captured packets. |
| Packet capture | ❌ No Go capture. Python used an AF_PACKET raw socket. |
| Enforcement bridge / exporters | ❌ Not in Go. |
| Reference | Python sensor recoverable at `git show 5afeba26:archive/python_legacy/src/tap/...`; original plan in `docs/phases/complete/PHASE_20.md`; retained fixtures in `tests/fp_corpus/data/` and the (now-removed) `tests/tap/` fixtures are recoverable from git. |
| Redis schema | `fp:conn:{id}`, `fp:ip:{ip}`, `fp:ja4:hll:{ja4}`, `fp:os:ip:{ip}`, `fp:ja4_to_ja4s:{ja4}`, … already documented in `REDIS_SCHEMA.md` and read by the consumer. |

## Design (proposed — for review)

**Capture.** AF_PACKET `RawConn` (via `golang.org/x/net` or a thin syscall
wrapper; evaluate `gopacket` vs hand-rolled at WP-1 review — gopacket is
ergonomic but a heavier dep). Bind to a mirror/SPAN interface in promiscuous
mode, parse Ethernet/IPv4/IPv6 (+fragmentation) and TCP/UDP, reassemble enough of
each flow to see the TLS ClientHello/ServerHello and (optionally) HTTP/2.

**Fingerprint.** Compute the JA4 family (JA4, JA4S, JA4T, JA4H, JA4X, JA4L,
JA4H2, JA4SSH, QUIC as feasible) reusing the inline JA4 code where it overlaps.
Parity is gated against the retained corpora + the Python golden outputs.

**Store.** Write to the existing `fp:*` Redis keys with their documented TTLs so
`tap_consumer.go` consumes them unchanged. Fire-and-forget writes; never block
capture.

**Act (out-of-band).** The sensor is passive — it never drops packets inline. It
publishes ban intents to the same `ja4proxy:bans` pub/sub the inline path uses,
plus optional out-of-band enforcement (iptables/ipset, BGP blackhole pipe,
webhook HMAC) mirroring the Python design — with the same IPv4 ≥/24, IPv6 ≥/48
expansion guards.

**Resilience.** Per-worker watchdog with rapid-crash detection; bounded
ring/queue with drop metrics; capability drop / seccomp at startup (the sensor
needs `CAP_NET_RAW` only).

## Work packages

- **WP-1 — Capture + fingerprint + store.** AF_PACKET capture, parse/reassemble,
  JA4-family computation, write to `fp:*`. Metrics:
  `ja4proxy_tap_packets_received_total`, `_packets_dropped_total`,
  `_streams_active`, `_ring_buffer_fill_ratio`, `_worker_restarts_total`. This WP
  alone makes the existing Go consumer fed by a Go sensor — shippable on its own.
- **WP-2 — Out-of-band enforcement bridge.** `ja4proxy:bans` fan-out, iptables/ipset,
  BGP named-pipe, webhook (HMAC-SHA256), with the /24 & /48 expansion guards and
  `ja4proxy_tap_enforcement_errors_total`.
- **WP-3 — Intelligence export.** EDL / F5 / Palo Alto / Kafka / Syslog CEF /
  TAXII 2.1 / MISP exporters, each isolated (one failing exporter never affects
  another), `ja4proxy_tap_export_errors_total`.

## Scope (files — indicative, WP-1)

- `internal/tap/capture.go`, `internal/tap/reassembler.go`, `internal/tap/sensor.go`
- `internal/tap/fingerprints/*.go` (reusing `internal/tls` where it overlaps)
- `internal/tap/store.go` (writes `fp:*`), `internal/tap/watchdog.go`, `internal/tap/security.go`
- `cmd/ja4-tap/main.go` (standalone sensor binary — separate from the inline proxy)
- `internal/metrics` TAP gauges/counters; `config/proxy.yml` `tap:` block
- `internal/tap/*_test.go` (synthetic packet builder), parity fixtures from `tests/fp_corpus/data/`
- `docs/runbooks/tap_mode.md` (Go), ADR (capture lib choice), CHANGELOG, manifest

## Implementation plan (WP-1)

1. Capture: AF_PACKET socket, Ethernet/IP/TCP parse, fragmentation handling.
2. Reassembly: per-flow ordering to surface ClientHello/ServerHello; eviction at cap.
3. Fingerprints: JA4 family, parity-tested vs golden corpus.
4. Store: write `fp:*` with documented TTLs; consumer round-trip test.
5. Watchdog + capability drop + metrics; runbook; ADR; CHANGELOG; manifest.

## Test strategy

- **Synthetic packet builder** (port the Python `SyntheticPacketBuilder`): SYN/SYNACK/ACK,
  ClientHello, ServerHello, HTTP, FIN/RST → assert computed fingerprints.
- **Parity**: Go fingerprints == Python golden outputs over the corpus (the
  retained `tests/fp_corpus/data/` + recovered TAP fixtures).
- **Round-trip**: sensor writes `fp:*` → `tap_consumer.go` reads them and produces the expected signal.
- **Reassembly**: out-of-order / fragmented / truncated → no panic, correct or skipped.
- **Chaos**: Redis down (writes dropped, capture continues), worker crash (watchdog restarts), ring overflow (drop metric).
- **FP rate** (ties into the gap from the phase-309 tidyup): JA4 family FP rate against the corpus.

## Acceptance criteria (per WP; WP-1 is the MVP)

- A Go sensor on a SPAN port computes the JA4 family and writes `fp:*`; the
  existing `tap_consumer.go` consumes them end-to-end.
- Fingerprint parity with the Python golden corpus.
- TAP metrics emitted; capture survives Redis outage / worker crash / overflow.
- Tests + runbook + ADR + CHANGELOG + manifest; `make test` green.

## Out of scope (this phase)

- Inline enforcement (the sensor is passive by definition).
- QUIC/HTTP3 deep parsing beyond initial-packet JA4 (can be a follow-on).
- Re-implementing the management-UI TAP panels (separate UI work).
