# Phase 316b — implementation notes

Sub-phase 2 of the Go TAP/SPAN sensor series. Delivers the **first end-to-end
value**: the passive sensor computes an OS class and writes `fp:os:ip:{ip}`, which
lights up the previously-dormant `tap_os_mismatch` signal in the inline proxy.

## Critical-review corrections applied to the plan (before coding)

The first draft of `PHASE_316b.md` was not implementable as written; the review
caught and the revised plan fixes:

1. **Blocker — false input contract.** The draft assumed 316a's `HandshakeEvent`
   already carried `tcp_options`/TTL. It carried only handshake bytes + 5-tuple.
   Added **Step 0**: extend the capture path to record SYN/IP-stack features.
2. **Descoped the speculative middlebox-signature DB** (former D5) to the
   conservative `unknown` default — a normalised stack simply fails to match a
   clean OS profile and is left unwritten.
3. **Dropped `android`/generic `other`** from the enum; added a precise `unknown`
   zero value that is never written and never compared.
4. **Pinned the key TTL to 24h** to match the consumer's documented assumption.
5. Documented the **CGNAT/shared-IP last-writer-wins** FP source and the
   **least-privilege Redis ACL** (sensor needs `fp:*` write only).

## What landed

| Area | File(s) |
|---|---|
| Canonical OS-class vocabulary (writer+reader shared) | `internal/fingerprint/osclass.go` |
| Consumer refactor to the shared type; compare only concrete classes | `internal/security/tap_consumer.go` |
| **Step 0** — SYN/IP-stack features on the event | `internal/tap/events.go`, `decode.go`, `sensor.go`, `reassembler.go` |
| Conservative passive OS classifier | `internal/tap/osfingerprint.go` |
| Fire-and-forget `fp:os:ip` writer (skips unknown) | `internal/tap/store.go` |
| `ja4proxy_tap_fingerprints_written_total{result}` | `internal/tap/metrics.go` |
| Binary wiring (classify→store behind `--redis-url`) | `cmd/ja4-tap/main.go` |
| GDPR erasure of `fp:os:ip`/`fp:ip` | `scripts/gdpr_delete.py` |
| Docs | `docs/reference/REDIS_SCHEMA.md`, `docs/reference/OBSERVABILITY_STANDARDS.md`, `docs/runbooks/tap_mode.md`, `docs/fragments/phase-316b-tap-osmismatch.md` |

## Key design decisions

- **SYN features source:** SYN TCP window/options/MSS come from the `*layers.TCP`
  passed to `streamFactory.New` (the connection's first packet). The IP TTL is not
  visible in any reassembly callback, so it is plumbed via `assemblerCtx.ttl`.
  `synFeatures` records features only for a genuine client SYN (`SYN && !ACK`);
  mid-stream captures get `HasSYN=false` → classified `unknown` → no write.
- **Conservative classifier, MVP scope = {Windows, Linux} only.** Exact stack
  signature match required. Windows: initial TTL 128 + NO TCP timestamps + option
  order [MSS, WS, SACK]. Linux: initial TTL 64 + timestamps + option order
  [MSS, SACK, TS, WS]. macOS and iOS share the Darwin stack and are passively
  indistinguishable from each other, so Darwin → `unknown` (emitting either would
  risk a false mismatch against a real iOS/macOS Safari user). Everything else →
  `unknown`.
- **Advisory-only.** The sensor only writes a fingerprint; the inline pipeline
  turns a mismatch into a normal RiskSignal scored under the dial (default 0).
- **Fail-open everywhere.** Redis error → fingerprint dropped + error counter, no
  panic, capture continues. Full event channel (316a) drops, never stalls capture.
  Each write is time-bounded (100 ms) so a slow Redis cannot back up the drain.

## Tests

- `internal/fingerprint/osclass_test.go` — vocabulary, parse/format round-trip,
  JA4 table, fail-open.
- `internal/tap/osfingerprint_test.go` — classifier matrix (Win/Linux concrete;
  Darwin/normalised/SYN-less/atypical → unknown); TTL inference; padding strip.
- `internal/tap/osfeatures_test.go` — Step-0 capture proven end to end through the
  sensor (SYN options → `HandshakeEvent.Stack`); mid-stream → `HasSYN=false`.
- `internal/tap/store_test.go` — writes known class with 24h TTL; skips unknown;
  nil backend; Redis error; unparsable IP; v4/v6 canonicalisation.
- `internal/tap/roundtrip_test.go` (`package tap_test`, miniredis) — **the closed
  loop**: sensor writes → consumer fires on mismatch, silent on agreement, silent
  on unknown; plus the **zero-FP corpus** test over legitimate browser profiles.

All `go build ./...`, `go vet`, `gofmt`, and `go test -race` pass.

## Status

`manifest.yaml` 316b = **IN_PROGRESS** — code + tests + docs complete on
`phase-316b-tap-osmismatch` (stacked on the unmerged 316a, PR #182). Marked
COMPLETE on merge.

## Deferred (later sub-phases)

- Full JA4 fingerprint family + other `fp:*` keys → 316c.
- Explicit middlebox/NAT signature database → later phase.
- TAP-originated enforcement (iptables/BGP) → 316d. Exporters → 316e.
- Real-pcap Tranco corpus replay wired into a live test target (the deterministic
  classifier+consumer FP test stands in for CI).
